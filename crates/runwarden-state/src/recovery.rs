use runwarden_kernel::operation::{
    OperationState, ProviderExecutionStatus, ProviderResultView, SafeProviderOutput,
    SecurityOperation, SideEffectState,
};
use runwarden_kernel::story::{EvidenceStatus, ExecutionLeaseId, OperationId, StoryProvenance};
use runwarden_kernel::trace::EventCode;
use rusqlite::{Transaction, TransactionBehavior, params};
use time::OffsetDateTime;

use crate::approvals::{
    MarkOutcomeUnknownInput, ReleaseLeaseInput, append_provider_event,
    commit_unknown_execution_budget_tx, decode_execution_lease_tx, has_execution_started_tx,
    operation_transition_cas_error, release_execution_budget_tx, require_operation_version,
    restore_unstarted_approval_tx, validate_mutation_time,
};
use crate::snapshots::{load_operation_tx, load_story_evidence_tx};
use crate::stories::load_story_record;
use crate::{JournalError, StateStore, canonical_json, enum_text, format_time, sqlite_u64};

/// Minimal, display-safe reconciliation material for a provider call that was
/// durably marked as started but has no durable result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCandidate {
    pub operation_id: OperationId,
    pub operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub lease_expires_at: OffsetDateTime,
}

impl StateStore {
    /// Discover only expired executions that crossed the durable start
    /// boundary. Discovery never retries providers and never mutates state.
    pub fn recovery_candidates(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<RecoveryCandidate>, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let operation_ids = {
            let mut statement = transaction.prepare(
                "SELECT operation_id FROM operations WHERE state = 'executing' ORDER BY operation_id",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut candidates = Vec::with_capacity(operation_ids.len());
        for raw_id in operation_ids {
            let operation_id: OperationId =
                crate::persisted_string(raw_id, "recovery operation id")?;
            let operation = load_operation_tx(&transaction, operation_id)?;
            load_story_evidence_tx(&transaction, operation.story_id)?;
            let lease = decode_execution_lease_tx(&transaction, &operation)?;
            if !has_execution_started_tx(&transaction, &operation)? {
                return Err(JournalError::Integrity(
                    "executing operation has no verified execution-start event".to_owned(),
                ));
            }
            if lease.expires_at <= now {
                candidates.push(RecoveryCandidate {
                    operation_id,
                    operation_version: operation.version,
                    lease_id: lease.lease_id,
                    lease_owner: lease.lease_owner,
                    lease_expires_at: lease.expires_at,
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.lease_expires_at
                .cmp(&right.lease_expires_at)
                .then_with(|| left.operation_id.cmp(&right.operation_id))
        });
        transaction.commit()?;
        Ok(candidates)
    }

    /// Release an expired lease only when provider execution never crossed the
    /// durable start boundary.
    pub fn release_unstarted_lease(
        &self,
        input: ReleaseLeaseInput,
    ) -> Result<SecurityOperation, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        require_recovery_write_admission(&transaction, &operation)?;
        require_operation_version(&operation, input.expected_operation_version)?;
        if operation.state != OperationState::ExecutionLeased {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: enum_text(&operation.state)?,
                to: "release_unstarted_lease".to_owned(),
            });
        }
        let story = load_story_record(&transaction, operation.story_id)?;
        validate_mutation_time(story.updated_at, input.now, "release_unstarted_lease")?;
        let lease = decode_execution_lease_tx(&transaction, &operation)?;
        if lease.lease_id != input.lease_id {
            return Err(JournalError::Integrity(
                "lease release does not match the durable lease identity".to_owned(),
            ));
        }
        if input.now < lease.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "lease_expiry",
                from: format_time(lease.expires_at)?,
                to: "release_unstarted_lease".to_owned(),
            });
        }
        if has_execution_started_tx(&transaction, &operation)? {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: "execution_started".to_owned(),
                to: "release_unstarted_lease".to_owned(),
            });
        }

        release_execution_budget_tx(&transaction, &lease, input.now)?;
        let target_state =
            restore_unstarted_approval_tx(&transaction, &operation, &lease, input.now)?;
        let target_side_effect = if target_state == OperationState::Expired {
            SideEffectState::BlockedBeforeExecution
        } else {
            SideEffectState::NotAttempted
        };
        let next_version = operation.version.checked_add(1).ok_or_else(|| {
            JournalError::Integrity("operation version overflowed u64".to_owned())
        })?;
        let affected = transaction.execute(
            r#"UPDATE operations
               SET state = ?1, side_effect_state = ?2, version = ?3,
                   lease_id = NULL, lease_owner = NULL, lease_expires_at = NULL,
                   lease_pre_state = NULL, lease_instance_id = NULL,
                   lease_instance_token_hash = NULL, updated_at = ?4
               WHERE operation_id = ?5 AND state = 'execution_leased'
                 AND version = ?6 AND side_effect_state = 'not_attempted'
                 AND provider_result_json IS NULL
                 AND lease_id = ?7 AND lease_owner = ?8
                 AND lease_expires_at = ?9 AND lease_pre_state = ?10
                 AND lease_instance_id = ?11
                 AND lease_instance_token_hash = ?12"#,
            params![
                enum_text(&target_state)?,
                enum_text(&target_side_effect)?,
                sqlite_u64(next_version, "operation version")?,
                format_time(input.now)?,
                operation.operation_id.to_string(),
                sqlite_u64(input.expected_operation_version, "operation version")?,
                lease.lease_id.to_string(),
                lease.lease_owner.as_str(),
                format_time(lease.expires_at)?,
                enum_text(&lease.pre_lease_state)?,
                lease.instance_id.as_str(),
                lease.instance_token_hash.as_str(),
            ],
        )?;
        if affected != 1 {
            return operation_transition_cas_error(
                &transaction,
                operation.operation_id,
                input.expected_operation_version,
                "release_unstarted_lease",
            );
        }
        let event_status = if target_state == OperationState::Expired {
            "execution_lease_expired"
        } else {
            "execution_lease_released"
        };
        append_provider_event(
            &transaction,
            &operation,
            event_status,
            target_side_effect,
            None,
            None,
            input.now,
        )?;
        let updated = load_operation_tx(&transaction, operation.operation_id)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(updated)
    }

    /// Persist the only truthful terminal state when execution started but its
    /// provider result could not be made durable. This path never calls or
    /// retries the provider and need not wait for lease expiry.
    pub fn mark_outcome_unknown(
        &self,
        input: MarkOutcomeUnknownInput,
    ) -> Result<SecurityOperation, JournalError> {
        let reason_code = EventCode::try_from(input.reason_code.clone()).map_err(|error| {
            JournalError::Integrity(format!("outcome-unknown reason code is invalid: {error}"))
        })?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        require_recovery_write_admission(&transaction, &operation)?;
        // Version must be checked first so a stale recovery candidate cannot
        // overwrite a concurrently committed terminal provider result.
        require_operation_version(&operation, input.expected_operation_version)?;
        if operation.state != OperationState::Executing {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: enum_text(&operation.state)?,
                to: enum_text(&OperationState::OutcomeUnknown)?,
            });
        }
        let story = load_story_record(&transaction, operation.story_id)?;
        validate_mutation_time(story.updated_at, input.now, "mark_outcome_unknown")?;
        let lease = decode_execution_lease_tx(&transaction, &operation)?;
        if lease.lease_id != input.lease_id || lease.lease_owner != input.lease_owner {
            return Err(JournalError::Integrity(
                "unknown execution does not match the durable lease identity".to_owned(),
            ));
        }
        if !has_execution_started_tx(&transaction, &operation)? {
            return Err(JournalError::Integrity(
                "unknown execution has no verified execution-start event".to_owned(),
            ));
        }
        commit_unknown_execution_budget_tx(&transaction, &lease, input.now)?;

        let provider_result = ProviderResultView {
            execution_status: ProviderExecutionStatus::OutcomeUnknown,
            output: SafeProviderOutput::None,
            output_hash: None,
            error_kind: Some("provider_outcome_unknown".to_owned()),
            reason_code: Some(reason_code.as_str().to_owned()),
        };
        let next_version = operation.version.checked_add(1).ok_or_else(|| {
            JournalError::Integrity("operation version overflowed u64".to_owned())
        })?;
        let affected = transaction.execute(
            r#"UPDATE operations
               SET state = 'outcome_unknown', side_effect_state = 'outcome_unknown',
                   provider_result_json = ?1, version = ?2, updated_at = ?3
               WHERE operation_id = ?4 AND state = 'executing' AND version = ?5
                 AND side_effect_state = 'not_attempted'
                 AND provider_result_json IS NULL
                 AND lease_id = ?6 AND lease_owner = ?7
                 AND lease_expires_at = ?8 AND lease_pre_state = ?9
                 AND lease_instance_id = ?10
                 AND lease_instance_token_hash = ?11"#,
            params![
                canonical_json(&provider_result)?,
                sqlite_u64(next_version, "operation version")?,
                format_time(input.now)?,
                operation.operation_id.to_string(),
                sqlite_u64(input.expected_operation_version, "operation version")?,
                lease.lease_id.to_string(),
                lease.lease_owner.as_str(),
                format_time(lease.expires_at)?,
                enum_text(&lease.pre_lease_state)?,
                lease.instance_id.as_str(),
                lease.instance_token_hash.as_str(),
            ],
        )?;
        if affected != 1 {
            return operation_transition_cas_error(
                &transaction,
                operation.operation_id,
                input.expected_operation_version,
                "outcome_unknown",
            );
        }
        append_provider_event(
            &transaction,
            &operation,
            "outcome_unknown",
            SideEffectState::OutcomeUnknown,
            None,
            None,
            input.now,
        )?;
        let updated = load_operation_tx(&transaction, operation.operation_id)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(updated)
    }
}

fn require_recovery_write_admission(
    transaction: &Transaction<'_>,
    operation: &SecurityOperation,
) -> Result<(), JournalError> {
    let evidence = load_story_evidence_tx(transaction, operation.story_id)?;
    if evidence.story.provenance != StoryProvenance::Native {
        return Err(JournalError::InvalidTransition {
            entity: "story_provenance",
            from: enum_text(&evidence.story.provenance)?,
            to: "journal_recovery".to_owned(),
        });
    }
    if evidence.story.evidence_status != EvidenceStatus::Pending {
        return Err(JournalError::InvalidTransition {
            entity: "story_evidence",
            from: enum_text(&evidence.story.evidence_status)?,
            to: "journal_recovery".to_owned(),
        });
    }
    Ok(())
}
