use std::collections::HashSet;

use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, SafeArgumentView, SecurityOperation,
    SideEffectState,
};
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::story::{
    EventId, InvocationKey, ObservationId, OperationId, SessionId, StoryId,
};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::events::{NewStoryEvent, append_event_and_frame_tx};
use crate::sessions::load_session_record;
use crate::snapshots::{load_operation_tx, verify_story_evidence_tx};
use crate::stories::load_story_record;
use crate::{
    JournalError, StateStore, canonical_json, enum_text, format_time, persisted_json,
    persisted_string, sqlite_u64,
};

/// Private provider arguments. Deliberately implements neither `Debug`,
/// `Serialize`, `JsonSchema`, nor `Clone`.
pub struct PrivateOperationMaterial {
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateOperationOutcome {
    pub created: bool,
    pub operation: SecurityOperation,
}

pub struct NewOperation {
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub invocation_key: InvocationKey,
    pub parent_model_call_id: Option<String>,
    pub proposed_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub resource_claim: ResourceClaim,
    pub argument_hash: Sha256Digest,
    pub arguments: SafeArgumentView,
    pub private_material: PrivateOperationMaterial,
    pub policy_snapshot_hash: Sha256Digest,
    pub now: OffsetDateTime,
}

pub struct RecordPolicyInput {
    pub operation_id: OperationId,
    pub expected_version: u64,
    pub decision: PolicyDecision,
    pub reason: String,
    pub next_state: OperationState,
    pub checks: Vec<PolicyCheck>,
    pub now: OffsetDateTime,
}

struct PreparedOperation {
    provider_code: EventCode,
    action_code: EventCode,
    safe_arguments_json: String,
    private_arguments: Vec<u8>,
    claim_json: String,
    claim_hash: Sha256Digest,
    invocation_binding_hash: Sha256Digest,
    now: String,
}

struct StoredBinding {
    operation_id: String,
    invocation_binding_hash: String,
    parent_model_call_id: Option<String>,
    proposed_tool_call_id: Option<String>,
    provider: String,
    action: String,
    argument_hash: String,
    safe_arguments_json: String,
    private_arguments: Vec<u8>,
    policy_snapshot_hash: String,
    claim_json: String,
    claim_hash: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvocationBindingMaterial<'a> {
    pub schema_version: &'static str,
    pub story_id: &'a StoryId,
    pub session_id: &'a SessionId,
    pub invocation_key: &'a str,
    pub parent_model_call_id: Option<&'a str>,
    pub proposed_tool_call_id: Option<&'a str>,
    pub provider: &'a str,
    pub action: &'a str,
    pub argument_hash: &'a str,
    pub safe_arguments_hash: Sha256Digest,
    pub resource_claim_hash: &'a str,
    pub policy_snapshot_hash: &'a str,
}

pub(crate) fn invocation_binding_hash(
    material: InvocationBindingMaterial<'_>,
) -> Result<Sha256Digest, JournalError> {
    Ok(Sha256Digest::from_bytes(
        canonical_json(&material)?.as_bytes(),
    ))
}

impl StateStore {
    pub fn create_operation(
        &self,
        input: NewOperation,
    ) -> Result<CreateOperationOutcome, JournalError> {
        let prepared = prepare_operation(&input)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_story_evidence_tx(&transaction, input.story_id)?;
        let story = load_story_record(&transaction, input.story_id)?;
        let session = load_session_record(&transaction, input.session_id)?;
        if story.story.authority.session_id != input.session_id
            || session.record.story_id != input.story_id
            || session.record.authority != story.story.authority
        {
            return Err(JournalError::Integrity(
                "operation story, session, and authority do not identify one context".to_owned(),
            ));
        }
        if input.policy_snapshot_hash.as_str() != session.record.policy_snapshot_hash {
            return Err(JournalError::Integrity(
                "operation policy hash does not match the immutable session".to_owned(),
            ));
        }

        if let Some(existing) = load_binding_for_invocation(
            &transaction,
            input.story_id,
            input.session_id,
            &input.invocation_key,
        )? {
            if existing.operation_id != input.operation_id.to_string()
                && let Some(actual) = operation_version_if_exists(&transaction, input.operation_id)?
            {
                return Err(JournalError::Conflict {
                    entity: "operation",
                    id: input.operation_id.to_string(),
                    expected: 0,
                    actual,
                });
            }
            validate_retry_binding(&input, &prepared, &existing)?;
            let existing_id: OperationId =
                persisted_string(existing.operation_id, "retry operation id")?;
            let operation = load_operation_tx(&transaction, existing_id)?;
            transaction.commit()?;
            return Ok(CreateOperationOutcome {
                created: false,
                operation,
            });
        }
        if story.story.provenance != runwarden_kernel::story::StoryProvenance::Native
            || story.story.evidence_status != runwarden_kernel::story::EvidenceStatus::Pending
            || matches!(
                story.story.status,
                runwarden_kernel::story::StoryStatus::EvidenceInvalid
                    | runwarden_kernel::story::StoryStatus::OutcomeUnknown
            )
        {
            return Err(JournalError::InvalidTransition {
                entity: "story",
                from: enum_text(&story.story.status)?,
                to: "create_operation".to_owned(),
            });
        }
        if !session.active || session.record.authority.authz_state != "active" {
            return Err(JournalError::InvalidTransition {
                entity: "session",
                from: session.record.authority.authz_state,
                to: "create_operation".to_owned(),
            });
        }
        if input.now >= session.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "session",
                from: "expired".to_owned(),
                to: "create_operation".to_owned(),
            });
        }
        if input.now < story.updated_at {
            return Err(JournalError::InvalidTransition {
                entity: "operation_time",
                from: format_time(story.updated_at)?,
                to: prepared.now,
            });
        }
        if let Some(actual) = operation_version_if_exists(&transaction, input.operation_id)? {
            return Err(JournalError::Conflict {
                entity: "operation",
                id: input.operation_id.to_string(),
                expected: 0,
                actual,
            });
        }

        transaction.execute(
            r#"INSERT INTO operations (
                operation_id, story_id, session_id, invocation_key,
                invocation_binding_hash,
                parent_model_call_id, proposed_tool_call_id, provider, action,
                argument_hash, redacted_arguments_json, private_arguments_json,
                policy_snapshot_hash, state, side_effect_state, version,
                created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                'proposed', 'not_attempted', 0, ?14, ?14
            )"#,
            params![
                input.operation_id.to_string(),
                input.story_id.to_string(),
                input.session_id.to_string(),
                input.invocation_key.as_str(),
                prepared.invocation_binding_hash.as_str(),
                input.parent_model_call_id,
                input.proposed_tool_call_id,
                input.provider,
                input.action,
                input.argument_hash.as_str(),
                prepared.safe_arguments_json,
                prepared.private_arguments,
                input.policy_snapshot_hash.as_str(),
                prepared.now,
            ],
        )?;
        transaction.execute(
            r#"INSERT INTO resource_claims (
                story_id, operation_id, claim_json, claim_hash
            ) VALUES (?1, ?2, ?3, ?4)"#,
            params![
                input.story_id.to_string(),
                input.operation_id.to_string(),
                prepared.claim_json,
                prepared.claim_hash.as_str(),
            ],
        )?;
        append_event_and_frame_tx(
            &transaction,
            NewStoryEvent {
                obs_id: ObservationId::new(),
                event_id: EventId::new(),
                story_id: input.story_id,
                session_id: input.session_id,
                operation_id: Some(input.operation_id),
                provider: Some(prepared.provider_code),
                payload: StoryEventPayload::OperationProposed {
                    provider: EventCode::try_from(input.provider).map_err(|error| {
                        JournalError::Integrity(format!(
                            "operation provider could not be sealed: {error}"
                        ))
                    })?,
                    action: prepared.action_code,
                    argument_hash: input.argument_hash,
                    resource_claim_hash: prepared.claim_hash,
                },
                recorded_at: input.now,
            },
        )?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(CreateOperationOutcome {
            created: true,
            operation,
        })
    }

    pub fn load_private_operation_material(
        &self,
        operation_id: OperationId,
    ) -> Result<PrivateOperationMaterial, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let raw: Option<(String, Vec<u8>, String)> = transaction
            .query_row(
                r#"SELECT story_id, private_arguments_json, argument_hash
                   FROM operations WHERE operation_id = ?1"#,
                params![operation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (story_id, bytes, stored_hash) = raw.ok_or_else(|| JournalError::NotFound {
            entity: "operation",
            id: operation_id.to_string(),
        })?;
        let story_id: StoryId = persisted_string(story_id, "private operation story id")?;
        verify_story_evidence_tx(&transaction, story_id)?;
        let json = std::str::from_utf8(&bytes).map_err(|_| {
            JournalError::Integrity("stored private operation material is not UTF-8".to_owned())
        })?;
        let arguments: Value = persisted_json(json, "private operation material")?;
        let canonical = canonical_json(&arguments)?;
        if canonical.as_bytes() != bytes {
            return Err(JournalError::Integrity(
                "stored private operation material is not canonical".to_owned(),
            ));
        }
        let stored_hash: Sha256Digest = persisted_string(stored_hash, "private argument hash")?;
        if Sha256Digest::from_bytes(canonical.as_bytes()) != stored_hash {
            return Err(JournalError::Integrity(
                "stored private operation material does not match its hash".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(PrivateOperationMaterial { arguments })
    }

    pub fn record_policy(
        &self,
        input: RecordPolicyInput,
    ) -> Result<SecurityOperation, JournalError> {
        validate_policy_input(&input)?;
        let expected_version = sqlite_u64(input.expected_version, "operation version")?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_operation_tx(&transaction, input.operation_id)?;
        verify_story_evidence_tx(&transaction, existing.story_id)?;
        if existing.version != input.expected_version {
            return Err(JournalError::Conflict {
                entity: "operation",
                id: input.operation_id.to_string(),
                expected: input.expected_version,
                actual: existing.version,
            });
        }
        if existing.state != OperationState::Proposed {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: enum_text(&existing.state)?,
                to: enum_text(&input.next_state)?,
            });
        }
        let story = load_story_record(&transaction, existing.story_id)?;
        let session = load_session_record(&transaction, existing.session_id)?;
        if !session.active
            || session.record.authority.authz_state != "active"
            || session.record.story_id != existing.story_id
            || session.record.policy_snapshot_hash != existing.policy_snapshot_hash.as_str()
        {
            return Err(JournalError::InvalidTransition {
                entity: "session",
                from: session.record.authority.authz_state,
                to: "record_policy".to_owned(),
            });
        }
        if input.now >= session.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "session",
                from: "expired".to_owned(),
                to: "record_policy".to_owned(),
            });
        }
        if input.now < story.updated_at {
            return Err(JournalError::InvalidTransition {
                entity: "operation_time",
                from: format_time(story.updated_at)?,
                to: format_time(input.now)?,
            });
        }
        let expected_state = match story.story.enforcement_mode {
            runwarden_kernel::story::EnforcementMode::MonitorOnly => {
                OperationState::PolicyEvaluated
            }
            runwarden_kernel::story::EnforcementMode::Enforced => match input.decision {
                PolicyDecision::Allowed => OperationState::PolicyEvaluated,
                PolicyDecision::Denied => OperationState::Denied,
                PolicyDecision::RequiresReview => OperationState::AwaitingApproval,
            },
        };
        if input.next_state != expected_state || !valid_policy_path(input.next_state) {
            return Err(JournalError::InvalidTransition {
                entity: "operation_policy",
                from: enum_text(&existing.state)?,
                to: enum_text(&input.next_state)?,
            });
        }
        let side_effect_state = if story.story.enforcement_mode
            == runwarden_kernel::story::EnforcementMode::Enforced
            && input.decision == PolicyDecision::Denied
        {
            SideEffectState::BlockedBeforeExecution
        } else {
            SideEffectState::NotAttempted
        };
        let next_version = input.expected_version.checked_add(1).ok_or_else(|| {
            JournalError::Integrity("operation version overflowed u64".to_owned())
        })?;
        let next_version_sql = sqlite_u64(next_version, "operation version")?;
        let updated_at = format_time(input.now)?;
        let affected = transaction.execute(
            r#"UPDATE operations
               SET policy_decision = ?1, policy_reason = ?2, state = ?3,
                   side_effect_state = ?4, version = ?5, updated_at = ?6
               WHERE operation_id = ?7 AND version = ?8 AND state = 'proposed'"#,
            params![
                enum_text(&input.decision)?,
                input.reason,
                enum_text(&input.next_state)?,
                enum_text(&side_effect_state)?,
                next_version_sql,
                updated_at,
                input.operation_id.to_string(),
                expected_version,
            ],
        )?;
        if affected != 1 {
            let actual: Option<i64> = transaction
                .query_row(
                    "SELECT version FROM operations WHERE operation_id = ?1",
                    params![input.operation_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            return match actual {
                Some(actual) => Err(JournalError::Conflict {
                    entity: "operation",
                    id: input.operation_id.to_string(),
                    expected: input.expected_version,
                    actual: crate::rust_u64(actual, "operation version")?,
                }),
                None => Err(JournalError::NotFound {
                    entity: "operation",
                    id: input.operation_id.to_string(),
                }),
            };
        }
        for (index, check) in input.checks.iter().enumerate() {
            let ordinal = index
                .checked_add(1)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| {
                    JournalError::Integrity("policy-check ordinal overflow".to_owned())
                })?;
            transaction.execute(
                r#"INSERT INTO policy_checks (
                    story_id, operation_id, ordinal, check_json
                ) VALUES (?1, ?2, ?3, ?4)"#,
                params![
                    existing.story_id.to_string(),
                    input.operation_id.to_string(),
                    ordinal,
                    canonical_json(check)?,
                ],
            )?;
        }
        let reason_code = match input.decision {
            PolicyDecision::Allowed => "policy_allowed",
            PolicyDecision::Denied => "policy_denied",
            PolicyDecision::RequiresReview => "approval_required",
        };
        append_event_and_frame_tx(
            &transaction,
            NewStoryEvent {
                obs_id: ObservationId::new(),
                event_id: EventId::new(),
                story_id: existing.story_id,
                session_id: existing.session_id,
                operation_id: Some(existing.operation_id),
                provider: Some(EventCode::try_from(existing.provider.clone()).map_err(
                    |error| {
                        JournalError::Integrity(format!(
                            "stored operation provider could not be sealed: {error}"
                        ))
                    },
                )?),
                payload: StoryEventPayload::PolicyDecision {
                    decision: input.decision,
                    reason_code: EventCode::try_from(reason_code.to_owned()).map_err(|error| {
                        JournalError::Integrity(format!("policy reason code is invalid: {error}"))
                    })?,
                    policy_snapshot_hash: existing.policy_snapshot_hash,
                },
                recorded_at: input.now,
            },
        )?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(operation)
    }
}

fn prepare_operation(input: &NewOperation) -> Result<PreparedOperation, JournalError> {
    let provider_code = EventCode::try_from(input.provider.clone()).map_err(|error| {
        JournalError::Integrity(format!("operation provider is invalid: {error}"))
    })?;
    let action_code = EventCode::try_from(input.action.clone()).map_err(|error| {
        JournalError::Integrity(format!("operation action is invalid: {error}"))
    })?;
    validate_optional_input_label(
        "parent model call id",
        input.parent_model_call_id.as_deref(),
    )?;
    validate_optional_input_label(
        "proposed tool call id",
        input.proposed_tool_call_id.as_deref(),
    )?;
    let safe_arguments_json = canonical_json(&input.arguments)?;
    let private_json = canonical_json(&input.private_material.arguments)?;
    if Sha256Digest::from_bytes(private_json.as_bytes()) != input.argument_hash {
        return Err(JournalError::Integrity(
            "operation private arguments do not match the supplied hash".to_owned(),
        ));
    }
    let claim_json = canonical_json(&input.resource_claim)?;
    let claim_hash = input.resource_claim.digest();
    let invocation_binding_hash = invocation_binding_hash(InvocationBindingMaterial {
        schema_version: "1.0.0",
        story_id: &input.story_id,
        session_id: &input.session_id,
        invocation_key: input.invocation_key.as_str(),
        parent_model_call_id: input.parent_model_call_id.as_deref(),
        proposed_tool_call_id: input.proposed_tool_call_id.as_deref(),
        provider: &input.provider,
        action: &input.action,
        argument_hash: input.argument_hash.as_str(),
        safe_arguments_hash: Sha256Digest::from_bytes(safe_arguments_json.as_bytes()),
        resource_claim_hash: claim_hash.as_str(),
        policy_snapshot_hash: input.policy_snapshot_hash.as_str(),
    })?;
    Ok(PreparedOperation {
        provider_code,
        action_code,
        safe_arguments_json,
        private_arguments: private_json.into_bytes(),
        claim_json,
        claim_hash,
        invocation_binding_hash,
        now: format_time(input.now)?,
    })
}

fn load_binding_for_invocation(
    connection: &rusqlite::Connection,
    story_id: StoryId,
    session_id: SessionId,
    invocation_key: &InvocationKey,
) -> Result<Option<StoredBinding>, JournalError> {
    connection
        .query_row(
            r#"SELECT o.operation_id, o.invocation_binding_hash,
                      o.parent_model_call_id,
                      o.proposed_tool_call_id, o.provider, o.action,
                      o.argument_hash, o.redacted_arguments_json,
                      o.private_arguments_json, o.policy_snapshot_hash,
                      r.claim_json, r.claim_hash
               FROM operations o
               JOIN resource_claims r
                 ON r.story_id = o.story_id AND r.operation_id = o.operation_id
               WHERE o.story_id = ?1 AND o.session_id = ?2
                 AND o.invocation_key = ?3"#,
            params![
                story_id.to_string(),
                session_id.to_string(),
                invocation_key.as_str()
            ],
            |row| {
                Ok(StoredBinding {
                    operation_id: row.get(0)?,
                    invocation_binding_hash: row.get(1)?,
                    parent_model_call_id: row.get(2)?,
                    proposed_tool_call_id: row.get(3)?,
                    provider: row.get(4)?,
                    action: row.get(5)?,
                    argument_hash: row.get(6)?,
                    safe_arguments_json: row.get(7)?,
                    private_arguments: row.get(8)?,
                    policy_snapshot_hash: row.get(9)?,
                    claim_json: row.get(10)?,
                    claim_hash: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn validate_retry_binding(
    input: &NewOperation,
    prepared: &PreparedOperation,
    stored: &StoredBinding,
) -> Result<(), JournalError> {
    let matches = stored.parent_model_call_id == input.parent_model_call_id
        && stored.invocation_binding_hash == prepared.invocation_binding_hash.as_str()
        && stored.proposed_tool_call_id == input.proposed_tool_call_id
        && stored.provider == input.provider
        && stored.action == input.action
        && stored.argument_hash == input.argument_hash.as_str()
        && stored.safe_arguments_json == prepared.safe_arguments_json
        && stored.private_arguments == prepared.private_arguments
        && stored.policy_snapshot_hash == input.policy_snapshot_hash.as_str()
        && stored.claim_json == prepared.claim_json
        && stored.claim_hash == prepared.claim_hash.as_str();
    if matches {
        Ok(())
    } else {
        Err(JournalError::InvocationConflict {
            operation_id: persisted_string(
                stored.operation_id.clone(),
                "conflicting invocation operation id",
            )?,
        })
    }
}

fn operation_version_if_exists(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
) -> Result<Option<u64>, JournalError> {
    connection
        .query_row(
            "SELECT version FROM operations WHERE operation_id = ?1",
            params![operation_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(JournalError::from)?
        .map(|version| crate::rust_u64(version, "operation version"))
        .transpose()
}

fn validate_policy_input(input: &RecordPolicyInput) -> Result<(), JournalError> {
    if input.reason.trim().is_empty() || input.reason.len() > 4_096 {
        return Err(JournalError::Integrity(
            "policy reason must contain 1-4096 bytes".to_owned(),
        ));
    }
    let mut check_ids = HashSet::new();
    for check in &input.checks {
        if check.check_id.trim().is_empty()
            || check.layer.trim().is_empty()
            || check.reason.trim().is_empty()
            || !check_ids.insert(check.check_id.as_str())
        {
            return Err(JournalError::Integrity(
                "policy checks require unique nonempty identifiers, layers, and reasons".to_owned(),
            ));
        }
    }
    let status_matches = match input.decision {
        PolicyDecision::Allowed => input
            .checks
            .iter()
            .all(|check| check.status == PolicyCheckStatus::Passed),
        PolicyDecision::Denied => input
            .checks
            .iter()
            .any(|check| check.status == PolicyCheckStatus::Failed),
        PolicyDecision::RequiresReview => input
            .checks
            .iter()
            .any(|check| check.status == PolicyCheckStatus::RequiresReview),
    };
    if !status_matches {
        return Err(JournalError::Integrity(
            "policy decision does not match its ordered checks".to_owned(),
        ));
    }
    Ok(())
}

fn valid_policy_path(target: OperationState) -> bool {
    OperationState::Proposed.can_transition_to(&OperationState::PolicyEvaluated)
        && (target == OperationState::PolicyEvaluated
            || OperationState::PolicyEvaluated.can_transition_to(&target))
}

fn validate_optional_input_label(
    label: &'static str,
    value: Option<&str>,
) -> Result<(), JournalError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        Err(JournalError::Integrity(format!(
            "{label} must not be empty"
        )))
    } else {
        Ok(())
    }
}
