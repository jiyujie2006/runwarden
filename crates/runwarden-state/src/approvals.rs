use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, ProviderExecutionStatus, ProviderResultView, SafeProviderOutput,
    SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::{
    DataClass, FileAccess, MemoryAccess, NetworkCapability, ResourceClaim,
};
use runwarden_kernel::session::{BudgetCharge, BudgetUsageSnapshot};
use runwarden_kernel::story::{
    ApprovalId, EnforcementMode, EventId, ExecutionLeaseId, ObservationId, OperationId, SessionId,
    StoryId,
};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use crate::events::{NewStoryEvent, append_event_and_frame_tx};
use crate::sessions::load_session_record;
use crate::snapshots::{load_operation_tx, load_story_evidence_tx, verify_story_evidence_tx};
use crate::stories::{load_story_record, validate_digest, validate_nonempty};
use crate::{
    JournalError, StateStore, canonical_json, enum_text, format_time, persisted_enum,
    persisted_json, persisted_string, persisted_time, rust_u64, sqlite_u64,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableApprovalBinding {
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub operation_id: OperationId,
    pub actor_id: String,
    pub authz_id: String,
    pub provider: String,
    pub action: String,
    pub resource_claim_hash: Sha256Digest,
    pub argument_hash: Sha256Digest,
    pub data_classification: Option<DataClass>,
    pub risk_tags: Vec<String>,
    pub policy_snapshot_hash: Sha256Digest,
    pub maximum_consumptions: OneShotConsumption,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneShotConsumption(());

impl OneShotConsumption {
    pub fn new() -> Self {
        Self(())
    }
}

impl Default for OneShotConsumption {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for OneShotConsumption {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for OneShotConsumption {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        if value == 1 {
            Ok(Self::new())
        } else {
            Err(serde::de::Error::custom(
                "maximum_consumptions must be the integer one",
            ))
        }
    }
}

pub struct NewApproval {
    pub approval_id: ApprovalId,
    pub operation_id: OperationId,
    pub binding: DurableApprovalBinding,
    pub expires_at: OffsetDateTime,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecordV1 {
    pub approval_id: ApprovalId,
    pub operation_id: OperationId,
    pub binding: DurableApprovalBinding,
    pub binding_hash: String,
    pub state: ApprovalState,
    pub reviewer: Option<String>,
    pub reason: Option<String>,
    pub expires_at: OffsetDateTime,
    pub lease_id: Option<ExecutionLeaseId>,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerDecision {
    Approve,
    Deny,
}

pub struct ApprovalDecisionInput {
    pub approval_id: ApprovalId,
    pub expected_version: u64,
    pub expected_operation_version: u64,
    pub reviewer: String,
    pub reason: String,
    pub decision: ReviewerDecision,
    pub now: OffsetDateTime,
}

pub struct ExpireApprovalInput {
    pub approval_id: ApprovalId,
    pub expected_approval_version: u64,
    pub expected_operation_version: u64,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseAuthorization {
    StoredPolicyAllow,
    ReviewerApproval {
        approval_id: ApprovalId,
        expected_approval_version: u64,
    },
}

pub struct LeaseRequest {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub authorization: LeaseAuthorization,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub instance_id: String,
    pub instance_token_hash: String,
    pub expected_budget_version: u64,
    pub budget_charge: BudgetCharge,
    pub expires_at: OffsetDateTime,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLease {
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub approval_id: Option<ApprovalId>,
    pub pre_lease_state: OperationState,
    pub instance_id: String,
    pub instance_token_hash: String,
    pub budget_charge: BudgetCharge,
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionStarted {
    pub operation_id: OperationId,
    pub operation_version: u64,
    pub approval_version: Option<u64>,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
}

pub struct ExecutionResultInput {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub next_state: OperationState,
    pub side_effect_state: SideEffectState,
    pub provider_result: ProviderResultView,
    pub actual_budget_charge: BudgetCharge,
    pub now: OffsetDateTime,
}

pub struct ReleaseLeaseInput {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub now: OffsetDateTime,
}

pub struct MarkOutcomeUnknownInput {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub reason_code: String,
    pub now: OffsetDateTime,
}

struct RawApproval {
    approval_id: String,
    story_id: String,
    session_id: String,
    operation_id: String,
    binding_json: String,
    binding_hash: String,
    state: String,
    reviewer: Option<String>,
    reason: Option<String>,
    expires_at: String,
    lease_id: Option<String>,
    lease_owner: Option<String>,
    lease_expires_at: Option<String>,
    version: i64,
    created_at: String,
    updated_at: String,
}

struct StoredApproval {
    record: ApprovalRecordV1,
    story_id: StoryId,
    session_id: SessionId,
    lease_owner: Option<String>,
    lease_expires_at: Option<OffsetDateTime>,
}

struct RawLeaseFields {
    lease_id: Option<String>,
    lease_owner: Option<String>,
    lease_expires_at: Option<String>,
    lease_pre_state: Option<String>,
    lease_instance_id: Option<String>,
    lease_instance_token_hash: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct StoredBudgetUsage {
    story_id: StoryId,
    session_id: SessionId,
    usage: BudgetUsageSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReservationState {
    Reserved,
    Committed,
    Released,
}

impl ReservationState {
    fn parse(raw: &str) -> Result<Self, JournalError> {
        match raw {
            "reserved" => Ok(Self::Reserved),
            "committed" => Ok(Self::Committed),
            "released" => Ok(Self::Released),
            other => Err(JournalError::Integrity(format!(
                "stored budget reservation state is invalid: {other}"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::Released => "released",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StoredReservation {
    lease_id: ExecutionLeaseId,
    story_id: StoryId,
    session_id: SessionId,
    charge: BudgetCharge,
    state: ReservationState,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettledBudgetCharge {
    reserved: BudgetCharge,
    actual: BudgetCharge,
}

impl StateStore {
    pub fn create_approval(&self, input: NewApproval) -> Result<ApprovalRecordV1, JournalError> {
        validate_binding_shape(&input.binding)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        let story = load_story_record(&transaction, operation.story_id)?;
        let session = load_session_record(&transaction, operation.session_id)?;
        validate_binding_context(&input.binding, &operation, &session.record.authority)?;
        if input.binding.operation_id != input.operation_id {
            return Err(JournalError::Integrity(
                "approval input and binding name different operations".to_owned(),
            ));
        }
        if operation.state != OperationState::AwaitingApproval
            || operation.side_effect_state != SideEffectState::NotAttempted
            || load_policy_decision(&transaction, operation.operation_id)?
                != Some(PolicyDecision::RequiresReview)
        {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: enum_text(&operation.state)?,
                to: "pending_approval".to_owned(),
            });
        }
        validate_live_session_for_approval(&session, input.now)?;
        validate_mutation_time(story.updated_at, input.now, "create_approval")?;
        if input.now >= input.expires_at || input.expires_at > session.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "approval_expiry",
                from: format_time(input.now)?,
                to: format_time(input.expires_at)?,
            });
        }
        if let Some(existing) =
            find_existing_approval(&transaction, input.approval_id, input.operation_id)?
        {
            return Err(JournalError::Conflict {
                entity: "approval",
                id: existing,
                expected: 0,
                actual: 1,
            });
        }

        let binding_json = canonical_json(&input.binding)?;
        let binding_hash = Sha256Digest::from_bytes(binding_json.as_bytes());
        let now = format_time(input.now)?;
        transaction.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, reviewer, reason, expires_at, lease_id,
                lease_owner, lease_expires_at, version, created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, ?7,
                NULL, NULL, NULL, 0, ?8, ?8
            )"#,
            params![
                input.approval_id.to_string(),
                operation.story_id.to_string(),
                operation.session_id.to_string(),
                operation.operation_id.to_string(),
                binding_json,
                binding_hash.as_str(),
                format_time(input.expires_at)?,
                now,
            ],
        )?;
        append_approval_event(
            &transaction,
            &operation,
            input.approval_id,
            ApprovalState::Pending,
            None,
            input.now,
        )?;
        let stored = load_approval_by_id_tx(&transaction, input.approval_id)?;
        validate_approval_operation_state(&stored.record, &operation)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(stored.record)
    }

    pub fn approval(&self, approval_id: ApprovalId) -> Result<ApprovalRecordV1, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let stored = load_approval_by_id_tx(&transaction, approval_id)?;
        verify_story_evidence_tx(&transaction, stored.story_id)?;
        let operation = load_operation_tx(&transaction, stored.record.operation_id)?;
        let session = load_session_record(&transaction, stored.session_id)?;
        validate_binding_context(
            &stored.record.binding,
            &operation,
            &session.record.authority,
        )?;
        validate_approval_operation_state(&stored.record, &operation)?;
        transaction.commit()?;
        Ok(stored.record)
    }

    pub fn approval_for_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApprovalRecordV1>, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let operation = load_operation_tx(&transaction, operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        let Some(stored) = load_approval_for_operation_tx(&transaction, operation_id)? else {
            transaction.commit()?;
            return Ok(None);
        };
        let session = load_session_record(&transaction, stored.session_id)?;
        validate_binding_context(
            &stored.record.binding,
            &operation,
            &session.record.authority,
        )?;
        validate_approval_operation_state(&stored.record, &operation)?;
        transaction.commit()?;
        Ok(Some(stored.record))
    }

    pub fn decide_approval(
        &self,
        input: ApprovalDecisionInput,
    ) -> Result<ApprovalRecordV1, JournalError> {
        validate_reviewer_input(&input.reviewer, &input.reason)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = load_approval_by_id_tx(&transaction, input.approval_id)?;
        verify_story_evidence_tx(&transaction, stored.story_id)?;
        require_approval_version(&stored.record, input.expected_version)?;
        require_pending_approval(&stored.record)?;
        if input.now >= stored.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "approval_expiry",
                from: "pending".to_owned(),
                to: "expired".to_owned(),
            });
        }
        let operation = load_operation_tx(&transaction, stored.record.operation_id)?;
        let story = load_story_record(&transaction, stored.story_id)?;
        let session = load_session_record(&transaction, stored.session_id)?;
        validate_binding_context(
            &stored.record.binding,
            &operation,
            &session.record.authority,
        )?;
        validate_approval_operation_state(&stored.record, &operation)?;
        require_operation_version(&operation, input.expected_operation_version)?;
        validate_live_session_for_approval(&session, input.now)?;
        validate_mutation_time(story.updated_at, input.now, "decide_approval")?;

        let (approval_state, operation_state, side_effect_state) = match input.decision {
            ReviewerDecision::Approve => (
                ApprovalState::Approved,
                OperationState::Approved,
                SideEffectState::NotAttempted,
            ),
            ReviewerDecision::Deny => (
                ApprovalState::Denied,
                OperationState::DeniedByReviewer,
                SideEffectState::BlockedBeforeExecution,
            ),
        };
        if !OperationState::AwaitingApproval.can_transition_to(&operation_state) {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: "awaiting_approval".to_owned(),
                to: enum_text(&operation_state)?,
            });
        }
        let next_approval_version = input
            .expected_version
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("approval version overflowed u64".to_owned()))?;
        let next_operation_version =
            input
                .expected_operation_version
                .checked_add(1)
                .ok_or_else(|| {
                    JournalError::Integrity("operation version overflowed u64".to_owned())
                })?;
        let now = format_time(input.now)?;
        let approval_affected = transaction.execute(
            r#"UPDATE approvals
               SET state = ?1, reviewer = ?2, reason = ?3,
                   version = ?4, updated_at = ?5
               WHERE approval_id = ?6 AND state = 'pending' AND version = ?7"#,
            params![
                enum_text(&approval_state)?,
                input.reviewer,
                input.reason,
                sqlite_u64(next_approval_version, "approval version")?,
                now,
                input.approval_id.to_string(),
                sqlite_u64(input.expected_version, "approval version")?,
            ],
        )?;
        if approval_affected != 1 {
            return approval_cas_error(&transaction, input.approval_id, input.expected_version);
        }
        let operation_affected = transaction.execute(
            r#"UPDATE operations
               SET state = ?1, side_effect_state = ?2,
                   version = ?3, updated_at = ?4
               WHERE operation_id = ?5 AND state = 'awaiting_approval'
                 AND version = ?6"#,
            params![
                enum_text(&operation_state)?,
                enum_text(&side_effect_state)?,
                sqlite_u64(next_operation_version, "operation version")?,
                now,
                operation.operation_id.to_string(),
                sqlite_u64(input.expected_operation_version, "operation version")?,
            ],
        )?;
        if operation_affected != 1 {
            return operation_cas_error(
                &transaction,
                operation.operation_id,
                input.expected_operation_version,
            );
        }

        let reviewer_hash = Sha256Digest::from_bytes(input.reviewer.as_bytes());
        append_approval_event(
            &transaction,
            &operation,
            input.approval_id,
            approval_state,
            Some(reviewer_hash),
            input.now,
        )?;
        let updated = load_approval_by_id_tx(&transaction, input.approval_id)?;
        let updated_operation = load_operation_tx(&transaction, operation.operation_id)?;
        validate_approval_operation_state(&updated.record, &updated_operation)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(updated.record)
    }

    pub fn expire_approval(
        &self,
        input: ExpireApprovalInput,
    ) -> Result<ApprovalRecordV1, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = load_approval_by_id_tx(&transaction, input.approval_id)?;
        verify_story_evidence_tx(&transaction, stored.story_id)?;
        require_approval_version(&stored.record, input.expected_approval_version)?;
        require_pending_approval(&stored.record)?;
        if input.now < stored.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "approval_expiry",
                from: "pending".to_owned(),
                to: "not_yet_expired".to_owned(),
            });
        }
        let operation = load_operation_tx(&transaction, stored.record.operation_id)?;
        let story = load_story_record(&transaction, stored.story_id)?;
        let session = load_session_record(&transaction, stored.session_id)?;
        validate_binding_context(
            &stored.record.binding,
            &operation,
            &session.record.authority,
        )?;
        validate_approval_operation_state(&stored.record, &operation)?;
        require_operation_version(&operation, input.expected_operation_version)?;
        validate_mutation_time(story.updated_at, input.now, "expire_approval")?;
        if !OperationState::AwaitingApproval.can_transition_to(&OperationState::Expired) {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: "awaiting_approval".to_owned(),
                to: "expired".to_owned(),
            });
        }

        let next_approval_version = input
            .expected_approval_version
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("approval version overflowed u64".to_owned()))?;
        let next_operation_version =
            input
                .expected_operation_version
                .checked_add(1)
                .ok_or_else(|| {
                    JournalError::Integrity("operation version overflowed u64".to_owned())
                })?;
        let now = format_time(input.now)?;
        let approval_affected = transaction.execute(
            r#"UPDATE approvals
               SET state = 'expired', version = ?1, updated_at = ?2
               WHERE approval_id = ?3 AND state = 'pending' AND version = ?4"#,
            params![
                sqlite_u64(next_approval_version, "approval version")?,
                now,
                input.approval_id.to_string(),
                sqlite_u64(input.expected_approval_version, "approval version")?,
            ],
        )?;
        if approval_affected != 1 {
            return approval_cas_error(
                &transaction,
                input.approval_id,
                input.expected_approval_version,
            );
        }
        let operation_affected = transaction.execute(
            r#"UPDATE operations
               SET state = 'expired', side_effect_state = 'blocked_before_execution',
                   version = ?1, updated_at = ?2
               WHERE operation_id = ?3 AND state = 'awaiting_approval'
                 AND version = ?4"#,
            params![
                sqlite_u64(next_operation_version, "operation version")?,
                now,
                operation.operation_id.to_string(),
                sqlite_u64(input.expected_operation_version, "operation version")?,
            ],
        )?;
        if operation_affected != 1 {
            return operation_cas_error(
                &transaction,
                operation.operation_id,
                input.expected_operation_version,
            );
        }
        append_approval_event(
            &transaction,
            &operation,
            input.approval_id,
            ApprovalState::Expired,
            None,
            input.now,
        )?;
        let updated = load_approval_by_id_tx(&transaction, input.approval_id)?;
        let updated_operation = load_operation_tx(&transaction, operation.operation_id)?;
        validate_approval_operation_state(&updated.record, &updated_operation)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(updated.record)
    }

    pub fn acquire_execution_lease(
        &self,
        input: LeaseRequest,
    ) -> Result<ExecutionLease, JournalError> {
        validate_lease_request_shape(&input)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        let story = load_story_record(&transaction, operation.story_id)?;
        let session = load_session_record(&transaction, operation.session_id)?;
        validate_mutation_time(story.updated_at, input.now, "acquire_execution_lease")?;
        if story.story.enforcement_mode != EnforcementMode::Enforced {
            return Err(JournalError::InvalidTransition {
                entity: "enforcement_mode",
                from: enum_text(&story.story.enforcement_mode)?,
                to: "execution_lease".to_owned(),
            });
        }
        revalidate_active_context_tx(
            &transaction,
            &operation,
            &input.instance_id,
            &input.instance_token_hash,
            input.now,
        )?;
        if input.expires_at > session.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "lease_expiry",
                from: format_time(session.record.expires_at)?,
                to: format_time(input.expires_at)?,
            });
        }

        let stored_approval = match &input.authorization {
            LeaseAuthorization::StoredPolicyAllow => {
                require_operation_version(&operation, input.expected_operation_version)?;
                require_operation_lease_ready(
                    &transaction,
                    &operation,
                    OperationState::PolicyEvaluated,
                    PolicyDecision::Allowed,
                )?;
                if load_approval_for_operation_tx(&transaction, operation.operation_id)?.is_some() {
                    return Err(JournalError::Integrity(
                        "direct policy lease unexpectedly has an approval row".to_owned(),
                    ));
                }
                None
            }
            LeaseAuthorization::ReviewerApproval {
                approval_id,
                expected_approval_version,
            } => {
                let approval = load_approval_by_id_tx(&transaction, *approval_id)?;
                require_approval_version(&approval.record, *expected_approval_version)?;
                if approval.record.operation_id != operation.operation_id {
                    return Err(JournalError::Integrity(
                        "lease approval names a different operation".to_owned(),
                    ));
                }
                if approval.record.state != ApprovalState::Approved {
                    return Err(JournalError::InvalidTransition {
                        entity: "approval",
                        from: enum_text(&approval.record.state)?,
                        to: "leased".to_owned(),
                    });
                }
                if input.now >= approval.record.expires_at
                    || input.expires_at > approval.record.expires_at
                {
                    return Err(JournalError::InvalidTransition {
                        entity: "approval_expiry",
                        from: format_time(approval.record.expires_at)?,
                        to: "execution_lease".to_owned(),
                    });
                }
                validate_binding_context(
                    &approval.record.binding,
                    &operation,
                    &session.record.authority,
                )?;
                validate_approval_operation_state(&approval.record, &operation)?;
                require_operation_version(&operation, input.expected_operation_version)?;
                require_operation_lease_ready(
                    &transaction,
                    &operation,
                    OperationState::Approved,
                    PolicyDecision::RequiresReview,
                )?;
                Some(approval)
            }
        };

        ensure_operation_has_no_lease_tx(&transaction, operation.operation_id)?;
        ensure_lease_id_unused_tx(&transaction, input.lease_id)?;
        reserve_budget_tx(
            &transaction,
            &operation,
            &session.record.authority,
            input.lease_id,
            input.expected_budget_version,
            input.budget_charge,
            input.now,
        )?;

        let lease_expiry = format_time(input.expires_at)?;
        let next_approval_version = if let Some(approval) = stored_approval.as_ref() {
            let next_version = approval.record.version.checked_add(1).ok_or_else(|| {
                JournalError::Integrity("approval version overflowed u64".to_owned())
            })?;
            let affected = transaction.execute(
                r#"UPDATE approvals
                   SET state = 'leased', lease_id = ?1, lease_owner = ?2,
                       lease_expires_at = ?3, version = ?4, updated_at = ?5
                   WHERE approval_id = ?6 AND state = 'approved' AND version = ?7
                     AND lease_id IS NULL AND lease_owner IS NULL
                     AND lease_expires_at IS NULL"#,
                params![
                    input.lease_id.to_string(),
                    input.lease_owner.as_str(),
                    lease_expiry.as_str(),
                    sqlite_u64(next_version, "approval version")?,
                    format_time(input.now)?,
                    approval.record.approval_id.to_string(),
                    sqlite_u64(approval.record.version, "approval version")?,
                ],
            )?;
            if affected != 1 {
                return approval_lease_cas_error(
                    &transaction,
                    approval.record.approval_id,
                    approval.record.version,
                    "leased",
                );
            }
            Some(next_version)
        } else {
            None
        };

        let next_operation_version = operation.version.checked_add(1).ok_or_else(|| {
            JournalError::Integrity("operation version overflowed u64".to_owned())
        })?;
        let pre_lease_state = operation.state;
        let pre_lease_state_text = enum_text(&pre_lease_state)?;
        let affected = transaction.execute(
            r#"UPDATE operations
               SET state = 'execution_leased', version = ?1,
                   lease_id = ?2, lease_owner = ?3, lease_expires_at = ?4,
                   lease_pre_state = ?5, lease_instance_id = ?6,
                   lease_instance_token_hash = ?7, updated_at = ?8
               WHERE operation_id = ?9 AND state = ?10 AND version = ?11
                 AND side_effect_state = 'not_attempted'
                 AND provider_result_json IS NULL
                 AND lease_id IS NULL AND lease_owner IS NULL
                 AND lease_expires_at IS NULL AND lease_pre_state IS NULL
                 AND lease_instance_id IS NULL
                 AND lease_instance_token_hash IS NULL"#,
            params![
                sqlite_u64(next_operation_version, "operation version")?,
                input.lease_id.to_string(),
                input.lease_owner.as_str(),
                lease_expiry,
                pre_lease_state_text.as_str(),
                input.instance_id.as_str(),
                input.instance_token_hash.as_str(),
                format_time(input.now)?,
                operation.operation_id.to_string(),
                pre_lease_state_text,
                sqlite_u64(input.expected_operation_version, "operation version")?,
            ],
        )?;
        if affected != 1 {
            return operation_transition_cas_error(
                &transaction,
                operation.operation_id,
                input.expected_operation_version,
                "execution_leased",
            );
        }
        append_provider_event(
            &transaction,
            &operation,
            "execution_lease_acquired",
            SideEffectState::NotAttempted,
            None,
            None,
            input.now,
        )?;
        let leased_operation = load_operation_tx(&transaction, operation.operation_id)?;
        let lease = decode_execution_lease_tx(&transaction, &leased_operation)?;
        if lease.approval_id.is_some() != next_approval_version.is_some() {
            return Err(JournalError::Integrity(
                "persisted lease authorization branch changed during acquisition".to_owned(),
            ));
        }
        transaction.commit()?;
        self.harden_files()?;
        Ok(lease)
    }

    pub fn execution_lease(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ExecutionLease>, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let operation = load_operation_tx(&transaction, operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        if operation.state != OperationState::ExecutionLeased {
            transaction.commit()?;
            return Ok(None);
        }
        let lease = decode_execution_lease_tx(&transaction, &operation)?;
        transaction.commit()?;
        Ok(Some(lease))
    }

    pub fn has_execution_started(&self, operation_id: OperationId) -> Result<bool, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let operation = load_operation_tx(&transaction, operation_id)?;
        let started = has_execution_started_tx(&transaction, &operation)?;
        transaction.commit()?;
        Ok(started)
    }

    pub fn mark_execution_started(
        &self,
        lease: &ExecutionLease,
    ) -> Result<ExecutionStarted, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&transaction, lease.operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        if operation.state != OperationState::ExecutionLeased {
            return operation_state_conflict_tx(&transaction, &operation);
        }
        let persisted_lease = decode_execution_lease_tx(&transaction, &operation)?;
        if &persisted_lease != lease {
            return Err(JournalError::Integrity(
                "execution lease does not exactly match the durable lease".to_owned(),
            ));
        }
        if has_execution_started_tx(&transaction, &operation)? {
            return operation_state_conflict_tx(&transaction, &operation);
        }
        let story = load_story_record(&transaction, operation.story_id)?;
        let now = OffsetDateTime::now_utc();
        validate_mutation_time(story.updated_at, now, "mark_execution_started")?;
        if now >= lease.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "lease_expiry",
                from: format_time(lease.expires_at)?,
                to: "execution_started".to_owned(),
            });
        }
        revalidate_active_context_tx(
            &transaction,
            &operation,
            &lease.instance_id,
            &lease.instance_token_hash,
            now,
        )?;

        let approval_version = if let Some(approval_id) = lease.approval_id {
            let approval = load_approval_by_id_tx(&transaction, approval_id)?;
            require_exact_approval_lease(&approval, lease, ApprovalState::Leased)?;
            let next_version = approval.record.version.checked_add(1).ok_or_else(|| {
                JournalError::Integrity("approval version overflowed u64".to_owned())
            })?;
            let affected = transaction.execute(
                r#"UPDATE approvals
                   SET state = 'consumed', version = ?1, updated_at = ?2
                   WHERE approval_id = ?3 AND state = 'leased' AND version = ?4
                     AND lease_id = ?5 AND lease_owner = ?6
                     AND lease_expires_at = ?7"#,
                params![
                    sqlite_u64(next_version, "approval version")?,
                    format_time(now)?,
                    approval_id.to_string(),
                    sqlite_u64(approval.record.version, "approval version")?,
                    lease.lease_id.to_string(),
                    lease.lease_owner.as_str(),
                    format_time(lease.expires_at)?,
                ],
            )?;
            if affected != 1 {
                return approval_lease_cas_error(
                    &transaction,
                    approval_id,
                    approval.record.version,
                    "consumed",
                );
            }
            Some(next_version)
        } else {
            if load_approval_for_operation_tx(&transaction, operation.operation_id)?.is_some() {
                return Err(JournalError::Integrity(
                    "direct execution lease gained an approval row".to_owned(),
                ));
            }
            None
        };

        let next_operation_version = operation.version.checked_add(1).ok_or_else(|| {
            JournalError::Integrity("operation version overflowed u64".to_owned())
        })?;
        let affected = transaction.execute(
            r#"UPDATE operations
               SET state = 'executing', version = ?1, updated_at = ?2
               WHERE operation_id = ?3 AND state = 'execution_leased'
                 AND version = ?4 AND lease_id = ?5 AND lease_owner = ?6
                 AND lease_expires_at = ?7 AND lease_pre_state = ?8
                 AND lease_instance_id = ?9
                 AND lease_instance_token_hash = ?10"#,
            params![
                sqlite_u64(next_operation_version, "operation version")?,
                format_time(now)?,
                operation.operation_id.to_string(),
                sqlite_u64(operation.version, "operation version")?,
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
                operation.version,
                "executing",
            );
        }
        append_provider_event(
            &transaction,
            &operation,
            "provider_execution_started",
            SideEffectState::NotAttempted,
            None,
            None,
            now,
        )?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(ExecutionStarted {
            operation_id: operation.operation_id,
            operation_version: next_operation_version,
            approval_version,
            lease_id: lease.lease_id,
            lease_owner: lease.lease_owner.clone(),
        })
    }

    pub fn record_execution_result(&self, input: ExecutionResultInput) -> Result<(), JournalError> {
        validate_execution_result(&input)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        require_operation_version(&operation, input.expected_operation_version)?;
        if operation.state != OperationState::Executing {
            return Err(JournalError::InvalidTransition {
                entity: "operation",
                from: enum_text(&operation.state)?,
                to: enum_text(&input.next_state)?,
            });
        }
        let story = load_story_record(&transaction, operation.story_id)?;
        validate_mutation_time(story.updated_at, input.now, "record_execution_result")?;
        let lease = decode_execution_lease_tx(&transaction, &operation)?;
        if lease.lease_id != input.lease_id || lease.lease_owner != input.lease_owner {
            return Err(JournalError::Integrity(
                "execution result does not match the durable lease identity".to_owned(),
            ));
        }
        if !has_execution_started_tx(&transaction, &operation)? {
            return Err(JournalError::Integrity(
                "execution result has no verified execution-start event".to_owned(),
            ));
        }
        let reservation = load_reservation_tx(&transaction, input.lease_id)?;
        if reservation.state != ReservationState::Reserved
            || reservation.story_id != operation.story_id
            || reservation.session_id != operation.session_id
        {
            return Err(JournalError::Integrity(
                "execution result reservation is not the active operation reservation".to_owned(),
            ));
        }
        require_charge_within(input.actual_budget_charge, reservation.charge)?;
        settle_budget_tx(
            &transaction,
            reservation,
            input.actual_budget_charge,
            input.now,
        )?;

        let provider_result_json = canonical_json(&input.provider_result)?;
        let next_operation_version = operation.version.checked_add(1).ok_or_else(|| {
            JournalError::Integrity("operation version overflowed u64".to_owned())
        })?;
        let affected = transaction.execute(
            r#"UPDATE operations
               SET state = ?1, side_effect_state = ?2,
                   provider_result_json = ?3, version = ?4, updated_at = ?5
               WHERE operation_id = ?6 AND state = 'executing' AND version = ?7
                 AND lease_id = ?8 AND lease_owner = ?9"#,
            params![
                enum_text(&input.next_state)?,
                enum_text(&input.side_effect_state)?,
                provider_result_json,
                sqlite_u64(next_operation_version, "operation version")?,
                format_time(input.now)?,
                operation.operation_id.to_string(),
                sqlite_u64(input.expected_operation_version, "operation version")?,
                input.lease_id.to_string(),
                input.lease_owner.as_str(),
            ],
        )?;
        if affected != 1 {
            return operation_transition_cas_error(
                &transaction,
                operation.operation_id,
                input.expected_operation_version,
                "execution_result",
            );
        }
        let receipt_hash = match &input.provider_result.output {
            SafeProviderOutput::Email { receipt_hash } => Some(receipt_hash.clone()),
            _ => None,
        };
        let execution_status = enum_text(&input.provider_result.execution_status)?;
        append_provider_event(
            &transaction,
            &operation,
            &execution_status,
            input.side_effect_state,
            input.provider_result.output_hash.clone(),
            receipt_hash,
            input.now,
        )?;
        transaction.commit()?;
        self.harden_files()
    }
}

pub(crate) fn validate_binding_shape(binding: &DurableApprovalBinding) -> Result<(), JournalError> {
    validate_nonempty("approval actor id", &binding.actor_id)?;
    validate_nonempty("approval authz id", &binding.authz_id)?;
    EventCode::try_from(binding.provider.clone())
        .map_err(|_| JournalError::Integrity("approval provider is invalid".to_owned()))?;
    EventCode::try_from(binding.action.clone())
        .map_err(|_| JournalError::Integrity("approval action is invalid".to_owned()))?;
    if binding.risk_tags.is_empty()
        || binding.risk_tags.iter().any(|tag| {
            EventCode::try_from(tag.clone()).is_err() || tag.trim().is_empty() || tag.len() > 128
        })
        || binding.risk_tags.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(JournalError::Integrity(
            "approval risk tags must be nonempty, valid, sorted, and unique".to_owned(),
        ));
    }
    Ok(())
}

fn validate_binding_context(
    binding: &DurableApprovalBinding,
    operation: &SecurityOperation,
    authority: &runwarden_kernel::session::AuthoritySnapshot,
) -> Result<(), JournalError> {
    validate_binding_shape(binding)?;
    let expected_classification = resource_classification(&operation.resource_claim);
    let expected_risk_tags = resource_risk_tags(&operation.resource_claim);
    if binding.story_id != operation.story_id
        || binding.session_id != operation.session_id
        || binding.operation_id != operation.operation_id
        || binding.actor_id != authority.actor_id
        || binding.authz_id != authority.authz_id
        || authority.session_id != operation.session_id
        || binding.provider != operation.provider
        || binding.action != operation.action
        || binding.resource_claim_hash != operation.resource_claim.digest()
        || binding.argument_hash != operation.argument_hash
        || binding.data_classification != expected_classification
        || binding.risk_tags != expected_risk_tags
        || binding.policy_snapshot_hash != operation.policy_snapshot_hash
        || binding.policy_snapshot_hash.as_str() != authority.policy_snapshot_hash
    {
        return Err(JournalError::Integrity(
            "approval binding does not match the durable operation context".to_owned(),
        ));
    }
    Ok(())
}

fn resource_risk_tags(resource: &ResourceClaim) -> Vec<String> {
    let tags: &[&str] = match resource {
        ResourceClaim::File {
            access: FileAccess::Read,
            ..
        } => &["filesystem_read"],
        ResourceClaim::File {
            access: FileAccess::Write,
            ..
        } => &["filesystem_write"],
        ResourceClaim::Network { .. } => &["network_egress"],
        ResourceClaim::Email { .. } => &["email_send", "network_egress"],
        ResourceClaim::Memory {
            access: MemoryAccess::Read,
            ..
        } => &["memory_read"],
        ResourceClaim::Memory {
            access: MemoryAccess::Write,
            ..
        } => &["memory_write"],
        ResourceClaim::CodeExecution {
            network: NetworkCapability::None,
            ..
        } => &["code_execution"],
        ResourceClaim::CodeExecution {
            network: NetworkCapability::Brokered,
            ..
        } => &["code_execution", "network_egress"],
        ResourceClaim::InputInspection { .. } => &["input_inspection"],
        ResourceClaim::Evidence { .. } => &["evidence_read"],
        ResourceClaim::Artifact { .. } => &["artifact_write"],
        ResourceClaim::OpaqueLegacy { .. } => &["legacy_opaque"],
    };
    tags.iter().map(|tag| (*tag).to_owned()).collect()
}

fn resource_classification(resource: &ResourceClaim) -> Option<DataClass> {
    match resource {
        ResourceClaim::File { classification, .. }
        | ResourceClaim::Network { classification, .. }
        | ResourceClaim::Email { classification, .. }
        | ResourceClaim::InputInspection { classification, .. } => Some(*classification),
        ResourceClaim::Memory { .. }
        | ResourceClaim::CodeExecution { .. }
        | ResourceClaim::Evidence { .. }
        | ResourceClaim::Artifact { .. }
        | ResourceClaim::OpaqueLegacy { .. } => None,
    }
}

fn validate_live_session_for_approval(
    session: &crate::sessions::StoredSession,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    if !session.active || session.record.authority.authz_state != "active" {
        return Err(JournalError::InvalidTransition {
            entity: "session",
            from: session.record.authority.authz_state.clone(),
            to: "approval".to_owned(),
        });
    }
    if now >= session.record.expires_at {
        return Err(JournalError::InvalidTransition {
            entity: "session",
            from: "expired".to_owned(),
            to: "approval".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_mutation_time(
    current: OffsetDateTime,
    now: OffsetDateTime,
    action: &'static str,
) -> Result<(), JournalError> {
    if now < current {
        Err(JournalError::InvalidTransition {
            entity: "journal_time",
            from: format_time(current)?,
            to: action.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_reviewer_input(reviewer: &str, reason: &str) -> Result<(), JournalError> {
    if reviewer.trim().is_empty() || reviewer.len() > 256 {
        return Err(JournalError::Integrity(
            "reviewer must contain 1-256 bytes".to_owned(),
        ));
    }
    if reason.trim().is_empty() || reason.len() > 4_096 {
        return Err(JournalError::Integrity(
            "review reason must contain 1-4096 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn require_approval_version(
    approval: &ApprovalRecordV1,
    expected: u64,
) -> Result<(), JournalError> {
    if approval.version == expected {
        Ok(())
    } else {
        Err(JournalError::Conflict {
            entity: "approval",
            id: approval.approval_id.to_string(),
            expected,
            actual: approval.version,
        })
    }
}

pub(crate) fn require_operation_version(
    operation: &SecurityOperation,
    expected: u64,
) -> Result<(), JournalError> {
    if operation.version == expected {
        Ok(())
    } else {
        Err(JournalError::Conflict {
            entity: "operation",
            id: operation.operation_id.to_string(),
            expected,
            actual: operation.version,
        })
    }
}

fn require_pending_approval(approval: &ApprovalRecordV1) -> Result<(), JournalError> {
    if approval.state == ApprovalState::Pending {
        Ok(())
    } else {
        Err(JournalError::InvalidTransition {
            entity: "approval",
            from: enum_text(&approval.state)?,
            to: "review_decision".to_owned(),
        })
    }
}

fn validate_bounded_nonempty(
    label: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), JournalError> {
    if value.trim().is_empty() || value.len() > maximum_bytes {
        Err(JournalError::Integrity(format!(
            "{label} must contain 1-{maximum_bytes} bytes"
        )))
    } else {
        Ok(())
    }
}

fn validate_lease_request_shape(input: &LeaseRequest) -> Result<(), JournalError> {
    validate_bounded_nonempty("lease owner", &input.lease_owner, 256)?;
    validate_bounded_nonempty("lease instance id", &input.instance_id, 256)?;
    validate_digest("lease instance token hash", &input.instance_token_hash)?;
    if input.now >= input.expires_at {
        return Err(JournalError::InvalidTransition {
            entity: "lease_expiry",
            from: format_time(input.now)?,
            to: format_time(input.expires_at)?,
        });
    }
    if input.budget_charge.calls == 0 {
        return Err(JournalError::Integrity(
            "an execution lease must reserve at least one provider call".to_owned(),
        ));
    }
    sqlite_u64(input.expected_operation_version, "operation version")?;
    sqlite_u64(input.expected_budget_version, "budget version")?;
    sqlite_u64(input.budget_charge.calls, "reserved calls")?;
    sqlite_u64(input.budget_charge.file_bytes, "reserved file bytes")?;
    sqlite_u64(input.budget_charge.network_bytes, "reserved network bytes")?;
    Ok(())
}

fn revalidate_active_context_tx(
    connection: &Connection,
    operation: &SecurityOperation,
    expected_instance_id: &str,
    expected_token_hash: &str,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    type RawActiveContext = (i64, String, String, String, String, String);
    let raw: Option<RawActiveContext> = connection
        .query_row(
            r#"SELECT singleton, instance_id, story_id, session_id,
                      instance_token_hash, heartbeat_at
               FROM active_instances WHERE singleton = 1"#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((singleton, instance_id, story_id, session_id, token_hash, heartbeat_at)) = raw else {
        return Err(JournalError::InvalidTransition {
            entity: "active_instance",
            from: "absent".to_owned(),
            to: "execution".to_owned(),
        });
    };
    if singleton != 1 {
        return Err(JournalError::Integrity(
            "active instance singleton key is not one".to_owned(),
        ));
    }
    let stored_story_id: StoryId = persisted_string(story_id, "active instance story id")?;
    let stored_session_id: SessionId = persisted_string(session_id, "active instance session id")?;
    let stored_token_hash: Sha256Digest =
        persisted_string(token_hash.clone(), "active instance token hash")?;
    let expected_token: Sha256Digest = persisted_string(
        expected_token_hash.to_owned(),
        "expected active instance token hash",
    )?;
    validate_bounded_nonempty("active instance id", &instance_id, 256)?;
    let heartbeat = persisted_time(&heartbeat_at, "active instance heartbeat")?;
    if format_time(heartbeat)? != heartbeat_at {
        return Err(JournalError::Integrity(
            "active instance heartbeat is not canonical".to_owned(),
        ));
    }
    if stored_story_id != operation.story_id
        || stored_session_id != operation.session_id
        || instance_id != expected_instance_id
        || stored_token_hash != expected_token
        || token_hash != expected_token_hash
    {
        return Err(JournalError::Integrity(
            "active instance binding does not match the execution context".to_owned(),
        ));
    }
    let story = load_story_record(connection, stored_story_id)?;
    let session = load_session_record(connection, stored_session_id)?;
    if story.story.authority != session.record.authority
        || session.record.story_id != operation.story_id
        || session.record.authority.session_id != operation.session_id
        || operation.policy_snapshot_hash.as_str() != session.record.policy_snapshot_hash
        || session.record.policy_snapshot_hash != session.record.authority.policy_snapshot_hash
        || !session
            .record
            .authority
            .allowed_providers
            .iter()
            .any(|provider| provider == &operation.provider)
    {
        return Err(JournalError::Integrity(
            "active session authority does not match the operation context".to_owned(),
        ));
    }
    if !session.active || session.record.authority.authz_state != "active" {
        return Err(JournalError::InvalidTransition {
            entity: "session",
            from: session.record.authority.authz_state,
            to: "execution".to_owned(),
        });
    }
    if heartbeat >= session.record.expires_at || now >= session.record.expires_at {
        return Err(JournalError::InvalidTransition {
            entity: "session",
            from: "expired".to_owned(),
            to: "execution".to_owned(),
        });
    }
    Ok(())
}

fn require_operation_lease_ready(
    connection: &Connection,
    operation: &SecurityOperation,
    expected_state: OperationState,
    expected_decision: PolicyDecision,
) -> Result<(), JournalError> {
    if operation.state != expected_state
        || operation.side_effect_state != SideEffectState::NotAttempted
        || operation.provider_result.is_some()
        || !operation
            .state
            .can_transition_to(&OperationState::ExecutionLeased)
        || load_policy_decision(connection, operation.operation_id)? != Some(expected_decision)
    {
        return Err(JournalError::InvalidTransition {
            entity: "operation",
            from: enum_text(&operation.state)?,
            to: "execution_leased".to_owned(),
        });
    }
    Ok(())
}

fn raw_lease_fields_tx(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<RawLeaseFields, JournalError> {
    connection
        .query_row(
            r#"SELECT lease_id, lease_owner, lease_expires_at, lease_pre_state,
                      lease_instance_id, lease_instance_token_hash
               FROM operations WHERE operation_id = ?1"#,
            params![operation_id.to_string()],
            |row| {
                Ok(RawLeaseFields {
                    lease_id: row.get(0)?,
                    lease_owner: row.get(1)?,
                    lease_expires_at: row.get(2)?,
                    lease_pre_state: row.get(3)?,
                    lease_instance_id: row.get(4)?,
                    lease_instance_token_hash: row.get(5)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| JournalError::NotFound {
            entity: "operation",
            id: operation_id.to_string(),
        })
}

fn ensure_operation_has_no_lease_tx(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<(), JournalError> {
    let raw = raw_lease_fields_tx(connection, operation_id)?;
    if raw.lease_id.is_some()
        || raw.lease_owner.is_some()
        || raw.lease_expires_at.is_some()
        || raw.lease_pre_state.is_some()
        || raw.lease_instance_id.is_some()
        || raw.lease_instance_token_hash.is_some()
    {
        Err(JournalError::Integrity(
            "unleased operation contains durable lease material".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_lease_id_unused_tx(
    connection: &Connection,
    lease_id: ExecutionLeaseId,
) -> Result<(), JournalError> {
    let existing: i64 = connection.query_row(
        r#"SELECT
             (SELECT count(*) FROM budget_reservations WHERE lease_id = ?1) +
             (SELECT count(*) FROM operations WHERE lease_id = ?1)"#,
        params![lease_id.to_string()],
        |row| row.get(0),
    )?;
    if existing == 0 {
        Ok(())
    } else {
        Err(JournalError::Conflict {
            entity: "lease",
            id: lease_id.to_string(),
            expected: 0,
            actual: u64::try_from(existing).unwrap_or(u64::MAX),
        })
    }
}

fn load_budget_usage_tx(
    connection: &Connection,
    session_id: SessionId,
) -> Result<StoredBudgetUsage, JournalError> {
    type RawBudget = (String, String, i64, i64, i64, i64, i64, i64, i64);
    let raw: Option<RawBudget> = connection
        .query_row(
            r#"SELECT story_id, session_id, version, calls_reserved,
                      calls_committed, file_bytes_reserved, file_bytes_committed,
                      network_bytes_reserved, network_bytes_committed
               FROM budget_usage WHERE session_id = ?1"#,
            params![session_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    let Some((story_id, stored_session_id, version, cr, cc, fr, fc, nr, nc)) = raw else {
        return Err(JournalError::Integrity(format!(
            "session {session_id} has no budget usage row"
        )));
    };
    let stored_session_id: SessionId = persisted_string(stored_session_id, "budget session id")?;
    if stored_session_id != session_id {
        return Err(JournalError::Integrity(
            "budget session id disagrees with its lookup key".to_owned(),
        ));
    }
    Ok(StoredBudgetUsage {
        story_id: persisted_string(story_id, "budget story id")?,
        session_id: stored_session_id,
        usage: BudgetUsageSnapshot {
            version: rust_u64(version, "budget version")?,
            calls_reserved: rust_u64(cr, "reserved calls")?,
            calls_committed: rust_u64(cc, "committed calls")?,
            file_bytes_reserved: rust_u64(fr, "reserved file bytes")?,
            file_bytes_committed: rust_u64(fc, "committed file bytes")?,
            network_bytes_reserved: rust_u64(nr, "reserved network bytes")?,
            network_bytes_committed: rust_u64(nc, "committed network bytes")?,
        },
    })
}

fn validate_budget_reservation_aggregate_tx(
    connection: &Connection,
    budget: &StoredBudgetUsage,
) -> Result<(), JournalError> {
    let rows = {
        let mut statement = connection.prepare(
            r#"SELECT charge_json, state
               FROM budget_reservations
               WHERE story_id = ?1 AND session_id = ?2
               ORDER BY lease_id"#,
        )?;
        statement
            .query_map(
                params![budget.story_id.to_string(), budget.session_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?
    };
    let zero = BudgetCharge {
        calls: 0,
        file_bytes: 0,
        network_bytes: 0,
    };
    let mut reserved = zero;
    let mut committed = zero;
    for (charge_json, raw_state) in rows {
        match ReservationState::parse(&raw_state)? {
            ReservationState::Reserved => {
                let charge: BudgetCharge =
                    persisted_json(&charge_json, "budget reservation charge")?;
                if canonical_json(&charge)? != charge_json {
                    return Err(JournalError::Integrity(
                        "budget reservation charge is not canonical".to_owned(),
                    ));
                }
                checked_add_budget_charge(&mut reserved, charge, "reserved")?;
            }
            ReservationState::Committed => {
                let settled: SettledBudgetCharge =
                    persisted_json(&charge_json, "settled budget reservation charge")?;
                if canonical_json(&settled)? != charge_json {
                    return Err(JournalError::Integrity(
                        "settled budget reservation charge is not canonical".to_owned(),
                    ));
                }
                require_charge_within(settled.actual, settled.reserved)?;
                checked_add_budget_charge(&mut committed, settled.actual, "committed")?;
            }
            ReservationState::Released => {
                let charge: BudgetCharge =
                    persisted_json(&charge_json, "released budget reservation charge")?;
                if canonical_json(&charge)? != charge_json {
                    return Err(JournalError::Integrity(
                        "released budget reservation charge is not canonical".to_owned(),
                    ));
                }
            }
        }
    }
    if reserved.calls != budget.usage.calls_reserved
        || reserved.file_bytes != budget.usage.file_bytes_reserved
        || reserved.network_bytes != budget.usage.network_bytes_reserved
        || committed.calls != budget.usage.calls_committed
        || committed.file_bytes != budget.usage.file_bytes_committed
        || committed.network_bytes != budget.usage.network_bytes_committed
    {
        return Err(JournalError::Integrity(
            "budget usage counters disagree with durable reservation totals".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_budget_reservation_aggregate_tx(
    connection: &Connection,
    session_id: SessionId,
) -> Result<(), JournalError> {
    let budget = load_budget_usage_tx(connection, session_id)?;
    validate_budget_reservation_aggregate_tx(connection, &budget)
}

fn checked_add_budget_charge(
    total: &mut BudgetCharge,
    charge: BudgetCharge,
    state: &'static str,
) -> Result<(), JournalError> {
    total.calls = total
        .calls
        .checked_add(charge.calls)
        .ok_or_else(|| JournalError::Integrity(format!("{state} call budget overflowed")))?;
    total.file_bytes = total
        .file_bytes
        .checked_add(charge.file_bytes)
        .ok_or_else(|| JournalError::Integrity(format!("{state} file budget overflowed")))?;
    total.network_bytes = total
        .network_bytes
        .checked_add(charge.network_bytes)
        .ok_or_else(|| JournalError::Integrity(format!("{state} network budget overflowed")))?;
    Ok(())
}

fn next_reserved_component(
    label: &'static str,
    reserved: u64,
    committed: u64,
    requested: u64,
    maximum: u64,
) -> Result<u64, JournalError> {
    let next_reserved = reserved
        .checked_add(requested)
        .ok_or_else(|| JournalError::Integrity(format!("{label} reservation overflowed")))?;
    let total = committed
        .checked_add(next_reserved)
        .ok_or_else(|| JournalError::Integrity(format!("{label} usage overflowed")))?;
    if total > maximum {
        Err(JournalError::Integrity(format!(
            "{label} budget exceeded: requested total {total}, maximum {maximum}"
        )))
    } else {
        Ok(next_reserved)
    }
}

fn reserve_budget_tx(
    connection: &Connection,
    operation: &SecurityOperation,
    authority: &runwarden_kernel::session::AuthoritySnapshot,
    lease_id: ExecutionLeaseId,
    expected_version: u64,
    charge: BudgetCharge,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    let budget = load_budget_usage_tx(connection, operation.session_id)?;
    if budget.story_id != operation.story_id || budget.session_id != operation.session_id {
        return Err(JournalError::Integrity(
            "budget usage does not match the leased operation context".to_owned(),
        ));
    }
    validate_budget_reservation_aggregate_tx(connection, &budget)?;
    if budget.usage.version != expected_version {
        return Err(JournalError::Conflict {
            entity: "budget",
            id: operation.session_id.to_string(),
            expected: expected_version,
            actual: budget.usage.version,
        });
    }
    let calls_reserved = next_reserved_component(
        "call",
        budget.usage.calls_reserved,
        budget.usage.calls_committed,
        charge.calls,
        authority.budgets.max_calls,
    )?;
    let file_bytes_reserved = next_reserved_component(
        "file byte",
        budget.usage.file_bytes_reserved,
        budget.usage.file_bytes_committed,
        charge.file_bytes,
        authority.budgets.max_file_bytes,
    )?;
    let network_bytes_reserved = next_reserved_component(
        "network byte",
        budget.usage.network_bytes_reserved,
        budget.usage.network_bytes_committed,
        charge.network_bytes,
        authority.budgets.max_network_bytes,
    )?;
    let next_version = expected_version
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("budget version overflowed u64".to_owned()))?;
    let affected = connection.execute(
        r#"UPDATE budget_usage
           SET version = ?1, calls_reserved = ?2, file_bytes_reserved = ?3,
               network_bytes_reserved = ?4
           WHERE session_id = ?5 AND story_id = ?6 AND version = ?7"#,
        params![
            sqlite_u64(next_version, "budget version")?,
            sqlite_u64(calls_reserved, "reserved calls")?,
            sqlite_u64(file_bytes_reserved, "reserved file bytes")?,
            sqlite_u64(network_bytes_reserved, "reserved network bytes")?,
            operation.session_id.to_string(),
            operation.story_id.to_string(),
            sqlite_u64(expected_version, "budget version")?,
        ],
    )?;
    if affected != 1 {
        let actual = load_budget_usage_tx(connection, operation.session_id)?;
        return Err(JournalError::Conflict {
            entity: "budget",
            id: operation.session_id.to_string(),
            expected: expected_version,
            actual: actual.usage.version,
        });
    }
    let charge_json = canonical_json(&charge)?;
    connection.execute(
        r#"INSERT INTO budget_reservations (
             lease_id, story_id, session_id, charge_json, state,
             created_at, updated_at
           ) VALUES (?1, ?2, ?3, ?4, 'reserved', ?5, ?5)"#,
        params![
            lease_id.to_string(),
            operation.story_id.to_string(),
            operation.session_id.to_string(),
            charge_json,
            format_time(now)?,
        ],
    )?;
    Ok(())
}

fn load_reservation_tx(
    connection: &Connection,
    lease_id: ExecutionLeaseId,
) -> Result<StoredReservation, JournalError> {
    type RawReservation = (String, String, String, String, String, String, String);
    let raw: Option<RawReservation> = connection
        .query_row(
            r#"SELECT lease_id, story_id, session_id, charge_json, state,
                      created_at, updated_at
               FROM budget_reservations WHERE lease_id = ?1"#,
            params![lease_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_lease_id, story_id, session_id, charge_json, state, created, updated)) = raw
    else {
        return Err(JournalError::NotFound {
            entity: "budget_reservation",
            id: lease_id.to_string(),
        });
    };
    let stored_lease_id: ExecutionLeaseId =
        persisted_string(stored_lease_id, "reservation lease id")?;
    if stored_lease_id != lease_id {
        return Err(JournalError::Integrity(
            "reservation lease id disagrees with its lookup key".to_owned(),
        ));
    }
    let state = ReservationState::parse(&state)?;
    let charge = match state {
        ReservationState::Reserved | ReservationState::Released => {
            let charge: BudgetCharge = persisted_json(&charge_json, "budget reservation charge")?;
            if canonical_json(&charge)? != charge_json {
                return Err(JournalError::Integrity(
                    "budget reservation charge is not canonical".to_owned(),
                ));
            }
            charge
        }
        ReservationState::Committed => {
            let settled: SettledBudgetCharge =
                persisted_json(&charge_json, "settled budget reservation charge")?;
            if canonical_json(&settled)? != charge_json {
                return Err(JournalError::Integrity(
                    "settled budget reservation charge is not canonical".to_owned(),
                ));
            }
            require_charge_within(settled.actual, settled.reserved)?;
            settled.reserved
        }
    };
    let created_at = persisted_time(&created, "reservation created_at")?;
    let updated_at = persisted_time(&updated, "reservation updated_at")?;
    if format_time(created_at)? != created
        || format_time(updated_at)? != updated
        || updated_at < created_at
    {
        return Err(JournalError::Integrity(
            "budget reservation timestamps are invalid or noncanonical".to_owned(),
        ));
    }
    Ok(StoredReservation {
        lease_id: stored_lease_id,
        story_id: persisted_string(story_id, "reservation story id")?,
        session_id: persisted_string(session_id, "reservation session id")?,
        charge,
        state,
        updated_at,
    })
}

fn require_charge_within(actual: BudgetCharge, reserved: BudgetCharge) -> Result<(), JournalError> {
    if actual.calls <= reserved.calls
        && actual.file_bytes <= reserved.file_bytes
        && actual.network_bytes <= reserved.network_bytes
    {
        Ok(())
    } else {
        Err(JournalError::Integrity(
            "actual budget charge exceeds its durable reservation".to_owned(),
        ))
    }
}

fn settle_budget_tx(
    connection: &Connection,
    reservation: StoredReservation,
    actual: BudgetCharge,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    if reservation.state != ReservationState::Reserved {
        return Err(JournalError::InvalidTransition {
            entity: "budget_reservation",
            from: reservation.state.as_str().to_owned(),
            to: ReservationState::Committed.as_str().to_owned(),
        });
    }
    require_charge_within(actual, reservation.charge)?;
    if now < reservation.updated_at {
        return Err(JournalError::InvalidTransition {
            entity: "budget_reservation_time",
            from: format_time(reservation.updated_at)?,
            to: format_time(now)?,
        });
    }
    let budget = load_budget_usage_tx(connection, reservation.session_id)?;
    if budget.story_id != reservation.story_id {
        return Err(JournalError::Integrity(
            "budget reservation story disagrees with budget usage".to_owned(),
        ));
    }
    validate_budget_reservation_aggregate_tx(connection, &budget)?;
    let calls_reserved = budget
        .usage
        .calls_reserved
        .checked_sub(reservation.charge.calls)
        .ok_or_else(|| JournalError::Integrity("reserved call budget underflowed".to_owned()))?;
    let calls_committed = budget
        .usage
        .calls_committed
        .checked_add(actual.calls)
        .ok_or_else(|| JournalError::Integrity("committed call budget overflowed".to_owned()))?;
    let file_bytes_reserved = budget
        .usage
        .file_bytes_reserved
        .checked_sub(reservation.charge.file_bytes)
        .ok_or_else(|| JournalError::Integrity("reserved file budget underflowed".to_owned()))?;
    let file_bytes_committed = budget
        .usage
        .file_bytes_committed
        .checked_add(actual.file_bytes)
        .ok_or_else(|| JournalError::Integrity("committed file budget overflowed".to_owned()))?;
    let network_bytes_reserved = budget
        .usage
        .network_bytes_reserved
        .checked_sub(reservation.charge.network_bytes)
        .ok_or_else(|| JournalError::Integrity("reserved network budget underflowed".to_owned()))?;
    let network_bytes_committed = budget
        .usage
        .network_bytes_committed
        .checked_add(actual.network_bytes)
        .ok_or_else(|| JournalError::Integrity("committed network budget overflowed".to_owned()))?;
    let next_version = budget
        .usage
        .version
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("budget version overflowed u64".to_owned()))?;
    let affected = connection.execute(
        r#"UPDATE budget_usage
           SET version = ?1, calls_reserved = ?2, calls_committed = ?3,
               file_bytes_reserved = ?4, file_bytes_committed = ?5,
               network_bytes_reserved = ?6, network_bytes_committed = ?7
           WHERE session_id = ?8 AND story_id = ?9 AND version = ?10"#,
        params![
            sqlite_u64(next_version, "budget version")?,
            sqlite_u64(calls_reserved, "reserved calls")?,
            sqlite_u64(calls_committed, "committed calls")?,
            sqlite_u64(file_bytes_reserved, "reserved file bytes")?,
            sqlite_u64(file_bytes_committed, "committed file bytes")?,
            sqlite_u64(network_bytes_reserved, "reserved network bytes")?,
            sqlite_u64(network_bytes_committed, "committed network bytes")?,
            reservation.session_id.to_string(),
            reservation.story_id.to_string(),
            sqlite_u64(budget.usage.version, "budget version")?,
        ],
    )?;
    if affected != 1 {
        let actual_budget = load_budget_usage_tx(connection, reservation.session_id)?;
        return Err(JournalError::Conflict {
            entity: "budget",
            id: reservation.session_id.to_string(),
            expected: budget.usage.version,
            actual: actual_budget.usage.version,
        });
    }
    let settled = canonical_json(&SettledBudgetCharge {
        reserved: reservation.charge,
        actual,
    })?;
    let affected = connection.execute(
        r#"UPDATE budget_reservations
           SET charge_json = ?1, state = 'committed', updated_at = ?2
           WHERE lease_id = ?3 AND story_id = ?4 AND session_id = ?5
             AND state = 'reserved' AND updated_at = ?6"#,
        params![
            settled,
            format_time(now)?,
            reservation.lease_id.to_string(),
            reservation.story_id.to_string(),
            reservation.session_id.to_string(),
            format_time(reservation.updated_at)?,
        ],
    )?;
    if affected != 1 {
        let current = load_reservation_tx(connection, reservation.lease_id)?;
        return Err(JournalError::InvalidTransition {
            entity: "budget_reservation",
            from: current.state.as_str().to_owned(),
            to: ReservationState::Committed.as_str().to_owned(),
        });
    }
    Ok(())
}

/// Release an unconsumed execution reservation while retaining its durable
/// lease identifier. Recovery is deliberately narrower than normal result
/// settlement: no committed counter is advanced because provider execution
/// has not started.
pub(crate) fn release_execution_budget_tx(
    connection: &Connection,
    lease: &ExecutionLease,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    let reservation = load_reservation_tx(connection, lease.lease_id)?;
    if reservation.state != ReservationState::Reserved
        || reservation.story_id != lease.story_id
        || reservation.session_id != lease.session_id
        || reservation.charge != lease.budget_charge
    {
        return Err(JournalError::Integrity(
            "released execution lease does not match its active budget reservation".to_owned(),
        ));
    }
    if now < reservation.updated_at {
        return Err(JournalError::InvalidTransition {
            entity: "budget_reservation_time",
            from: format_time(reservation.updated_at)?,
            to: format_time(now)?,
        });
    }
    let budget = load_budget_usage_tx(connection, reservation.session_id)?;
    if budget.story_id != reservation.story_id || budget.session_id != reservation.session_id {
        return Err(JournalError::Integrity(
            "budget reservation story disagrees with budget usage".to_owned(),
        ));
    }
    validate_budget_reservation_aggregate_tx(connection, &budget)?;
    let calls_reserved = budget
        .usage
        .calls_reserved
        .checked_sub(reservation.charge.calls)
        .ok_or_else(|| JournalError::Integrity("reserved call budget underflowed".to_owned()))?;
    let file_bytes_reserved = budget
        .usage
        .file_bytes_reserved
        .checked_sub(reservation.charge.file_bytes)
        .ok_or_else(|| JournalError::Integrity("reserved file budget underflowed".to_owned()))?;
    let network_bytes_reserved = budget
        .usage
        .network_bytes_reserved
        .checked_sub(reservation.charge.network_bytes)
        .ok_or_else(|| JournalError::Integrity("reserved network budget underflowed".to_owned()))?;
    let next_version = budget
        .usage
        .version
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("budget version overflowed u64".to_owned()))?;
    let affected = connection.execute(
        r#"UPDATE budget_usage
           SET version = ?1, calls_reserved = ?2, file_bytes_reserved = ?3,
               network_bytes_reserved = ?4
           WHERE session_id = ?5 AND story_id = ?6 AND version = ?7"#,
        params![
            sqlite_u64(next_version, "budget version")?,
            sqlite_u64(calls_reserved, "reserved calls")?,
            sqlite_u64(file_bytes_reserved, "reserved file bytes")?,
            sqlite_u64(network_bytes_reserved, "reserved network bytes")?,
            reservation.session_id.to_string(),
            reservation.story_id.to_string(),
            sqlite_u64(budget.usage.version, "budget version")?,
        ],
    )?;
    if affected != 1 {
        let actual = load_budget_usage_tx(connection, reservation.session_id)?;
        return Err(JournalError::Conflict {
            entity: "budget",
            id: reservation.session_id.to_string(),
            expected: budget.usage.version,
            actual: actual.usage.version,
        });
    }
    let affected = connection.execute(
        r#"UPDATE budget_reservations
           SET state = 'released', updated_at = ?1
           WHERE lease_id = ?2 AND story_id = ?3 AND session_id = ?4
             AND state = 'reserved' AND updated_at = ?5"#,
        params![
            format_time(now)?,
            reservation.lease_id.to_string(),
            reservation.story_id.to_string(),
            reservation.session_id.to_string(),
            format_time(reservation.updated_at)?,
        ],
    )?;
    if affected != 1 {
        let current = load_reservation_tx(connection, reservation.lease_id)?;
        return Err(JournalError::InvalidTransition {
            entity: "budget_reservation",
            from: current.state.as_str().to_owned(),
            to: ReservationState::Released.as_str().to_owned(),
        });
    }
    Ok(())
}

/// Conservatively account for a provider call whose durable outcome could not
/// be recorded. Every reserved unit is treated as committed.
pub(crate) fn commit_unknown_execution_budget_tx(
    connection: &Connection,
    lease: &ExecutionLease,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    let reservation = load_reservation_tx(connection, lease.lease_id)?;
    if reservation.state != ReservationState::Reserved
        || reservation.story_id != lease.story_id
        || reservation.session_id != lease.session_id
        || reservation.charge != lease.budget_charge
    {
        return Err(JournalError::Integrity(
            "unknown execution does not match its active budget reservation".to_owned(),
        ));
    }
    settle_budget_tx(connection, reservation, reservation.charge, now)
}

/// Restore the approval half of an unstarted lease. Direct policy approvals
/// have no row; reviewed approvals are reusable only while their original
/// expiry remains live.
pub(crate) fn restore_unstarted_approval_tx(
    connection: &Connection,
    operation: &SecurityOperation,
    lease: &ExecutionLease,
    now: OffsetDateTime,
) -> Result<OperationState, JournalError> {
    let Some(approval_id) = lease.approval_id else {
        if load_approval_for_operation_tx(connection, operation.operation_id)?.is_some() {
            return Err(JournalError::Integrity(
                "direct execution lease gained an approval row".to_owned(),
            ));
        }
        return Ok(OperationState::PolicyEvaluated);
    };
    let approval = load_approval_by_id_tx(connection, approval_id)?;
    require_exact_approval_lease(&approval, lease, ApprovalState::Leased)?;
    let (approval_state, operation_state) = if now >= approval.record.expires_at {
        (ApprovalState::Expired, OperationState::Expired)
    } else {
        (ApprovalState::Approved, OperationState::Approved)
    };
    let next_version = approval
        .record
        .version
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("approval version overflowed u64".to_owned()))?;
    let affected = connection.execute(
        r#"UPDATE approvals
           SET state = ?1, lease_id = NULL, lease_owner = NULL,
               lease_expires_at = NULL, version = ?2, updated_at = ?3
           WHERE approval_id = ?4 AND operation_id = ?5
             AND state = 'leased' AND version = ?6
             AND lease_id = ?7 AND lease_owner = ?8
             AND lease_expires_at = ?9"#,
        params![
            enum_text(&approval_state)?,
            sqlite_u64(next_version, "approval version")?,
            format_time(now)?,
            approval_id.to_string(),
            operation.operation_id.to_string(),
            sqlite_u64(approval.record.version, "approval version")?,
            lease.lease_id.to_string(),
            lease.lease_owner.as_str(),
            format_time(lease.expires_at)?,
        ],
    )?;
    if affected != 1 {
        return approval_lease_cas_error(
            connection,
            approval_id,
            approval.record.version,
            "restore_unstarted_lease",
        );
    }
    Ok(operation_state)
}

pub(crate) fn decode_execution_lease_tx(
    connection: &Connection,
    operation: &SecurityOperation,
) -> Result<ExecutionLease, JournalError> {
    if !matches!(
        operation.state,
        OperationState::ExecutionLeased | OperationState::Executing
    ) || operation.side_effect_state != SideEffectState::NotAttempted
        || operation.provider_result.is_some()
    {
        return Err(JournalError::InvalidTransition {
            entity: "operation",
            from: enum_text(&operation.state)?,
            to: "decode_execution_lease".to_owned(),
        });
    }
    let raw = raw_lease_fields_tx(connection, operation.operation_id)?;
    let (
        Some(raw_lease_id),
        Some(lease_owner),
        Some(raw_expiry),
        Some(raw_pre_state),
        Some(instance_id),
        Some(instance_token_hash),
    ) = (
        raw.lease_id,
        raw.lease_owner,
        raw.lease_expires_at,
        raw.lease_pre_state,
        raw.lease_instance_id,
        raw.lease_instance_token_hash,
    )
    else {
        return Err(JournalError::Integrity(
            "leased operation has incomplete durable lease fields".to_owned(),
        ));
    };
    let lease_id: ExecutionLeaseId = persisted_string(raw_lease_id, "operation lease id")?;
    validate_bounded_nonempty("operation lease owner", &lease_owner, 256)?;
    validate_bounded_nonempty("operation lease instance id", &instance_id, 256)?;
    validate_digest("operation lease instance token hash", &instance_token_hash)?;
    let expires_at = persisted_time(&raw_expiry, "operation lease expiry")?;
    if format_time(expires_at)? != raw_expiry {
        return Err(JournalError::Integrity(
            "operation lease expiry is not canonical".to_owned(),
        ));
    }
    let pre_lease_state: OperationState =
        persisted_enum(raw_pre_state, "operation pre-lease state")?;
    if !matches!(
        pre_lease_state,
        OperationState::PolicyEvaluated | OperationState::Approved
    ) {
        return Err(JournalError::Integrity(
            "operation pre-lease state is not executable".to_owned(),
        ));
    }
    let session = load_session_record(connection, operation.session_id)?;
    if session.record.story_id != operation.story_id
        || session.record.policy_snapshot_hash != operation.policy_snapshot_hash.as_str()
        || expires_at > session.record.expires_at
    {
        return Err(JournalError::Integrity(
            "operation lease disagrees with its durable session".to_owned(),
        ));
    }
    let reservation = load_reservation_tx(connection, lease_id)?;
    if reservation.state != ReservationState::Reserved
        || reservation.story_id != operation.story_id
        || reservation.session_id != operation.session_id
    {
        return Err(JournalError::Integrity(
            "operation lease has no matching active budget reservation".to_owned(),
        ));
    }
    let story = load_story_record(connection, operation.story_id)?;
    if reservation.updated_at > story.updated_at {
        return Err(JournalError::Integrity(
            "operation reservation timestamp is ahead of the story clock".to_owned(),
        ));
    }
    verify_budget_reservation_aggregate_tx(connection, operation.session_id)?;
    let stored_approval = load_approval_for_operation_tx(connection, operation.operation_id)?;
    let approval_id = match pre_lease_state {
        OperationState::PolicyEvaluated => {
            if load_policy_decision(connection, operation.operation_id)?
                != Some(PolicyDecision::Allowed)
                || stored_approval.is_some()
            {
                return Err(JournalError::Integrity(
                    "direct execution lease lacks its stored policy authorization".to_owned(),
                ));
            }
            None
        }
        OperationState::Approved => {
            if load_policy_decision(connection, operation.operation_id)?
                != Some(PolicyDecision::RequiresReview)
            {
                return Err(JournalError::Integrity(
                    "reviewed execution lease lacks its stored policy authorization".to_owned(),
                ));
            }
            let approval = stored_approval.ok_or_else(|| {
                JournalError::Integrity("reviewed execution lease has no approval".to_owned())
            })?;
            validate_binding_context(
                &approval.record.binding,
                operation,
                &session.record.authority,
            )?;
            let expected_state = if operation.state == OperationState::ExecutionLeased {
                ApprovalState::Leased
            } else {
                ApprovalState::Consumed
            };
            let provisional = ExecutionLease {
                lease_id,
                lease_owner: lease_owner.clone(),
                approval_id: Some(approval.record.approval_id),
                pre_lease_state,
                instance_id: instance_id.clone(),
                instance_token_hash: instance_token_hash.clone(),
                budget_charge: reservation.charge,
                operation_id: operation.operation_id,
                story_id: operation.story_id,
                session_id: operation.session_id,
                provider: operation.provider.clone(),
                action: operation.action.clone(),
                argument_hash: operation.argument_hash.clone(),
                resource_claim_hash: operation.resource_claim.digest(),
                policy_snapshot_hash: operation.policy_snapshot_hash.clone(),
                expires_at,
            };
            require_exact_approval_lease(&approval, &provisional, expected_state)?;
            Some(approval.record.approval_id)
        }
        _ => unreachable!("pre-lease state was checked above"),
    };
    Ok(ExecutionLease {
        lease_id,
        lease_owner,
        approval_id,
        pre_lease_state,
        instance_id,
        instance_token_hash,
        budget_charge: reservation.charge,
        operation_id: operation.operation_id,
        story_id: operation.story_id,
        session_id: operation.session_id,
        provider: operation.provider.clone(),
        action: operation.action.clone(),
        argument_hash: operation.argument_hash.clone(),
        resource_claim_hash: operation.resource_claim.digest(),
        policy_snapshot_hash: operation.policy_snapshot_hash.clone(),
        expires_at,
    })
}

fn require_exact_approval_lease(
    approval: &StoredApproval,
    lease: &ExecutionLease,
    expected_state: ApprovalState,
) -> Result<(), JournalError> {
    if approval.record.state != expected_state
        || Some(approval.record.approval_id) != lease.approval_id
        || approval.record.operation_id != lease.operation_id
        || approval.record.lease_id != Some(lease.lease_id)
        || approval.lease_owner.as_deref() != Some(lease.lease_owner.as_str())
        || approval.lease_expires_at != Some(lease.expires_at)
        || lease.expires_at > approval.record.expires_at
    {
        return Err(JournalError::Integrity(
            "approval lease does not exactly match the operation lease".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn has_execution_started_tx(
    connection: &Connection,
    operation: &SecurityOperation,
) -> Result<bool, JournalError> {
    let evidence = load_story_evidence_tx(connection, operation.story_id)?;
    let count = evidence
        .events
        .iter()
        .filter(|event| {
            event.operation_id == Some(operation.operation_id)
                && event.provider.as_ref().map(EventCode::as_str)
                    == Some(operation.provider.as_str())
                && matches!(
                    event.payload(),
                    StoryEventPayload::ProviderExecution {
                        execution_status,
                        side_effect_state: SideEffectState::NotAttempted,
                        output_hash: None,
                        receipt_hash: None,
                    } if execution_status.as_str() == "provider_execution_started"
                )
        })
        .count();
    if count > 1 {
        Err(JournalError::Integrity(
            "operation has more than one verified execution-start event".to_owned(),
        ))
    } else {
        Ok(count == 1)
    }
}

fn execution_leased_version_tx(
    connection: &Connection,
    operation: &SecurityOperation,
) -> Result<u64, JournalError> {
    let evidence = load_story_evidence_tx(connection, operation.story_id)?;
    let mut leased_version = None;
    for (event, frame) in evidence.events.iter().zip(&evidence.replay_frames) {
        let is_acquisition = event.operation_id == Some(operation.operation_id)
            && event.provider.as_ref().map(EventCode::as_str) == Some(operation.provider.as_str())
            && matches!(
                event.payload(),
                StoryEventPayload::ProviderExecution {
                    execution_status,
                    side_effect_state: SideEffectState::NotAttempted,
                    output_hash: None,
                    receipt_hash: None,
                } if execution_status.as_str() == "execution_lease_acquired"
            );
        if !is_acquisition {
            continue;
        }
        let framed_operation = frame
            .story
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .ok_or_else(|| {
                JournalError::Integrity("lease-acquisition frame omits its operation".to_owned())
            })?;
        if framed_operation.state != OperationState::ExecutionLeased
            || leased_version.is_some_and(|previous| framed_operation.version <= previous)
        {
            return Err(JournalError::Integrity(
                "operation lease-acquisition versions are not strictly increasing".to_owned(),
            ));
        }
        leased_version = Some(framed_operation.version);
    }
    leased_version.ok_or_else(|| {
        JournalError::Integrity("operation has no verified lease-acquisition event".to_owned())
    })
}

fn validate_execution_result(input: &ExecutionResultInput) -> Result<(), JournalError> {
    validate_bounded_nonempty("result lease owner", &input.lease_owner, 256)?;
    let valid = matches!(
        (
            input.next_state,
            input.provider_result.execution_status,
            input.side_effect_state,
        ),
        (
            OperationState::Completed,
            ProviderExecutionStatus::Completed,
            SideEffectState::Completed,
        ) | (
            OperationState::Failed,
            ProviderExecutionStatus::NotExecuted,
            SideEffectState::BlockedBeforeExecution,
        ) | (
            OperationState::Failed,
            ProviderExecutionStatus::FailedBeforeSideEffect,
            SideEffectState::BlockedBeforeExecution | SideEffectState::FailedBeforeSideEffect,
        ) | (
            OperationState::Failed,
            ProviderExecutionStatus::ExecutedWithError,
            SideEffectState::ExecutedWithError,
        )
    );
    if !valid {
        return Err(JournalError::InvalidTransition {
            entity: "execution_result",
            from: enum_text(&input.provider_result.execution_status)?,
            to: format!(
                "{}/{}",
                enum_text(&input.next_state)?,
                enum_text(&input.side_effect_state)?
            ),
        });
    }
    for (label, value) in [
        (
            "provider error kind",
            input.provider_result.error_kind.as_deref(),
        ),
        (
            "provider reason code",
            input.provider_result.reason_code.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            EventCode::try_from(value.to_owned())
                .map_err(|error| JournalError::Integrity(format!("{label} is invalid: {error}")))?;
        }
    }
    if input.provider_result.execution_status == ProviderExecutionStatus::Completed {
        if input.provider_result.error_kind.is_some() {
            return Err(JournalError::Integrity(
                "completed provider result unexpectedly has an error kind".to_owned(),
            ));
        }
    } else if input.provider_result.reason_code.is_none() {
        return Err(JournalError::Integrity(
            "failed provider result is missing a stable reason code".to_owned(),
        ));
    }
    if matches!(
        input.provider_result.execution_status,
        ProviderExecutionStatus::NotExecuted | ProviderExecutionStatus::FailedBeforeSideEffect
    ) && (!matches!(input.provider_result.output, SafeProviderOutput::None)
        || input.provider_result.output_hash.is_some())
    {
        return Err(JournalError::Integrity(
            "pre-side-effect provider result unexpectedly contains output".to_owned(),
        ));
    }
    if matches!(
        input.provider_result.execution_status,
        ProviderExecutionStatus::NotExecuted | ProviderExecutionStatus::FailedBeforeSideEffect
    ) && (input.actual_budget_charge.calls != 0
        || input.actual_budget_charge.file_bytes != 0
        || input.actual_budget_charge.network_bytes != 0)
    {
        return Err(JournalError::Integrity(
            "pre-side-effect provider result must release its full reservation".to_owned(),
        ));
    }
    canonical_json(&input.provider_result)?;
    sqlite_u64(input.actual_budget_charge.calls, "actual calls")?;
    sqlite_u64(input.actual_budget_charge.file_bytes, "actual file bytes")?;
    sqlite_u64(
        input.actual_budget_charge.network_bytes,
        "actual network bytes",
    )?;
    Ok(())
}

pub(crate) fn append_provider_event(
    transaction: &Transaction<'_>,
    operation: &SecurityOperation,
    execution_status: &str,
    side_effect_state: SideEffectState,
    output_hash: Option<Sha256Digest>,
    receipt_hash: Option<Sha256Digest>,
    recorded_at: OffsetDateTime,
) -> Result<(), JournalError> {
    let provider = EventCode::try_from(operation.provider.clone()).map_err(|error| {
        JournalError::Integrity(format!("operation provider cannot be sealed: {error}"))
    })?;
    let execution_status = EventCode::try_from(execution_status.to_owned()).map_err(|error| {
        JournalError::Integrity(format!(
            "provider execution status cannot be sealed: {error}"
        ))
    })?;
    append_event_and_frame_tx(
        transaction,
        NewStoryEvent {
            obs_id: ObservationId::new(),
            event_id: EventId::new(),
            story_id: operation.story_id,
            session_id: operation.session_id,
            operation_id: Some(operation.operation_id),
            provider: Some(provider),
            payload: StoryEventPayload::ProviderExecution {
                execution_status,
                side_effect_state,
                output_hash,
                receipt_hash,
            },
            recorded_at,
        },
    )?;
    Ok(())
}

fn operation_state_conflict_tx<T>(
    connection: &Connection,
    operation: &SecurityOperation,
) -> Result<T, JournalError> {
    let expected = execution_leased_version_tx(connection, operation)?;
    if operation.version <= expected {
        return Err(JournalError::Integrity(
            "operation state changed without advancing its lease version".to_owned(),
        ));
    }
    Err(JournalError::Conflict {
        entity: "operation",
        id: operation.operation_id.to_string(),
        expected,
        actual: operation.version,
    })
}

fn find_existing_approval(
    connection: &Connection,
    approval_id: ApprovalId,
    operation_id: OperationId,
) -> Result<Option<String>, JournalError> {
    connection
        .query_row(
            r#"SELECT approval_id FROM approvals
               WHERE approval_id = ?1 OR operation_id = ?2 LIMIT 1"#,
            params![approval_id.to_string(), operation_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn load_policy_decision(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<PolicyDecision>, JournalError> {
    let raw: Option<String> = connection.query_row(
        "SELECT policy_decision FROM operations WHERE operation_id = ?1",
        params![operation_id.to_string()],
        |row| row.get(0),
    )?;
    raw.map(|value| persisted_enum(value, "operation policy decision"))
        .transpose()
}

fn load_approval_by_id_tx(
    connection: &Connection,
    approval_id: ApprovalId,
) -> Result<StoredApproval, JournalError> {
    let raw = query_approval(
        connection,
        "WHERE approval_id = ?1",
        approval_id.to_string(),
    )?
    .ok_or_else(|| JournalError::NotFound {
        entity: "approval",
        id: approval_id.to_string(),
    })?;
    decode_approval(raw)
}

fn load_approval_for_operation_tx(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StoredApproval>, JournalError> {
    query_approval(
        connection,
        "WHERE operation_id = ?1",
        operation_id.to_string(),
    )?
    .map(decode_approval)
    .transpose()
}

fn query_approval(
    connection: &Connection,
    predicate: &str,
    id: String,
) -> Result<Option<RawApproval>, JournalError> {
    let sql = format!(
        r#"SELECT approval_id, story_id, session_id, operation_id,
                  binding_json, binding_hash, state, reviewer, reason,
                  expires_at, lease_id, lease_owner, lease_expires_at,
                  version, created_at, updated_at
           FROM approvals {predicate}"#
    );
    connection
        .query_row(&sql, params![id], |row| {
            Ok(RawApproval {
                approval_id: row.get(0)?,
                story_id: row.get(1)?,
                session_id: row.get(2)?,
                operation_id: row.get(3)?,
                binding_json: row.get(4)?,
                binding_hash: row.get(5)?,
                state: row.get(6)?,
                reviewer: row.get(7)?,
                reason: row.get(8)?,
                expires_at: row.get(9)?,
                lease_id: row.get(10)?,
                lease_owner: row.get(11)?,
                lease_expires_at: row.get(12)?,
                version: row.get(13)?,
                created_at: row.get(14)?,
                updated_at: row.get(15)?,
            })
        })
        .optional()
        .map_err(Into::into)
}

fn decode_approval(raw: RawApproval) -> Result<StoredApproval, JournalError> {
    let approval_id: ApprovalId = persisted_string(raw.approval_id, "approval id")?;
    let story_id: StoryId = persisted_string(raw.story_id, "approval story id")?;
    let session_id: SessionId = persisted_string(raw.session_id, "approval session id")?;
    let operation_id: OperationId = persisted_string(raw.operation_id, "approval operation id")?;
    let binding: DurableApprovalBinding = persisted_json(&raw.binding_json, "approval binding")?;
    validate_binding_shape(&binding)?;
    if canonical_json(&binding)? != raw.binding_json
        || binding.story_id != story_id
        || binding.session_id != session_id
        || binding.operation_id != operation_id
    {
        return Err(JournalError::Integrity(
            "stored approval binding is noncanonical or context-mismatched".to_owned(),
        ));
    }
    let binding_hash: Sha256Digest =
        persisted_string(raw.binding_hash.clone(), "approval binding hash")?;
    if Sha256Digest::from_bytes(raw.binding_json.as_bytes()) != binding_hash {
        return Err(JournalError::Integrity(
            "stored approval binding hash does not match its binding".to_owned(),
        ));
    }
    let state: ApprovalState = persisted_enum(raw.state, "approval state")?;
    if raw.reviewer.is_some() != raw.reason.is_some() {
        return Err(JournalError::Integrity(
            "stored approval reviewer and reason are incomplete".to_owned(),
        ));
    }
    if state == ApprovalState::Pending && raw.reviewer.is_some() {
        return Err(JournalError::Integrity(
            "pending approval unexpectedly has reviewer material".to_owned(),
        ));
    }
    if matches!(state, ApprovalState::Approved | ApprovalState::Denied) && raw.reviewer.is_none() {
        return Err(JournalError::Integrity(
            "decided approval is missing reviewer material".to_owned(),
        ));
    }
    let lease_id = raw
        .lease_id
        .map(|value| persisted_string::<ExecutionLeaseId>(value, "approval lease id"))
        .transpose()?;
    let lease_expires_at = raw
        .lease_expires_at
        .as_deref()
        .map(|value| persisted_time(value, "approval lease expiry"))
        .transpose()?;
    if let (Some(raw_expiry), Some(parsed_expiry)) =
        (raw.lease_expires_at.as_deref(), lease_expires_at)
        && format_time(parsed_expiry)? != raw_expiry
    {
        return Err(JournalError::Integrity(
            "stored approval lease expiry is not canonical".to_owned(),
        ));
    }
    if lease_id.is_some() != raw.lease_owner.is_some()
        || lease_id.is_some() != lease_expires_at.is_some()
    {
        return Err(JournalError::Integrity(
            "stored approval lease fields are incomplete".to_owned(),
        ));
    }
    let lease_required = matches!(state, ApprovalState::Leased | ApprovalState::Consumed);
    if lease_required != lease_id.is_some() {
        return Err(JournalError::Integrity(
            "stored approval lease material disagrees with its state".to_owned(),
        ));
    }
    if matches!(
        state,
        ApprovalState::Pending | ApprovalState::Approved | ApprovalState::Denied
    ) && lease_id.is_some()
    {
        return Err(JournalError::Integrity(
            "unleased approval unexpectedly has lease material".to_owned(),
        ));
    }
    if matches!(
        state,
        ApprovalState::Leased | ApprovalState::Consumed | ApprovalState::Revoked
    ) && raw.reviewer.is_none()
    {
        return Err(JournalError::Integrity(
            "post-review approval is missing reviewer material".to_owned(),
        ));
    }
    if let Some(owner) = raw.lease_owner.as_deref() {
        validate_bounded_nonempty("approval lease owner", owner, 256)?;
    }
    let expires_at = persisted_time(&raw.expires_at, "approval expiry")?;
    let created_at = persisted_time(&raw.created_at, "approval created_at")?;
    let updated_at = persisted_time(&raw.updated_at, "approval updated_at")?;
    if format_time(expires_at)? != raw.expires_at
        || format_time(created_at)? != raw.created_at
        || format_time(updated_at)? != raw.updated_at
        || updated_at < created_at
        || expires_at <= created_at
        || lease_expires_at.is_some_and(|lease_expiry| lease_expiry > expires_at)
        || lease_expires_at.is_some_and(|lease_expiry| lease_expiry <= updated_at)
    {
        return Err(JournalError::Integrity(
            "stored approval timestamps are invalid or noncanonical".to_owned(),
        ));
    }
    Ok(StoredApproval {
        record: ApprovalRecordV1 {
            approval_id,
            operation_id,
            binding,
            binding_hash: raw.binding_hash,
            state,
            reviewer: raw.reviewer,
            reason: raw.reason,
            expires_at,
            lease_id,
            version: rust_u64(raw.version, "approval version")?,
        },
        story_id,
        session_id,
        lease_owner: raw.lease_owner,
        lease_expires_at,
    })
}

fn validate_approval_operation_state(
    approval: &ApprovalRecordV1,
    operation: &SecurityOperation,
) -> Result<(), JournalError> {
    let valid = match approval.state {
        ApprovalState::Pending => operation.state == OperationState::AwaitingApproval,
        ApprovalState::Approved => operation.state == OperationState::Approved,
        ApprovalState::Denied => operation.state == OperationState::DeniedByReviewer,
        ApprovalState::Expired => operation.state == OperationState::Expired,
        ApprovalState::Leased => operation.state == OperationState::ExecutionLeased,
        ApprovalState::Consumed => matches!(
            operation.state,
            OperationState::Executing
                | OperationState::Completed
                | OperationState::Failed
                | OperationState::OutcomeUnknown
        ),
        ApprovalState::Revoked => operation.state == OperationState::DeniedByReviewer,
    };
    if valid {
        Ok(())
    } else {
        Err(JournalError::Integrity(
            "approval and operation states are inconsistent".to_owned(),
        ))
    }
}

fn append_approval_event(
    transaction: &Transaction<'_>,
    operation: &SecurityOperation,
    approval_id: ApprovalId,
    state: ApprovalState,
    reviewer_id_hash: Option<Sha256Digest>,
    recorded_at: OffsetDateTime,
) -> Result<(), JournalError> {
    let provider = EventCode::try_from(operation.provider.clone()).map_err(|_| {
        JournalError::Integrity("stored approval provider cannot be sealed".to_owned())
    })?;
    append_event_and_frame_tx(
        transaction,
        NewStoryEvent {
            obs_id: ObservationId::new(),
            event_id: EventId::new(),
            story_id: operation.story_id,
            session_id: operation.session_id,
            operation_id: Some(operation.operation_id),
            provider: Some(provider),
            payload: StoryEventPayload::ApprovalLifecycle {
                approval_id,
                state,
                reviewer_id_hash,
            },
            recorded_at,
        },
    )?;
    Ok(())
}

fn approval_cas_error<T>(
    connection: &Connection,
    approval_id: ApprovalId,
    expected: u64,
) -> Result<T, JournalError> {
    let stored = load_approval_by_id_tx(connection, approval_id)?;
    if stored.record.version != expected {
        Err(JournalError::Conflict {
            entity: "approval",
            id: approval_id.to_string(),
            expected,
            actual: stored.record.version,
        })
    } else {
        Err(JournalError::InvalidTransition {
            entity: "approval",
            from: enum_text(&stored.record.state)?,
            to: "review_decision".to_owned(),
        })
    }
}

fn approval_lease_cas_error<T>(
    connection: &Connection,
    approval_id: ApprovalId,
    expected: u64,
    target: &'static str,
) -> Result<T, JournalError> {
    let stored = load_approval_by_id_tx(connection, approval_id)?;
    if stored.record.version != expected {
        Err(JournalError::Conflict {
            entity: "approval",
            id: approval_id.to_string(),
            expected,
            actual: stored.record.version,
        })
    } else {
        Err(JournalError::InvalidTransition {
            entity: "approval",
            from: enum_text(&stored.record.state)?,
            to: target.to_owned(),
        })
    }
}

fn operation_cas_error<T>(
    connection: &Connection,
    operation_id: OperationId,
    expected: u64,
) -> Result<T, JournalError> {
    let operation = load_operation_tx(connection, operation_id)?;
    if operation.version != expected {
        Err(JournalError::Conflict {
            entity: "operation",
            id: operation_id.to_string(),
            expected,
            actual: operation.version,
        })
    } else {
        Err(JournalError::InvalidTransition {
            entity: "operation",
            from: enum_text(&operation.state)?,
            to: "approval_decision".to_owned(),
        })
    }
}

pub(crate) fn operation_transition_cas_error<T>(
    connection: &Connection,
    operation_id: OperationId,
    expected: u64,
    target: &'static str,
) -> Result<T, JournalError> {
    let operation = load_operation_tx(connection, operation_id)?;
    if operation.version != expected {
        Err(JournalError::Conflict {
            entity: "operation",
            id: operation_id.to_string(),
            expected,
            actual: operation.version,
        })
    } else {
        Err(JournalError::InvalidTransition {
            entity: "operation",
            from: enum_text(&operation.state)?,
            to: target.to_owned(),
        })
    }
}
