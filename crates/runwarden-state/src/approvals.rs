use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, ProviderResultView, SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::{
    DataClass, FileAccess, MemoryAccess, NetworkCapability, ResourceClaim,
};
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{
    ApprovalId, EventId, ExecutionLeaseId, ObservationId, OperationId, SessionId, StoryId,
};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use crate::events::{NewStoryEvent, append_event_and_frame_tx};
use crate::sessions::load_session_record;
use crate::snapshots::{load_operation_tx, verify_story_evidence_tx};
use crate::stories::{load_story_record, validate_nonempty};
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

#[allow(dead_code)]
struct StoredApproval {
    record: ApprovalRecordV1,
    story_id: StoryId,
    session_id: SessionId,
    lease_owner: Option<String>,
    lease_expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
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

fn validate_mutation_time(
    current: OffsetDateTime,
    now: OffsetDateTime,
    action: &'static str,
) -> Result<(), JournalError> {
    if now < current {
        Err(JournalError::InvalidTransition {
            entity: "approval_time",
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

fn require_operation_version(
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
    if lease_id.is_some() != raw.lease_owner.is_some()
        || lease_id.is_some() != lease_expires_at.is_some()
    {
        return Err(JournalError::Integrity(
            "stored approval lease fields are incomplete".to_owned(),
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
    let expires_at = persisted_time(&raw.expires_at, "approval expiry")?;
    let created_at = persisted_time(&raw.created_at, "approval created_at")?;
    let updated_at = persisted_time(&raw.updated_at, "approval updated_at")?;
    if format_time(expires_at)? != raw.expires_at
        || format_time(created_at)? != raw.created_at
        || format_time(updated_at)? != raw.updated_at
        || updated_at < created_at
        || expires_at <= created_at
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
        created_at,
        updated_at,
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
