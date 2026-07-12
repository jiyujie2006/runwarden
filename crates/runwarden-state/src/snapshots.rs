use std::collections::HashSet;

use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    ApprovalView, OperationState, PolicyCheck, ProviderResultView, SafeArgumentView,
    SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::story::{
    ApprovalId, EvidenceStatus, ExecutionLeaseId, InvocationKey, ObservationId, OperationId,
    SecurityStory, StoryClaim, StoryEvidenceView, StoryId, StoryReplayFrame, StoryStatus,
};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEvent};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::operations::{
    InvocationBindingMaterial, invocation_binding_hash, load_frozen_proposal_tx,
};
use crate::sessions::load_session_record;
use crate::stories::load_story_record;
use crate::{
    JournalError, StateStore, canonical_json, format_time, persisted_enum, persisted_json,
    persisted_string, persisted_time, rust_u64,
};

/// The operation portion of a display-safe story snapshot.
///
/// Keep this query explicit: it is also a regression surface proving that
/// reviewer views do not fetch journal-only authorization material.
pub const STORY_SNAPSHOT_SQL: &str = r#"
SELECT
    o.operation_id,
    o.story_id,
    o.session_id,
    o.parent_model_call_id,
    o.proposed_tool_call_id,
    o.provider,
    o.action,
    o.argument_hash,
    o.redacted_arguments_json,
    o.policy_snapshot_hash,
    o.policy_decision,
    o.state,
    o.side_effect_state,
    o.provider_result_json,
    o.version,
    o.created_at,
    o.updated_at,
    r.claim_json,
    r.claim_hash,
    (
        SELECT e.sequence
        FROM events e
        WHERE e.story_id = o.story_id
          AND e.operation_id = o.operation_id
          AND e.event_type = 'operation_proposed'
        ORDER BY e.sequence
        LIMIT 1
    ) AS proposed_sequence
FROM operations o
JOIN resource_claims r
  ON r.story_id = o.story_id AND r.operation_id = o.operation_id
WHERE o.story_id = ?1
ORDER BY proposed_sequence, o.created_at, o.operation_id
"#;

struct RawOperation {
    operation_id: String,
    story_id: String,
    session_id: String,
    parent_model_call_id: Option<String>,
    proposed_tool_call_id: Option<String>,
    provider: String,
    action: String,
    argument_hash: String,
    arguments_json: String,
    policy_snapshot_hash: String,
    policy_decision: Option<String>,
    state: String,
    side_effect_state: String,
    provider_result_json: Option<String>,
    version: i64,
    created_at: String,
    updated_at: String,
    claim_json: String,
    claim_hash: String,
    proposed_sequence: Option<i64>,
}

struct RawEvent {
    story_id: String,
    sequence: i64,
    obs_id: String,
    event_id: String,
    session_id: String,
    operation_id: Option<String>,
    event_type: String,
    provider: Option<String>,
    payload_json: String,
    previous_hash: Option<String>,
    event_hash: String,
    recorded_at: String,
}

struct RawFrame {
    story_id: String,
    sequence: i64,
    story_version: i64,
    event_hash: String,
    snapshot_hash: String,
    previous_frame_hash: Option<String>,
    frame_hash: String,
    story_json: String,
    recorded_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReviewerOperationSnapshot {
    pub operation: SecurityOperation,
    pub approval_version: Option<u64>,
}

impl StateStore {
    pub fn operation(&self, operation_id: OperationId) -> Result<SecurityOperation, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let operation = load_operation_tx(&transaction, operation_id)?;
        verify_story_evidence_tx(&transaction, operation.story_id)?;
        transaction.commit()?;
        Ok(operation)
    }

    /// Load one display-safe operation and its approval CAS version from the
    /// same verified story snapshot.
    pub fn reviewer_operation_snapshot(
        &self,
        story_id: StoryId,
        operation_id: OperationId,
    ) -> Result<ReviewerOperationSnapshot, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let snapshot = load_story_snapshot_tx(&transaction, story_id)?;
        verify_snapshot_anchor_tx(&transaction, &snapshot)?;
        let operation = snapshot
            .operations
            .into_iter()
            .find(|operation| operation.operation_id == operation_id)
            .ok_or_else(|| JournalError::NotFound {
                entity: "operation",
                id: operation_id.to_string(),
            })?;
        let approval_version: Option<i64> = transaction
            .query_row(
                r#"SELECT version FROM approvals
                   WHERE story_id = ?1 AND session_id = ?2 AND operation_id = ?3"#,
                params![
                    story_id.to_string(),
                    operation.session_id.to_string(),
                    operation_id.to_string()
                ],
                |row| row.get(0),
            )
            .optional()?;
        if operation.approval.is_some() != approval_version.is_some() {
            return Err(JournalError::Integrity(
                "operation approval view and approval version disagree".to_owned(),
            ));
        }
        let approval_version = approval_version
            .map(|version| rust_u64(version, "approval version"))
            .transpose()?;
        transaction.commit()?;
        Ok(ReviewerOperationSnapshot {
            operation,
            approval_version,
        })
    }

    pub fn story_snapshot(&self, story_id: StoryId) -> Result<SecurityStory, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let snapshot = load_story_snapshot_tx(&transaction, story_id)?;
        verify_snapshot_anchor_tx(&transaction, &snapshot)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub fn story_evidence(&self, story_id: StoryId) -> Result<StoryEvidenceView, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let evidence = load_story_evidence_tx(&transaction, story_id)?;
        transaction.commit()?;
        Ok(evidence)
    }
}

pub(crate) fn verify_story_evidence_tx(
    connection: &Connection,
    story_id: StoryId,
) -> Result<(), JournalError> {
    load_story_evidence_tx(connection, story_id).map(|_| ())
}

pub(crate) fn verify_event_frame_chains_tx(
    connection: &Connection,
    story_id: StoryId,
) -> Result<(), JournalError> {
    let events = load_events(connection, story_id)?;
    let replay_frames = load_frames(connection, story_id)?;
    let stored = load_story_record(connection, story_id)?;
    verify_frame_story_versions(&replay_frames, stored.version)?;
    let story = match replay_frames.last() {
        Some(frame) => frame.story.clone(),
        None => stored.story,
    };
    let evidence = StoryEvidenceView {
        story,
        events,
        replay_frames,
    };
    evidence.verify_structure().map_err(|error| {
        JournalError::Integrity(format!(
            "stored event/frame chains failed verification: {error}"
        ))
    })
}

pub(crate) fn load_story_evidence_tx(
    connection: &Connection,
    story_id: StoryId,
) -> Result<StoryEvidenceView, JournalError> {
    let stored = load_story_record(connection, story_id)?;
    let stored_version = stored.version;
    let stored_event_count = stored.story.event_count;
    let stored_final_event_hash = stored.story.final_event_hash;
    let stored_updated_at = stored.updated_at;
    let story = load_story_snapshot_tx(connection, story_id)?;
    if stored_event_count != story.event_count || stored_final_event_hash != story.final_event_hash
    {
        return Err(JournalError::Integrity(
            "stored story event head disagrees with the relational event tail".to_owned(),
        ));
    }
    let events = load_events(connection, story_id)?;
    let replay_frames = load_frames(connection, story_id)?;
    if replay_frames
        .last()
        .is_some_and(|frame| frame.recorded_at != stored_updated_at)
    {
        return Err(JournalError::Integrity(
            "stored story timestamp disagrees with the final replay frame".to_owned(),
        ));
    }
    verify_frame_story_versions(&replay_frames, stored_version)?;
    let evidence = StoryEvidenceView {
        story,
        events,
        replay_frames,
    };
    evidence.verify_structure().map_err(|error| {
        JournalError::Integrity(format!(
            "stored story evidence failed verification: {error}"
        ))
    })?;
    Ok(evidence)
}

pub(crate) fn load_story_snapshot_tx(
    connection: &Connection,
    story_id: StoryId,
) -> Result<SecurityStory, JournalError> {
    let stored = load_story_record(connection, story_id)?;
    load_session_record(connection, stored.story.authority.session_id)?;
    let mut story = stored.story;
    story.operations = load_operations(connection, story_id)?;
    story.report_claims = load_report_claims(connection, story_id)?;

    let event_tail = load_event_tail(connection, story_id)?;
    story.event_count = event_tail.as_ref().map_or(0, |(sequence, _)| *sequence);
    story.final_event_hash = event_tail.map(|(_, hash)| hash);
    story.status = derived_story_status(story.status, story.evidence_status, &story.operations);
    Ok(story)
}

pub(crate) fn load_operation_tx(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<SecurityOperation, JournalError> {
    let story_id_raw: Option<String> = connection
        .query_row(
            "SELECT story_id FROM operations WHERE operation_id = ?1",
            params![operation_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let story_id_raw = story_id_raw.ok_or_else(|| JournalError::NotFound {
        entity: "operation",
        id: operation_id.to_string(),
    })?;
    let story_id: StoryId = persisted_string(story_id_raw, "operation story id")?;
    load_operations(connection, story_id)?
        .into_iter()
        .find(|operation| operation.operation_id == operation_id)
        .ok_or_else(|| {
            JournalError::Integrity("operation vanished from its story snapshot".to_owned())
        })
}

fn load_operations(
    connection: &Connection,
    story_id: StoryId,
) -> Result<Vec<SecurityOperation>, JournalError> {
    let mut statement = connection.prepare(STORY_SNAPSHOT_SQL)?;
    let rows = statement.query_map(params![story_id.to_string()], |row| {
        Ok(RawOperation {
            operation_id: row.get(0)?,
            story_id: row.get(1)?,
            session_id: row.get(2)?,
            parent_model_call_id: row.get(3)?,
            proposed_tool_call_id: row.get(4)?,
            provider: row.get(5)?,
            action: row.get(6)?,
            argument_hash: row.get(7)?,
            arguments_json: row.get(8)?,
            policy_snapshot_hash: row.get(9)?,
            policy_decision: row.get(10)?,
            state: row.get(11)?,
            side_effect_state: row.get(12)?,
            provider_result_json: row.get(13)?,
            version: row.get(14)?,
            created_at: row.get(15)?,
            updated_at: row.get(16)?,
            claim_json: row.get(17)?,
            claim_hash: row.get(18)?,
            proposed_sequence: row.get(19)?,
        })
    })?;
    let raw = rows.collect::<Result<Vec<_>, _>>()?;
    raw.into_iter()
        .map(|raw| decode_operation(connection, story_id, raw))
        .collect()
}

fn decode_operation(
    connection: &Connection,
    expected_story_id: StoryId,
    raw: RawOperation,
) -> Result<SecurityOperation, JournalError> {
    let operation_id: OperationId = persisted_string(raw.operation_id.clone(), "operation id")?;
    let story_id: StoryId = persisted_string(raw.story_id.clone(), "operation story id")?;
    let session_id = persisted_string(raw.session_id.clone(), "operation session id")?;
    if story_id != expected_story_id {
        return Err(JournalError::Integrity(
            "operation story id disagrees with snapshot story".to_owned(),
        ));
    }
    verify_invocation_binding(connection, operation_id, story_id, session_id, &raw)?;
    if raw.proposed_sequence.is_none() {
        return Err(JournalError::Integrity(
            "operation has no operation-proposed event".to_owned(),
        ));
    }
    validate_optional_label("parent model call id", raw.parent_model_call_id.as_deref())?;
    validate_optional_label(
        "proposed tool call id",
        raw.proposed_tool_call_id.as_deref(),
    )?;
    EventCode::try_from(raw.provider.clone()).map_err(|error| {
        JournalError::Integrity(format!("stored operation provider is invalid: {error}"))
    })?;
    EventCode::try_from(raw.action.clone()).map_err(|error| {
        JournalError::Integrity(format!("stored operation action is invalid: {error}"))
    })?;
    let argument_hash = persisted_string(raw.argument_hash, "operation argument hash")?;
    let arguments: SafeArgumentView = persisted_json(&raw.arguments_json, "safe arguments")?;
    if canonical_json(&arguments)? != raw.arguments_json {
        return Err(JournalError::Integrity(
            "stored safe arguments are not canonical".to_owned(),
        ));
    }
    let policy_snapshot_hash =
        persisted_string(raw.policy_snapshot_hash, "operation policy snapshot hash")?;
    let state: OperationState = persisted_enum(raw.state, "operation state")?;
    let side_effect_state: SideEffectState =
        persisted_enum(raw.side_effect_state, "operation side-effect state")?;
    let policy_decision = raw
        .policy_decision
        .map(|value| persisted_enum::<PolicyDecision>(value, "operation policy decision"))
        .transpose()?;
    if (state == OperationState::Proposed) != policy_decision.is_none() {
        return Err(JournalError::Integrity(
            "operation policy decision and state are inconsistent".to_owned(),
        ));
    }

    let resource_claim: ResourceClaim = persisted_json(&raw.claim_json, "resource claim")?;
    if canonical_json(&resource_claim)? != raw.claim_json {
        return Err(JournalError::Integrity(
            "stored resource claim is not canonical".to_owned(),
        ));
    }
    let stored_claim_hash: Sha256Digest = persisted_string(raw.claim_hash, "resource claim hash")?;
    if resource_claim.digest() != stored_claim_hash {
        return Err(JournalError::Integrity(
            "stored resource claim hash does not match the claim".to_owned(),
        ));
    }

    let created_at = persisted_time(&raw.created_at, "operation created_at")?;
    let updated_at = persisted_time(&raw.updated_at, "operation updated_at")?;
    if format_time(created_at)? != raw.created_at
        || format_time(updated_at)? != raw.updated_at
        || updated_at < created_at
    {
        return Err(JournalError::Integrity(
            "stored operation timestamps are invalid or noncanonical".to_owned(),
        ));
    }

    let policy_checks = load_policy_checks(connection, story_id, operation_id)?;
    let approval = load_approval(connection, story_id, session_id, operation_id)?;
    let provider_result = raw
        .provider_result_json
        .map(|json| {
            let result: ProviderResultView = persisted_json(&json, "provider result")?;
            if canonical_json(&result)? != json {
                return Err(JournalError::Integrity(
                    "stored provider result is not canonical".to_owned(),
                ));
            }
            Ok(result)
        })
        .transpose()?;
    let observation_refs =
        load_operation_observations(connection, story_id, operation_id, &policy_checks)?;

    Ok(SecurityOperation {
        operation_id,
        story_id,
        session_id,
        parent_model_call_id: raw.parent_model_call_id,
        proposed_tool_call_id: raw.proposed_tool_call_id,
        provider: raw.provider,
        action: raw.action,
        resource_claim,
        argument_hash,
        arguments,
        policy_snapshot_hash,
        state,
        version: rust_u64(raw.version, "operation version")?,
        policy_checks,
        approval,
        provider_result,
        side_effect_state,
        observation_refs,
    })
}

fn verify_invocation_binding(
    connection: &Connection,
    operation_id: OperationId,
    story_id: StoryId,
    session_id: runwarden_kernel::story::SessionId,
    raw: &RawOperation,
) -> Result<(), JournalError> {
    let (invocation_key, stored_hash): (String, String) = connection.query_row(
        r#"SELECT invocation_key, invocation_binding_hash
           FROM operations WHERE operation_id = ?1"#,
        params![operation_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let invocation_key: InvocationKey =
        persisted_string(invocation_key, "operation invocation key")?;
    let stored_hash: Sha256Digest =
        persisted_string(stored_hash, "operation invocation binding hash")?;
    let frozen = load_frozen_proposal_tx(connection, operation_id)?;
    let budget_charge_json = canonical_json(&frozen.budget_charge)?;
    let expected = invocation_binding_hash(InvocationBindingMaterial {
        schema_version: "1.0.0",
        story_id: &story_id,
        session_id: &session_id,
        invocation_key: invocation_key.as_str(),
        parent_model_call_id: raw.parent_model_call_id.as_deref(),
        proposed_tool_call_id: raw.proposed_tool_call_id.as_deref(),
        provider: &raw.provider,
        action: &raw.action,
        argument_hash: &raw.argument_hash,
        safe_arguments_hash: Sha256Digest::from_bytes(raw.arguments_json.as_bytes()),
        resource_claim_hash: &raw.claim_hash,
        policy_snapshot_hash: &raw.policy_snapshot_hash,
        proposal_commitment: frozen.proposal_commitment.as_str(),
        provider_contract_hash: frozen.provider_contract_hash.as_str(),
        budget_charge_hash: Sha256Digest::from_bytes(budget_charge_json.as_bytes()),
    })?;
    if stored_hash != expected {
        return Err(JournalError::Integrity(
            "stored operation invocation binding hash does not match".to_owned(),
        ));
    }
    Ok(())
}

fn load_policy_checks(
    connection: &Connection,
    story_id: StoryId,
    operation_id: OperationId,
) -> Result<Vec<PolicyCheck>, JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT ordinal, check_json
           FROM policy_checks
           WHERE story_id = ?1 AND operation_id = ?2
           ORDER BY ordinal"#,
    )?;
    let rows = statement.query_map(
        params![story_id.to_string(), operation_id.to_string()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?;
    let mut checks = Vec::new();
    for (index, row) in rows.enumerate() {
        let (ordinal, json) = row?;
        let expected = i64::try_from(index + 1)
            .map_err(|_| JournalError::Integrity("policy-check ordinal overflow".to_owned()))?;
        if ordinal != expected {
            return Err(JournalError::Integrity(
                "policy-check ordinals are not contiguous".to_owned(),
            ));
        }
        let check: PolicyCheck = persisted_json(&json, "policy check")?;
        if canonical_json(&check)? != json {
            return Err(JournalError::Integrity(
                "stored policy check is not canonical".to_owned(),
            ));
        }
        checks.push(check);
    }
    Ok(checks)
}

fn load_approval(
    connection: &Connection,
    story_id: StoryId,
    session_id: runwarden_kernel::story::SessionId,
    operation_id: OperationId,
) -> Result<Option<ApprovalView>, JournalError> {
    type RawApproval = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
    );
    let raw: Option<RawApproval> = connection
        .query_row(
            r#"SELECT approval_id, state, binding_json, binding_hash,
                      reviewer, reason, expires_at, lease_id
               FROM approvals
               WHERE story_id = ?1 AND session_id = ?2 AND operation_id = ?3"#,
            params![
                story_id.to_string(),
                session_id.to_string(),
                operation_id.to_string()
            ],
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
                ))
            },
        )
        .optional()?;
    raw.map(
        |(
            approval_id,
            state,
            binding_json,
            binding_hash,
            reviewer,
            reason,
            expires_at,
            lease_id,
        )| {
            let approval_id: ApprovalId = persisted_string(approval_id, "approval id")?;
            let state: ApprovalState = persisted_enum(state, "approval state")?;
            let binding: serde_json::Value = persisted_json(&binding_json, "approval binding")?;
            if canonical_json(&binding)? != binding_json {
                return Err(JournalError::Integrity(
                    "stored approval binding is not canonical".to_owned(),
                ));
            }
            let stored_binding_hash: Sha256Digest =
                persisted_string(binding_hash.clone(), "approval binding hash")?;
            if Sha256Digest::from_bytes(binding_json.as_bytes()) != stored_binding_hash {
                return Err(JournalError::Integrity(
                    "stored approval binding hash does not match its binding".to_owned(),
                ));
            }
            let parsed_expiry = persisted_time(&expires_at, "approval expiry")?;
            if format_time(parsed_expiry)? != expires_at {
                return Err(JournalError::Integrity(
                    "stored approval expiry is not canonical".to_owned(),
                ));
            }
            let lease_id = lease_id
                .map(|value| persisted_string::<ExecutionLeaseId>(value, "approval lease id"))
                .transpose()?;
            Ok(ApprovalView {
                approval_id,
                state,
                binding_digest: binding_hash,
                reviewer,
                reason,
                expires_at: Some(expires_at),
                lease_id,
            })
        },
    )
    .transpose()
}

fn load_operation_observations(
    connection: &Connection,
    story_id: StoryId,
    operation_id: OperationId,
    checks: &[PolicyCheck],
) -> Result<Vec<ObservationId>, JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT obs_id FROM events
           WHERE story_id = ?1 AND operation_id = ?2
           ORDER BY sequence"#,
    )?;
    let rows = statement.query_map(
        params![story_id.to_string(), operation_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let mut observations = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        let observation: ObservationId = persisted_string(row?, "event observation id")?;
        if seen.insert(observation) {
            observations.push(observation);
        }
    }
    for observation in checks.iter().filter_map(|check| check.observation_ref) {
        if seen.insert(observation) {
            observations.push(observation);
        }
    }
    Ok(observations)
}

fn load_report_claims(
    connection: &Connection,
    story_id: StoryId,
) -> Result<Vec<StoryClaim>, JournalError> {
    let mut statement = connection.prepare(
        "SELECT claim_id, claim_json FROM report_claims WHERE story_id = ?1 ORDER BY claim_id",
    )?;
    let rows = statement.query_map(params![story_id.to_string()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.map(|row| {
        let (claim_id, json) = row?;
        let claim: StoryClaim = persisted_json(&json, "report claim")?;
        if claim.claim_id != claim_id || canonical_json(&claim)? != json {
            return Err(JournalError::Integrity(
                "stored report claim is noncanonical or has a mismatched id".to_owned(),
            ));
        }
        Ok(claim)
    })
    .collect()
}

fn load_event_tail(
    connection: &Connection,
    story_id: StoryId,
) -> Result<Option<(u64, String)>, JournalError> {
    let mut statement = connection
        .prepare("SELECT sequence, event_hash FROM events WHERE story_id = ?1 ORDER BY sequence")?;
    let rows = statement.query_map(params![story_id.to_string()], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut tail = None;
    for (index, row) in rows.enumerate() {
        let (sequence, event_hash) = row?;
        let sequence = rust_u64(sequence, "event sequence")?;
        let expected = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| JournalError::Integrity("event sequence overflow".to_owned()))?;
        if sequence != expected {
            return Err(JournalError::Integrity(
                "event sequences are not contiguous".to_owned(),
            ));
        }
        let _: Sha256Digest = persisted_string(event_hash.clone(), "event hash")?;
        tail = Some((sequence, event_hash));
    }
    Ok(tail)
}

fn load_events(
    connection: &Connection,
    story_id: StoryId,
) -> Result<Vec<StoryEvent>, JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT story_id, sequence, obs_id, event_id, session_id,
                  operation_id, event_type, provider, redacted_payload_json,
                  previous_hash, event_hash, recorded_at
           FROM events WHERE story_id = ?1 ORDER BY sequence"#,
    )?;
    let rows = statement.query_map(params![story_id.to_string()], |row| {
        Ok(RawEvent {
            story_id: row.get(0)?,
            sequence: row.get(1)?,
            obs_id: row.get(2)?,
            event_id: row.get(3)?,
            session_id: row.get(4)?,
            operation_id: row.get(5)?,
            event_type: row.get(6)?,
            provider: row.get(7)?,
            payload_json: row.get(8)?,
            previous_hash: row.get(9)?,
            event_hash: row.get(10)?,
            recorded_at: row.get(11)?,
        })
    })?;
    rows.map(|row| decode_event(row?)).collect()
}

fn decode_event(raw: RawEvent) -> Result<StoryEvent, JournalError> {
    let payload: serde_json::Value = persisted_json(&raw.payload_json, "event payload")?;
    if canonical_json(&payload)? != raw.payload_json {
        return Err(JournalError::Integrity(
            "stored event payload is not canonical".to_owned(),
        ));
    }
    let recorded_at = persisted_time(&raw.recorded_at, "event recorded_at")?;
    if format_time(recorded_at)? != raw.recorded_at {
        return Err(JournalError::Integrity(
            "stored event timestamp is not canonical".to_owned(),
        ));
    }
    let event: StoryEvent = serde_json::from_value(serde_json::json!({
        "obs_id": raw.obs_id,
        "event_id": raw.event_id,
        "story_id": raw.story_id,
        "session_id": raw.session_id,
        "sequence": rust_u64(raw.sequence, "event sequence")?,
        "operation_id": raw.operation_id,
        "event_type": raw.event_type,
        "provider": raw.provider,
        "payload": payload,
        "previous_hash": raw.previous_hash,
        "event_hash": raw.event_hash,
        "recorded_at": raw.recorded_at,
    }))
    .map_err(|error| {
        JournalError::Integrity(format!("stored event failed typed decoding: {error}"))
    })?;
    event.verify().map_err(|error| {
        JournalError::Integrity(format!("stored event failed seal verification: {error}"))
    })?;
    Ok(event)
}

fn load_frames(
    connection: &Connection,
    story_id: StoryId,
) -> Result<Vec<StoryReplayFrame>, JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT story_id, sequence, story_version, event_hash,
                  snapshot_hash, previous_frame_hash, frame_hash,
                  safe_story_json, recorded_at
           FROM story_frames WHERE story_id = ?1 ORDER BY sequence"#,
    )?;
    let rows = statement.query_map(params![story_id.to_string()], |row| {
        Ok(RawFrame {
            story_id: row.get(0)?,
            sequence: row.get(1)?,
            story_version: row.get(2)?,
            event_hash: row.get(3)?,
            snapshot_hash: row.get(4)?,
            previous_frame_hash: row.get(5)?,
            frame_hash: row.get(6)?,
            story_json: row.get(7)?,
            recorded_at: row.get(8)?,
        })
    })?;
    rows.map(|row| decode_frame(story_id, row?)).collect()
}

fn decode_frame(
    expected_story_id: StoryId,
    raw: RawFrame,
) -> Result<StoryReplayFrame, JournalError> {
    let stored_story_id: StoryId = persisted_string(raw.story_id, "frame story id")?;
    if stored_story_id != expected_story_id {
        return Err(JournalError::Integrity(
            "frame story id disagrees with evidence story".to_owned(),
        ));
    }
    let story: SecurityStory = persisted_json(&raw.story_json, "frame story")?;
    crate::stories::validate_story_contract(&story)?;
    if canonical_json(&story)? != raw.story_json {
        return Err(JournalError::Integrity(
            "stored frame story is not canonical".to_owned(),
        ));
    }
    for (label, digest) in [
        ("frame event hash", raw.event_hash.as_str()),
        ("frame snapshot hash", raw.snapshot_hash.as_str()),
        ("frame hash", raw.frame_hash.as_str()),
    ] {
        let _: Sha256Digest = persisted_string(digest.to_owned(), label)?;
    }
    if let Some(previous) = raw.previous_frame_hash.as_ref() {
        let _: Sha256Digest = persisted_string(previous.clone(), "previous frame hash")?;
    }
    let recorded_at = persisted_time(&raw.recorded_at, "frame recorded_at")?;
    if format_time(recorded_at)? != raw.recorded_at {
        return Err(JournalError::Integrity(
            "stored frame timestamp is not canonical".to_owned(),
        ));
    }
    let frame = StoryReplayFrame {
        sequence: rust_u64(raw.sequence, "frame sequence")?,
        story_version: rust_u64(raw.story_version, "frame story version")?,
        event_hash: raw.event_hash,
        snapshot_hash: raw.snapshot_hash,
        previous_frame_hash: raw.previous_frame_hash,
        frame_hash: raw.frame_hash,
        recorded_at,
        story,
    };
    frame.verify().map_err(|error| {
        JournalError::Integrity(format!("stored frame failed seal verification: {error}"))
    })?;
    Ok(frame)
}

fn verify_snapshot_anchor_tx(
    connection: &Connection,
    snapshot: &SecurityStory,
) -> Result<(), JournalError> {
    let (frame_count, minimum, maximum): (i64, Option<i64>, Option<i64>) = connection.query_row(
        r#"SELECT count(*), min(sequence), max(sequence)
           FROM story_frames WHERE story_id = ?1"#,
        params![snapshot.story_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let frame_count = rust_u64(frame_count, "frame count")?;
    if snapshot.event_count == 0 {
        if frame_count != 0 || !snapshot.operations.is_empty() || !snapshot.report_claims.is_empty()
        {
            return Err(JournalError::Integrity(
                "story has dynamic state without replay frames".to_owned(),
            ));
        }
        return Ok(());
    }
    let minimum = minimum
        .map(|value| rust_u64(value, "minimum frame sequence"))
        .transpose()?;
    let maximum = maximum
        .map(|value| rust_u64(value, "maximum frame sequence"))
        .transpose()?;
    if frame_count != snapshot.event_count
        || minimum != Some(1)
        || maximum != Some(snapshot.event_count)
    {
        return Err(JournalError::Integrity(
            "snapshot event count and replay-frame sequence bounds disagree".to_owned(),
        ));
    }
    let raw = connection.query_row(
        r#"SELECT story_id, sequence, story_version, event_hash,
                  snapshot_hash, previous_frame_hash, frame_hash,
                  safe_story_json, recorded_at
           FROM story_frames WHERE story_id = ?1
           ORDER BY sequence DESC LIMIT 1"#,
        params![snapshot.story_id.to_string()],
        |row| {
            Ok(RawFrame {
                story_id: row.get(0)?,
                sequence: row.get(1)?,
                story_version: row.get(2)?,
                event_hash: row.get(3)?,
                snapshot_hash: row.get(4)?,
                previous_frame_hash: row.get(5)?,
                frame_hash: row.get(6)?,
                story_json: row.get(7)?,
                recorded_at: row.get(8)?,
            })
        },
    )?;
    let final_frame = decode_frame(snapshot.story_id, raw)?;
    let stored_version: i64 = connection.query_row(
        "SELECT version FROM stories WHERE story_id = ?1",
        params![snapshot.story_id.to_string()],
        |row| row.get(0),
    )?;
    let stored_version = rust_u64(stored_version, "story version")?;
    if final_frame.sequence != snapshot.event_count
        || final_frame.story_version != stored_version
        || final_frame.event_hash != snapshot.final_event_hash.as_deref().unwrap_or_default()
        || final_frame.story != *snapshot
    {
        return Err(JournalError::Integrity(
            "current snapshot does not match the final replay frame".to_owned(),
        ));
    }
    Ok(())
}

fn verify_frame_story_versions(
    frames: &[StoryReplayFrame],
    stored_story_version: u64,
) -> Result<(), JournalError> {
    let mut previous: Option<u64> = None;
    for frame in frames {
        if frame.story_version == 0 {
            return Err(JournalError::Integrity(
                "replay-frame story version must be positive".to_owned(),
            ));
        }
        if let Some(previous) = previous {
            let expected = previous.checked_add(1).ok_or_else(|| {
                JournalError::Integrity("replay-frame story version overflow".to_owned())
            })?;
            if frame.story_version != expected {
                return Err(JournalError::Integrity(
                    "replay-frame story versions are not contiguous".to_owned(),
                ));
            }
        }
        previous = Some(frame.story_version);
    }
    if let Some(final_version) = previous
        && final_version != stored_story_version
    {
        return Err(JournalError::Integrity(
            "final replay-frame version does not match stored story version".to_owned(),
        ));
    }
    Ok(())
}

fn derived_story_status(
    current: StoryStatus,
    evidence: EvidenceStatus,
    operations: &[SecurityOperation],
) -> StoryStatus {
    if current == StoryStatus::EvidenceInvalid || evidence == EvidenceStatus::Invalid {
        return StoryStatus::EvidenceInvalid;
    }
    if operations
        .iter()
        .any(|operation| operation.state == OperationState::OutcomeUnknown)
    {
        StoryStatus::OutcomeUnknown
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::AwaitingApproval)
    {
        StoryStatus::AwaitingApproval
    } else if operations.iter().any(|operation| {
        matches!(
            operation.state,
            OperationState::Proposed
                | OperationState::PolicyEvaluated
                | OperationState::Approved
                | OperationState::ExecutionLeased
                | OperationState::Executing
        )
    }) {
        StoryStatus::Running
    } else if let Some(last) = operations.last() {
        match last.state {
            OperationState::Denied | OperationState::DeniedByReviewer | OperationState::Expired => {
                StoryStatus::BlockedBeforeSideEffect
            }
            OperationState::Completed => StoryStatus::CompletedWithControlledSideEffect,
            OperationState::Failed => StoryStatus::Failed,
            _ => current,
        }
    } else if operations.is_empty() {
        current
    } else {
        StoryStatus::Running
    }
}

fn validate_optional_label(label: &'static str, value: Option<&str>) -> Result<(), JournalError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        Err(JournalError::Integrity(format!(
            "stored {label} must not be empty"
        )))
    } else {
        Ok(())
    }
}
