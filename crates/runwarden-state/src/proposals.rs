use std::collections::{HashMap, HashSet};

use runwarden_kernel::operation::{SafeArgumentView, SecurityOperation};
use runwarden_kernel::story::{
    EventId, EvidenceStatus, ObservationId, OperationId, SessionId, StoryId, StoryProvenance,
    StoryStatus,
};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::events::{NewStoryEvent, append_event_and_frame_tx, append_verified_event_and_frame_tx};
use crate::operations::{
    NewOperation, append_operation_proposed_tx, existing_invocation_operation_id_tx,
    insert_operation_rows_tx, load_operation_creation_context_tx, prepare_operation,
    require_operation_id_available_tx, retry_operation_tx, validate_new_operation_context,
};
use crate::sessions::load_session_record;
use crate::snapshots::{load_operation_tx, verify_story_evidence_tx};
use crate::stories::{load_active_demo, load_story_record, require_current_story_schema};
use crate::{
    JournalError, StateStore, canonical_json, enum_text, format_time, persisted_json,
    persisted_string, rust_u64, sqlite_u64,
};

const MODEL_REQUEST_RECEIVED: &str = "model_request_received";
const INPUT_FILTER_DECISION: &str = "input_filter_decision";
const MODEL_RESPONSE_RECEIVED: &str = "model_response_received";
const MODEL_EVIDENCE_VERIFIER: &str = "model_journal_v1";
const MODEL_COMPLETION_COMMIT_FAILED: &str = "model_completion_commit_failed";

/// A trusted, display-safe binding between one proxy process and the active
/// model-egress authority. Fields are private so callers cannot mint a binding
/// from agent input or substitute a different story, session, token, or
/// upstream after startup.
#[derive(Clone, PartialEq, Eq)]
pub struct ModelJournalBinding {
    instance_id: String,
    story_id: StoryId,
    session_id: SessionId,
    instance_token_hash: String,
    upstream_provider: String,
    canonical_origin: String,
}

impl ModelJournalBinding {
    pub fn story_id(&self) -> StoryId {
        self.story_id
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
}

/// A redacted filter result. `content_bytes` is the size of the exact
/// canonical byte sequence committed by the accompanying content hash; the
/// byte sequence itself never enters the state crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterDecisionEvent {
    pub filter_state: EventCode,
    pub risk_codes: Vec<EventCode>,
    pub content_bytes: u64,
    pub recorded_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCallCompletion {
    pub model_call_id: String,
    pub response_hash: Sha256Digest,
    pub output_filter_state: EventCode,
    pub output_risk_codes: Vec<EventCode>,
    pub response_forwarded: bool,
    pub output_bytes: u64,
    pub completed_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCallIntent {
    pub model_call_id: String,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub endpoint_kind: String,
    pub model_id: String,
    pub prompt_hash: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProposedToolCall {
    pub proposal_id: String,
    pub model_call_id: String,
    pub upstream_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
    pub redacted_arguments: SafeArgumentView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalGapReason {
    MissingUpstreamId,
    NoMatchingProposal,
    AmbiguousCommitment,
    ProposalAlreadyClaimed,
}

impl CausalGapReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingUpstreamId => "missing_upstream_id",
            Self::NoMatchingProposal => "no_matching_proposal",
            Self::AmbiguousCommitment => "ambiguous_commitment",
            Self::ProposalAlreadyClaimed => "proposal_already_claimed",
        }
    }

    fn from_code(value: &str) -> Result<Self, JournalError> {
        match value {
            "missing_upstream_id" => Ok(Self::MissingUpstreamId),
            "no_matching_proposal" => Ok(Self::NoMatchingProposal),
            "ambiguous_commitment" => Ok(Self::AmbiguousCommitment),
            "proposal_already_claimed" => Ok(Self::ProposalAlreadyClaimed),
            _ => Err(JournalError::Integrity(
                "stored causal gap reason is unknown".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CausalLinkResult {
    Linked {
        proposal_id: String,
        model_call_id: String,
    },
    Unresolved {
        reason: CausalGapReason,
        candidate_count: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalLinkQuery {
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub upstream_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreateOperationWithProposalOutcome {
    pub created: bool,
    pub operation: SecurityOperation,
    pub causal_link: CausalLinkResult,
}

#[derive(Debug)]
struct StoredProposal {
    proposal_id: String,
    model_call_id: String,
    upstream_tool_call_id: Option<String>,
    story_id: String,
    session_id: String,
    provider: String,
    action: String,
    argument_hash: String,
    redacted_arguments_json: String,
    linked_operation_id: Option<String>,
}

struct ProposalResolution {
    selected: Option<StoredProposal>,
    result: CausalLinkResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredModelUsage {
    version: u64,
    calls_committed: u64,
    input_bytes_committed: u64,
    output_bytes_committed: u64,
}

struct StoredModelCall {
    story_id: StoryId,
    session_id: SessionId,
    endpoint_kind: String,
    model_id: String,
    prompt_hash: Sha256Digest,
    response_hash: Option<Sha256Digest>,
    input_filter_state: String,
    output_filter_state: Option<String>,
    output_risk_codes_json: Option<String>,
    response_forwarded: Option<bool>,
    output_bytes: Option<u64>,
    proposal_count: Option<u64>,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
}

struct StoredModelEvent {
    sequence: u64,
    provider: Option<String>,
    model_id: Option<EventCode>,
    content_hash: Sha256Digest,
    filter_state: Option<EventCode>,
    risk_codes: Vec<EventCode>,
    forwarded: Option<bool>,
    content_bytes: u64,
    proposal_count: Option<u64>,
    recorded_at: OffsetDateTime,
}

#[derive(Default)]
struct StoredModelLifecycle {
    request: Option<StoredModelEvent>,
    filter: Option<StoredModelEvent>,
    response: Option<StoredModelEvent>,
}

struct StoredProposalEvent {
    provider: Option<String>,
    proposal_id: String,
    upstream_tool_call_id: Option<String>,
    payload_provider: String,
    action: String,
    argument_hash: Sha256Digest,
    recorded_at: OffsetDateTime,
}

struct StoredLifecycleProposal {
    proposal_id: String,
    story_id: StoryId,
    session_id: SessionId,
    model_call_id: String,
    upstream_tool_call_id: Option<String>,
    provider: String,
    action: String,
    argument_hash: Sha256Digest,
    created_at: OffsetDateTime,
}

impl StateStore {
    /// Bind the proxy to the exact active model-journal authority without
    /// retaining the inherited raw instance token.
    pub fn bind_model_journal(
        &self,
        instance_token_hash: &str,
        upstream_provider: &str,
        canonical_origin: &str,
        now: OffsetDateTime,
    ) -> Result<ModelJournalBinding, JournalError> {
        validate_event_code("model upstream provider", upstream_provider)?;
        validate_canonical_origin(canonical_origin)?;
        let context = self.active_context_snapshot(instance_token_hash, now)?;
        if context.story.provenance != StoryProvenance::Native
            || context.story.evidence_status != EvidenceStatus::Pending
            || matches!(
                context.story.status,
                StoryStatus::EvidenceInvalid | StoryStatus::OutcomeUnknown
            )
        {
            return Err(JournalError::InvalidTransition {
                entity: "story",
                from: enum_text(&context.story.status)?,
                to: "bind_model_journal".to_owned(),
            });
        }
        require_model_egress(
            &context.session.authority,
            upstream_provider,
            canonical_origin,
        )?;
        Ok(ModelJournalBinding {
            instance_id: context.active.instance_id,
            story_id: context.active.story_id,
            session_id: context.active.session_id,
            instance_token_hash: context.active.instance_token_hash,
            upstream_provider: upstream_provider.to_owned(),
            canonical_origin: canonical_origin.to_owned(),
        })
    }

    /// Atomically commit the pre-forward model intent, input-filter evidence,
    /// and model call/input-byte budget charge.
    pub fn begin_model_call(
        &self,
        binding: &ModelJournalBinding,
        intent: ModelCallIntent,
        filter: FilterDecisionEvent,
    ) -> Result<(), JournalError> {
        validate_model_intent(&intent)?;
        validate_filter_decision(&filter)?;
        if intent.story_id != binding.story_id || intent.session_id != binding.session_id {
            return Err(JournalError::Integrity(
                "model call intent does not match its trusted journal binding".to_owned(),
            ));
        }

        let now_text = format_time(filter.recorded_at)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session =
            revalidate_active_model_binding_tx(&transaction, binding, filter.recorded_at)?;
        let usage = load_model_usage_tx(&transaction, binding.story_id, binding.session_id)?;
        verify_model_usage_aggregate_tx(&transaction, binding.story_id, binding.session_id, usage)?;

        let next_usage =
            reserve_model_input(&session.record.authority, usage, filter.content_bytes)?;
        insert_model_call_tx(&transaction, &intent, &filter.filter_state, &now_text)?;
        cas_model_usage_tx(
            &transaction,
            binding.story_id,
            binding.session_id,
            usage,
            next_usage,
        )?;

        append_event_and_frame_tx(
            &transaction,
            NewStoryEvent {
                obs_id: ObservationId::new(),
                event_id: EventId::new(),
                story_id: binding.story_id,
                session_id: binding.session_id,
                operation_id: None,
                provider: Some(event_code(
                    "model upstream provider",
                    &binding.upstream_provider,
                )?),
                payload: StoryEventPayload::ModelCall {
                    model_call_id: event_code("model call id", &intent.model_call_id)?,
                    phase: event_code("model call phase", MODEL_REQUEST_RECEIVED)?,
                    model_id: Some(event_code("model id", &intent.model_id)?),
                    content_hash: intent.prompt_hash.clone(),
                    filter_state: None,
                    risk_codes: Vec::new(),
                    forwarded: None,
                    content_bytes: filter.content_bytes,
                    proposal_count: None,
                },
                recorded_at: filter.recorded_at,
            },
        )?;
        append_event_and_frame_tx(
            &transaction,
            NewStoryEvent {
                obs_id: ObservationId::new(),
                event_id: EventId::new(),
                story_id: binding.story_id,
                session_id: binding.session_id,
                operation_id: None,
                provider: Some(event_code(
                    "model upstream provider",
                    &binding.upstream_provider,
                )?),
                payload: StoryEventPayload::ModelCall {
                    model_call_id: event_code("model call id", &intent.model_call_id)?,
                    phase: event_code("model call phase", INPUT_FILTER_DECISION)?,
                    model_id: Some(event_code("model id", &intent.model_id)?),
                    content_hash: intent.prompt_hash,
                    filter_state: Some(filter.filter_state.clone()),
                    risk_codes: filter.risk_codes,
                    // A successful safe/flagged intent authorizes a later
                    // forward; it does not claim that the network call already
                    // happened. A blocked decision can truthfully prove no
                    // forward was authorized.
                    forwarded: (filter.filter_state.as_str() == "blocked").then_some(false),
                    content_bytes: filter.content_bytes,
                    proposal_count: None,
                },
                recorded_at: filter.recorded_at,
            },
        )?;
        verify_model_usage_aggregate_tx(
            &transaction,
            binding.story_id,
            binding.session_id,
            next_usage,
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    /// Atomically seal post-upstream response evidence. This is intentionally
    /// not a new forwarding authorization check: after upstream I/O has begun,
    /// a deactivated or expired context must not suppress truthful evidence.
    pub fn complete_model_call(
        &self,
        binding: &ModelJournalBinding,
        completion: ModelCallCompletion,
        proposals: Vec<ProposedToolCall>,
    ) -> Result<(), JournalError> {
        validate_model_completion(binding, &completion, &proposals)?;
        let now = completion.completed_at;
        let completed_at = format_time(now)?;
        let output_risk_codes_json = canonical_json(&completion.output_risk_codes)?;
        let proposal_count = u64::try_from(proposals.len()).map_err(|_| {
            JournalError::Integrity("model proposal count overflowed u64".to_owned())
        })?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = validate_sealed_model_context_tx(&transaction, binding, now)?;
        let model = load_model_call_tx(&transaction, &completion.model_call_id)?;
        let usage = load_model_usage_tx(&transaction, binding.story_id, binding.session_id)?;
        verify_model_usage_aggregate_tx(&transaction, binding.story_id, binding.session_id, usage)?;
        if model.completed_at.is_some() {
            validate_completed_model_retry_tx(
                &transaction,
                binding,
                &completion,
                &proposals,
                &model,
            )?;
            transaction.commit()?;
            return self.harden_files();
        }
        validate_model_row_for_completion(binding, &completion, &model)?;
        let preexisting_proposals: i64 = transaction.query_row(
            r#"SELECT count(*) FROM tool_proposals
               WHERE story_id = ?1 AND session_id = ?2 AND model_call_id = ?3"#,
            params![
                binding.story_id.to_string(),
                binding.session_id.to_string(),
                completion.model_call_id
            ],
            |row| row.get(0),
        )?;
        if preexisting_proposals != 0 {
            return Err(JournalError::InvalidTransition {
                entity: "model_call",
                from: "preexisting_tool_proposals".to_owned(),
                to: "complete_model_call".to_owned(),
            });
        }
        if now < model.created_at {
            return Err(JournalError::InvalidTransition {
                entity: "model_call_time",
                from: format_time(model.created_at)?,
                to: completed_at,
            });
        }
        let next_usage =
            commit_model_output(&session.record.authority, usage, completion.output_bytes)?;
        cas_model_usage_tx(
            &transaction,
            binding.story_id,
            binding.session_id,
            usage,
            next_usage,
        )?;

        let affected = transaction.execute(
            r#"UPDATE model_calls
               SET response_hash = ?1, output_filter_state = ?2,
                   output_risk_codes_json = ?3, response_forwarded = ?4,
                   output_bytes = ?5, proposal_count = ?6, completed_at = ?7
               WHERE model_call_id = ?8 AND story_id = ?9 AND session_id = ?10
                 AND response_hash IS NULL AND output_filter_state IS NULL
                 AND output_risk_codes_json IS NULL AND response_forwarded IS NULL
                 AND output_bytes IS NULL AND proposal_count IS NULL
                 AND completed_at IS NULL"#,
            params![
                completion.response_hash.as_str(),
                completion.output_filter_state.as_str(),
                output_risk_codes_json,
                i64::from(completion.response_forwarded),
                sqlite_u64(completion.output_bytes, "model output bytes")?,
                sqlite_u64(proposal_count, "model proposal count")?,
                format_time(now)?,
                completion.model_call_id,
                binding.story_id.to_string(),
                binding.session_id.to_string(),
            ],
        )?;
        if affected != 1 {
            return Err(JournalError::Conflict {
                entity: "model_call",
                id: completion.model_call_id,
                expected: 0,
                actual: 1,
            });
        }

        for proposal in &proposals {
            insert_tool_proposal_tx(
                &transaction,
                binding.story_id,
                binding.session_id,
                proposal,
                &format_time(now)?,
            )?;
        }

        append_event_and_frame_tx(
            &transaction,
            NewStoryEvent {
                obs_id: ObservationId::new(),
                event_id: EventId::new(),
                story_id: binding.story_id,
                session_id: binding.session_id,
                operation_id: None,
                provider: Some(event_code(
                    "model upstream provider",
                    &binding.upstream_provider,
                )?),
                payload: StoryEventPayload::ModelCall {
                    model_call_id: event_code("model call id", &completion.model_call_id)?,
                    phase: event_code("model call phase", MODEL_RESPONSE_RECEIVED)?,
                    model_id: Some(event_code("model id", &model.model_id)?),
                    content_hash: completion.response_hash,
                    filter_state: Some(completion.output_filter_state),
                    risk_codes: completion.output_risk_codes,
                    forwarded: Some(completion.response_forwarded),
                    content_bytes: completion.output_bytes,
                    proposal_count: Some(proposal_count),
                },
                recorded_at: now,
            },
        )?;
        for proposal in proposals {
            append_event_and_frame_tx(
                &transaction,
                NewStoryEvent {
                    obs_id: ObservationId::new(),
                    event_id: EventId::new(),
                    story_id: binding.story_id,
                    session_id: binding.session_id,
                    operation_id: None,
                    provider: Some(event_code("proposal provider", &proposal.provider)?),
                    payload: StoryEventPayload::ToolProposal {
                        proposal_id: event_code("proposal id", &proposal.proposal_id)?,
                        upstream_tool_call_id: proposal
                            .upstream_tool_call_id
                            .as_deref()
                            .map(|id| event_code("upstream tool call id", id))
                            .transpose()?,
                        provider: event_code("proposal provider", &proposal.provider)?,
                        action: event_code("proposal action", &proposal.action)?,
                        argument_hash: proposal.argument_hash,
                    },
                    recorded_at: now,
                },
            )?;
        }
        verify_model_usage_aggregate_tx(
            &transaction,
            binding.story_id,
            binding.session_id,
            next_usage,
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    /// Best-effort post-upstream evidence invalidation. Only a fixed safe code
    /// is accepted; database errors or response text must never be persisted as
    /// the reason.
    pub fn mark_model_evidence_invalid(
        &self,
        binding: &ModelJournalBinding,
        stable_reason: &str,
        now: OffsetDateTime,
    ) -> Result<(), JournalError> {
        if stable_reason != MODEL_COMPLETION_COMMIT_FAILED {
            return Err(JournalError::Integrity(
                "model evidence invalidation reason is not an allowed stable code".to_owned(),
            ));
        }
        let reason = event_code("model evidence invalidation reason", stable_reason)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let evidence = crate::snapshots::load_story_evidence_tx(&transaction, binding.story_id)?;
        let stored = load_story_record(&transaction, binding.story_id)?;
        require_current_story_schema(&stored.story)?;
        let session = load_session_record(&transaction, binding.session_id)?;
        if evidence.story.story_id != binding.story_id
            || evidence.story.authority.session_id != binding.session_id
            || session.record.story_id != binding.story_id
            || session.record.authority != evidence.story.authority
            || evidence.story.provenance != StoryProvenance::Native
            || evidence.story.evidence_status != EvidenceStatus::Pending
        {
            return Err(JournalError::InvalidTransition {
                entity: "story_evidence",
                from: enum_text(&evidence.story.evidence_status)?,
                to: "invalid".to_owned(),
            });
        }
        if now < stored.updated_at {
            return Err(JournalError::InvalidTransition {
                entity: "model_evidence_time",
                from: format_time(stored.updated_at)?,
                to: format_time(now)?,
            });
        }
        let candidate_chain_head: Sha256Digest = evidence
            .story
            .final_event_hash
            .as_ref()
            .ok_or_else(|| {
                JournalError::Integrity(
                    "model evidence invalidation requires a committed request event".to_owned(),
                )
            })
            .and_then(|hash| persisted_string(hash.clone(), "candidate chain head"))?;
        let claim_count = u64::try_from(evidence.story.report_claims.len())
            .map_err(|_| JournalError::Integrity("report claim count overflowed u64".to_owned()))?;

        let mut invalid_story = evidence.story;
        invalid_story.status = StoryStatus::EvidenceInvalid;
        invalid_story.evidence_status = EvidenceStatus::Invalid;
        invalid_story.final_outcome_summary =
            "Model completion evidence could not be committed".to_owned();
        let affected = transaction.execute(
            r#"UPDATE stories
               SET status = ?1, evidence_status = ?2, safe_story_json = ?3
               WHERE story_id = ?4 AND version = ?5
                 AND evidence_status = 'pending'"#,
            params![
                enum_text(&invalid_story.status)?,
                enum_text(&invalid_story.evidence_status)?,
                canonical_json(&invalid_story)?,
                binding.story_id.to_string(),
                sqlite_u64(stored.version, "story version")?,
            ],
        )?;
        if affected != 1 {
            let actual = load_story_record(&transaction, binding.story_id)?;
            return Err(JournalError::Conflict {
                entity: "story",
                id: binding.story_id.to_string(),
                expected: stored.version,
                actual: actual.version,
            });
        }
        append_verified_event_and_frame_tx(
            &transaction,
            NewStoryEvent {
                obs_id: ObservationId::new(),
                event_id: EventId::new(),
                story_id: binding.story_id,
                session_id: binding.session_id,
                operation_id: None,
                provider: Some(event_code(
                    "model upstream provider",
                    &binding.upstream_provider,
                )?),
                payload: StoryEventPayload::EvidenceVerification {
                    status: EvidenceStatus::Invalid,
                    error_codes: vec![reason],
                    claim_count,
                    candidate_chain_head,
                    candidate_story_version: stored.version,
                    verifier_version: event_code(
                        "model evidence verifier",
                        MODEL_EVIDENCE_VERIFIER,
                    )?,
                    event_chain_verified: true,
                    report_claims_verified: false,
                },
                recorded_at: now,
            },
        )?;
        let invalid = crate::snapshots::load_story_evidence_tx(&transaction, binding.story_id)?;
        if invalid.story.status != StoryStatus::EvidenceInvalid
            || invalid.story.evidence_status != EvidenceStatus::Invalid
        {
            return Err(JournalError::Integrity(
                "model evidence invalidation did not seal the invalid story".to_owned(),
            ));
        }
        transaction.commit()?;
        self.harden_files()
    }

    /// Persist a redacted model-call commitment.
    ///
    /// This low-level Plan 5 state primitive deliberately does not reserve
    /// model budget or claim that forwarding occurred. The proxy's journal
    /// transaction owns those decisions and the associated story events.
    pub fn record_model_call(
        &self,
        intent: ModelCallIntent,
        input_filter_state: EventCode,
        now: OffsetDateTime,
    ) -> Result<(), JournalError> {
        validate_event_code("model call id", &intent.model_call_id)?;
        validate_event_code("model endpoint kind", &intent.endpoint_kind)?;
        validate_event_code("model id", &intent.model_id)?;
        validate_filter_state(&input_filter_state)?;
        let now_text = format_time(now)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_model_context_tx(&transaction, intent.story_id, intent.session_id, now)?;
        if row_exists(
            &transaction,
            "SELECT 1 FROM model_calls WHERE model_call_id = ?1",
            &intent.model_call_id,
        )? {
            return Err(JournalError::Conflict {
                entity: "model_call",
                id: intent.model_call_id,
                expected: 0,
                actual: 1,
            });
        }
        transaction.execute(
            r#"INSERT INTO model_calls (
                model_call_id, story_id, session_id, endpoint_kind, model_id,
                prompt_hash, input_filter_state, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                intent.model_call_id,
                intent.story_id.to_string(),
                intent.session_id.to_string(),
                intent.endpoint_kind,
                intent.model_id,
                intent.prompt_hash.as_str(),
                input_filter_state.as_str(),
                now_text,
            ],
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    /// Persist one display-safe tool proposal under its committed model call.
    pub fn record_tool_proposal(
        &self,
        proposal: ProposedToolCall,
        now: OffsetDateTime,
    ) -> Result<(), JournalError> {
        validate_event_code("proposal id", &proposal.proposal_id)?;
        validate_event_code("model call id", &proposal.model_call_id)?;
        validate_optional_event_code(
            "upstream tool call id",
            proposal.upstream_tool_call_id.as_deref(),
        )?;
        validate_event_code("proposal provider", &proposal.provider)?;
        validate_event_code("proposal action", &proposal.action)?;
        let redacted_arguments_json = canonical_json(&proposal.redacted_arguments)?;
        let now_text = format_time(now)?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let model: Option<(String, String, String, String, Option<String>)> = transaction
            .query_row(
                r#"SELECT story_id, session_id, input_filter_state, created_at, completed_at
                   FROM model_calls WHERE model_call_id = ?1"#,
                params![proposal.model_call_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (story_id, session_id, input_filter_state, created_at, completed_at) = model
            .ok_or_else(|| JournalError::NotFound {
                entity: "model_call",
                id: proposal.model_call_id.clone(),
            })?;
        let story_id: StoryId = persisted_string(story_id, "proposal story id")?;
        let session_id: SessionId = persisted_string(session_id, "proposal session id")?;
        validate_model_context_tx(&transaction, story_id, session_id, now)?;
        let has_domain_events: bool = transaction
            .query_row(
                r#"SELECT 1 FROM events
                   WHERE story_id = ?1 AND session_id = ?2
                     AND event_type = 'model_call'
                     AND json_extract(redacted_payload_json, '$.model_call_id') = ?3
                   LIMIT 1"#,
                params![
                    story_id.to_string(),
                    session_id.to_string(),
                    proposal.model_call_id
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if has_domain_events {
            return Err(JournalError::InvalidTransition {
                entity: "model_call",
                from: "domain_owned".to_owned(),
                to: "record_tool_proposal".to_owned(),
            });
        }
        if input_filter_state == "blocked"
            || input_filter_state == "pending"
            || completed_at.is_some()
        {
            return Err(JournalError::InvalidTransition {
                entity: "model_call",
                from: if completed_at.is_some() {
                    "completed".to_owned()
                } else {
                    input_filter_state
                },
                to: "record_tool_proposal".to_owned(),
            });
        }
        let created_at = crate::persisted_time(&created_at, "model call created_at")?;
        if now < created_at {
            return Err(JournalError::InvalidTransition {
                entity: "proposal_time",
                from: format_time(created_at)?,
                to: now_text,
            });
        }
        if row_exists(
            &transaction,
            "SELECT 1 FROM tool_proposals WHERE proposal_id = ?1",
            &proposal.proposal_id,
        )? {
            return Err(JournalError::Conflict {
                entity: "tool_proposal",
                id: proposal.proposal_id,
                expected: 0,
                actual: 1,
            });
        }
        transaction.execute(
            r#"INSERT INTO tool_proposals (
                proposal_id, story_id, session_id, model_call_id,
                upstream_tool_call_id, provider, action, argument_hash,
                redacted_arguments_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                proposal.proposal_id,
                story_id.to_string(),
                session_id.to_string(),
                proposal.model_call_id,
                proposal.upstream_tool_call_id,
                proposal.provider,
                proposal.action,
                proposal.argument_hash.as_str(),
                redacted_arguments_json,
                now_text,
            ],
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    pub fn create_operation_with_proposal(
        &self,
        mut input: NewOperation,
        query: ProposalLinkQuery,
    ) -> Result<CreateOperationWithProposalOutcome, JournalError> {
        validate_link_request(&input, &query)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let context = load_operation_creation_context_tx(&transaction, &input)?;

        if let Some(existing_id) = existing_invocation_operation_id_tx(&transaction, &input)? {
            let (causal_link, parent_model_call_id, proposed_tool_call_id) =
                load_existing_causal_result_tx(&transaction, existing_id, &query)?;
            input.parent_model_call_id = parent_model_call_id;
            input.proposed_tool_call_id = proposed_tool_call_id;
            let prepared = prepare_operation(&input)?;
            let operation =
                retry_operation_tx(&transaction, &input, &prepared)?.ok_or_else(|| {
                    JournalError::Integrity(
                        "invocation disappeared while validating causal retry".to_owned(),
                    )
                })?;
            transaction.commit()?;
            return Ok(CreateOperationWithProposalOutcome {
                created: false,
                operation,
                causal_link,
            });
        }

        let resolution = resolve_proposal_tx(&transaction, &query)?;
        if let Some(selected) = resolution.selected.as_ref() {
            input.parent_model_call_id = Some(selected.model_call_id.clone());
            input.proposed_tool_call_id = selected.upstream_tool_call_id.clone();
        }
        let prepared = prepare_operation(&input)?;
        validate_new_operation_context(&input, &prepared, &context)?;
        require_operation_id_available_tx(&transaction, input.operation_id)?;
        insert_operation_rows_tx(&transaction, &input, &prepared)?;

        if let Some(selected) = resolution.selected.as_ref() {
            let affected = transaction.execute(
                r#"UPDATE tool_proposals
                   SET linked_operation_id = ?1
                   WHERE proposal_id = ?2 AND story_id = ?3 AND session_id = ?4
                     AND linked_operation_id IS NULL"#,
                params![
                    input.operation_id.to_string(),
                    selected.proposal_id,
                    input.story_id.to_string(),
                    input.session_id.to_string(),
                ],
            )?;
            if affected != 1 {
                return Err(JournalError::Conflict {
                    entity: "tool_proposal",
                    id: selected.proposal_id.clone(),
                    expected: 0,
                    actual: 1,
                });
            }
        }

        append_operation_proposed_tx(&transaction, &input, &prepared)?;
        append_causal_link_tx(&transaction, &input, &resolution.result)?;
        let operation = load_operation_tx(&transaction, input.operation_id)?;
        verify_operation_causal_link_tx(&transaction, &operation)?;
        transaction.commit()?;
        self.harden_files()?;
        Ok(CreateOperationWithProposalOutcome {
            created: true,
            operation,
            causal_link: resolution.result,
        })
    }
}

fn validate_model_intent(intent: &ModelCallIntent) -> Result<(), JournalError> {
    validate_event_code("model call id", &intent.model_call_id)?;
    validate_event_code("model endpoint kind", &intent.endpoint_kind)?;
    validate_event_code("model id", &intent.model_id)?;
    if !matches!(
        intent.endpoint_kind.as_str(),
        "chat_completions" | "responses"
    ) {
        return Err(JournalError::Integrity(
            "model endpoint kind is not supported".to_owned(),
        ));
    }
    Ok(())
}

fn validate_filter_decision(filter: &FilterDecisionEvent) -> Result<(), JournalError> {
    validate_filter_state(&filter.filter_state)?;
    sqlite_u64(filter.content_bytes, "model content bytes")?;
    format_time(filter.recorded_at)?;
    if filter
        .risk_codes
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(JournalError::Integrity(
            "model filter risk codes must be sorted and unique".to_owned(),
        ));
    }
    Ok(())
}

fn validate_model_completion(
    binding: &ModelJournalBinding,
    completion: &ModelCallCompletion,
    proposals: &[ProposedToolCall],
) -> Result<(), JournalError> {
    validate_event_code("model call id", &completion.model_call_id)?;
    validate_filter_state(&completion.output_filter_state)?;
    sqlite_u64(completion.output_bytes, "model output bytes")?;
    format_time(completion.completed_at)?;
    if completion.output_filter_state.as_str() == "blocked" && completion.response_forwarded {
        return Err(JournalError::Integrity(
            "a blocked model response cannot be marked forwarded".to_owned(),
        ));
    }
    if completion
        .output_risk_codes
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(JournalError::Integrity(
            "model output risk codes must be sorted and unique".to_owned(),
        ));
    }
    let mut proposal_ids = HashSet::new();
    let mut upstream_ids = HashSet::new();
    for proposal in proposals {
        validate_event_code("proposal id", &proposal.proposal_id)?;
        validate_event_code("proposal model call id", &proposal.model_call_id)?;
        validate_event_code("proposal provider", &proposal.provider)?;
        validate_event_code("proposal action", &proposal.action)?;
        validate_optional_event_code(
            "upstream tool call id",
            proposal.upstream_tool_call_id.as_deref(),
        )?;
        if proposal.model_call_id != completion.model_call_id {
            return Err(JournalError::Integrity(
                "tool proposal does not match the completed model call".to_owned(),
            ));
        }
        if !proposal_ids.insert(proposal.proposal_id.as_str()) {
            return Err(JournalError::Integrity(
                "tool proposal ids must be unique within a completion".to_owned(),
            ));
        }
        if let Some(upstream_id) = proposal.upstream_tool_call_id.as_deref()
            && !upstream_ids.insert(upstream_id)
        {
            return Err(JournalError::Integrity(
                "upstream tool call ids must be unique within a completion".to_owned(),
            ));
        }
        canonical_json(&proposal.redacted_arguments)?;
    }
    // Touch the private fields here so this validator also proves that the
    // completion path was entered through a real startup binding.
    validate_event_code("bound upstream provider", &binding.upstream_provider)?;
    validate_canonical_origin(&binding.canonical_origin)
}

fn validate_canonical_origin(origin: &str) -> Result<(), JournalError> {
    let parsed = Url::parse(origin)
        .map_err(|_| JournalError::Integrity("model upstream origin is invalid".to_owned()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(JournalError::Integrity(
            "model upstream origin is not a canonical HTTP(S) origin".to_owned(),
        ));
    }
    Ok(())
}

fn require_model_egress(
    authority: &runwarden_kernel::session::AuthoritySnapshot,
    provider: &str,
    origin: &str,
) -> Result<(), JournalError> {
    if authority.networks.iter().any(|network| {
        network.provider == provider
            && network
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
    }) {
        Ok(())
    } else {
        Err(JournalError::InvalidTransition {
            entity: "model_egress",
            from: "not_authorized".to_owned(),
            to: "model_forward".to_owned(),
        })
    }
}

fn revalidate_active_model_binding_tx(
    connection: &Connection,
    binding: &ModelJournalBinding,
    now: OffsetDateTime,
) -> Result<crate::sessions::StoredSession, JournalError> {
    verify_story_evidence_tx(connection, binding.story_id)?;
    let active = load_active_demo(connection)?.ok_or_else(|| JournalError::InvalidTransition {
        entity: "active_instance",
        from: "absent".to_owned(),
        to: "model_forward".to_owned(),
    })?;
    if active.instance_id != binding.instance_id
        || active.story_id != binding.story_id
        || active.session_id != binding.session_id
        || active.instance_token_hash != binding.instance_token_hash
    {
        return Err(JournalError::Integrity(
            "active instance no longer matches the model journal binding".to_owned(),
        ));
    }
    if active.heartbeat_at > now {
        return Err(JournalError::Integrity(
            "active model instance heartbeat is in the future".to_owned(),
        ));
    }
    validate_model_context_tx(connection, binding.story_id, binding.session_id, now)?;
    let session = load_session_record(connection, binding.session_id)?;
    require_model_egress(
        &session.record.authority,
        &binding.upstream_provider,
        &binding.canonical_origin,
    )?;
    Ok(session)
}

fn validate_sealed_model_context_tx(
    connection: &Connection,
    binding: &ModelJournalBinding,
    now: OffsetDateTime,
) -> Result<crate::sessions::StoredSession, JournalError> {
    verify_story_evidence_tx(connection, binding.story_id)?;
    let story = load_story_record(connection, binding.story_id)?;
    require_current_story_schema(&story.story)?;
    let session = load_session_record(connection, binding.session_id)?;
    if story.story.story_id != binding.story_id
        || story.story.authority.session_id != binding.session_id
        || session.record.story_id != binding.story_id
        || session.record.authority != story.story.authority
    {
        return Err(JournalError::Integrity(
            "completed model call does not match its sealed story and session".to_owned(),
        ));
    }
    if story.story.provenance != StoryProvenance::Native
        || story.story.evidence_status != EvidenceStatus::Pending
        || matches!(
            story.story.status,
            StoryStatus::EvidenceInvalid | StoryStatus::OutcomeUnknown
        )
    {
        return Err(JournalError::InvalidTransition {
            entity: "story",
            from: enum_text(&story.story.status)?,
            to: "complete_model_call".to_owned(),
        });
    }
    if now < story.updated_at {
        return Err(JournalError::InvalidTransition {
            entity: "model_event_time",
            from: format_time(story.updated_at)?,
            to: format_time(now)?,
        });
    }
    require_model_egress(
        &session.record.authority,
        &binding.upstream_provider,
        &binding.canonical_origin,
    )?;
    Ok(session)
}

fn load_model_usage_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
) -> Result<StoredModelUsage, JournalError> {
    let raw: Option<(String, i64, i64, i64, i64)> = connection
        .query_row(
            r#"SELECT story_id, version, calls_committed,
                      input_bytes_committed, output_bytes_committed
               FROM model_usage WHERE session_id = ?1"#,
            params![session_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let (stored_story_id, version, calls, input_bytes, output_bytes) = raw.ok_or_else(|| {
        JournalError::Integrity(format!("session {session_id} has no model usage row"))
    })?;
    let stored_story_id: StoryId = persisted_string(stored_story_id, "model usage story id")?;
    if stored_story_id != story_id {
        return Err(JournalError::Integrity(
            "model usage story does not match the bound session".to_owned(),
        ));
    }
    Ok(StoredModelUsage {
        version: rust_u64(version, "model usage version")?,
        calls_committed: rust_u64(calls, "committed model calls")?,
        input_bytes_committed: rust_u64(input_bytes, "committed model input bytes")?,
        output_bytes_committed: rust_u64(output_bytes, "committed model output bytes")?,
    })
}

fn reserve_model_input(
    authority: &runwarden_kernel::session::AuthoritySnapshot,
    usage: StoredModelUsage,
    input_bytes: u64,
) -> Result<StoredModelUsage, JournalError> {
    let calls = usage
        .calls_committed
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("model call budget overflowed".to_owned()))?;
    let input = usage
        .input_bytes_committed
        .checked_add(input_bytes)
        .ok_or_else(|| JournalError::Integrity("model input budget overflowed".to_owned()))?;
    if calls > authority.budgets.max_model_calls {
        return Err(model_budget_exceeded("model call"));
    }
    if input > authority.budgets.max_model_input_bytes {
        return Err(model_budget_exceeded("model input byte"));
    }
    Ok(StoredModelUsage {
        version: usage
            .version
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("model usage version overflowed".to_owned()))?,
        calls_committed: calls,
        input_bytes_committed: input,
        output_bytes_committed: usage.output_bytes_committed,
    })
}

fn commit_model_output(
    authority: &runwarden_kernel::session::AuthoritySnapshot,
    usage: StoredModelUsage,
    output_bytes: u64,
) -> Result<StoredModelUsage, JournalError> {
    let output = usage
        .output_bytes_committed
        .checked_add(output_bytes)
        .ok_or_else(|| JournalError::Integrity("model output budget overflowed".to_owned()))?;
    if output > authority.budgets.max_model_output_bytes {
        return Err(model_budget_exceeded("model output byte"));
    }
    Ok(StoredModelUsage {
        version: usage
            .version
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("model usage version overflowed".to_owned()))?,
        output_bytes_committed: output,
        ..usage
    })
}

fn model_budget_exceeded(label: &str) -> JournalError {
    JournalError::InvalidTransition {
        entity: "model_budget",
        from: format!("{label}_exhausted"),
        to: "model_forward".to_owned(),
    }
}

fn cas_model_usage_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
    expected: StoredModelUsage,
    next: StoredModelUsage,
) -> Result<(), JournalError> {
    let affected = connection.execute(
        r#"UPDATE model_usage
           SET version = ?1, calls_committed = ?2,
               input_bytes_committed = ?3, output_bytes_committed = ?4
           WHERE story_id = ?5 AND session_id = ?6 AND version = ?7
             AND calls_committed = ?8 AND input_bytes_committed = ?9
             AND output_bytes_committed = ?10"#,
        params![
            sqlite_u64(next.version, "model usage version")?,
            sqlite_u64(next.calls_committed, "committed model calls")?,
            sqlite_u64(next.input_bytes_committed, "committed model input bytes")?,
            sqlite_u64(next.output_bytes_committed, "committed model output bytes")?,
            story_id.to_string(),
            session_id.to_string(),
            sqlite_u64(expected.version, "model usage version")?,
            sqlite_u64(expected.calls_committed, "committed model calls")?,
            sqlite_u64(
                expected.input_bytes_committed,
                "committed model input bytes"
            )?,
            sqlite_u64(
                expected.output_bytes_committed,
                "committed model output bytes"
            )?,
        ],
    )?;
    if affected == 1 {
        return Ok(());
    }
    let actual = load_model_usage_tx(connection, story_id, session_id)?;
    Err(JournalError::Conflict {
        entity: "model_usage",
        id: session_id.to_string(),
        expected: expected.version,
        actual: actual.version,
    })
}

fn insert_model_call_tx(
    connection: &Connection,
    intent: &ModelCallIntent,
    input_filter_state: &EventCode,
    now: &str,
) -> Result<(), JournalError> {
    if row_exists(
        connection,
        "SELECT 1 FROM model_calls WHERE model_call_id = ?1",
        &intent.model_call_id,
    )? {
        return Err(JournalError::Conflict {
            entity: "model_call",
            id: intent.model_call_id.clone(),
            expected: 0,
            actual: 1,
        });
    }
    connection.execute(
        r#"INSERT INTO model_calls (
            model_call_id, story_id, session_id, endpoint_kind, model_id,
            prompt_hash, input_filter_state, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
        params![
            intent.model_call_id,
            intent.story_id.to_string(),
            intent.session_id.to_string(),
            intent.endpoint_kind,
            intent.model_id,
            intent.prompt_hash.as_str(),
            input_filter_state.as_str(),
            now,
        ],
    )?;
    Ok(())
}

fn load_model_call_tx(
    connection: &Connection,
    model_call_id: &str,
) -> Result<StoredModelCall, JournalError> {
    type Raw = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        String,
        Option<String>,
    );
    let raw: Option<Raw> = connection
        .query_row(
            r#"SELECT story_id, session_id, endpoint_kind, model_id, prompt_hash,
                      response_hash, input_filter_state, output_filter_state,
                      output_risk_codes_json, response_forwarded, output_bytes,
                      proposal_count, created_at, completed_at
               FROM model_calls WHERE model_call_id = ?1"#,
            params![model_call_id],
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .optional()?;
    let raw = raw.ok_or_else(|| JournalError::NotFound {
        entity: "model_call",
        id: model_call_id.to_owned(),
    })?;
    let response_forwarded = raw
        .9
        .map(|value| match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(JournalError::Integrity(
                "stored model response forwarded flag is invalid".to_owned(),
            )),
        })
        .transpose()?;
    validate_event_code("stored model endpoint kind", &raw.2)?;
    validate_event_code("stored model id", &raw.3)?;
    if !matches!(raw.2.as_str(), "chat_completions" | "responses") {
        return Err(JournalError::Integrity(
            "stored model endpoint kind is unsupported".to_owned(),
        ));
    }
    let created_at = crate::persisted_time(&raw.12, "model call created_at")?;
    if format_time(created_at)? != raw.12 {
        return Err(JournalError::Integrity(
            "stored model call created_at is noncanonical".to_owned(),
        ));
    }
    let completed_at = raw
        .13
        .as_deref()
        .map(|value| {
            let completed_at = crate::persisted_time(value, "model call completed_at")?;
            if format_time(completed_at)? != value {
                return Err(JournalError::Integrity(
                    "stored model call completed_at is noncanonical".to_owned(),
                ));
            }
            Ok(completed_at)
        })
        .transpose()?;
    Ok(StoredModelCall {
        story_id: persisted_string(raw.0, "model call story id")?,
        session_id: persisted_string(raw.1, "model call session id")?,
        endpoint_kind: raw.2,
        model_id: raw.3,
        prompt_hash: persisted_string(raw.4, "model prompt hash")?,
        response_hash: raw
            .5
            .map(|hash| persisted_string(hash, "model response hash"))
            .transpose()?,
        input_filter_state: raw.6,
        output_filter_state: raw.7,
        output_risk_codes_json: raw.8,
        response_forwarded,
        output_bytes: raw
            .10
            .map(|value| rust_u64(value, "model output bytes"))
            .transpose()?,
        proposal_count: raw
            .11
            .map(|value| rust_u64(value, "model proposal count"))
            .transpose()?,
        created_at,
        completed_at,
    })
}

fn validate_model_row_for_completion(
    binding: &ModelJournalBinding,
    completion: &ModelCallCompletion,
    model: &StoredModelCall,
) -> Result<(), JournalError> {
    if model.story_id != binding.story_id || model.session_id != binding.session_id {
        return Err(JournalError::Integrity(
            "model call row does not match the journal binding".to_owned(),
        ));
    }
    if model.input_filter_state == "blocked" {
        return Err(JournalError::InvalidTransition {
            entity: "model_call",
            from: "input_blocked".to_owned(),
            to: "complete_model_call".to_owned(),
        });
    }
    if model.response_hash.is_some()
        || model.output_filter_state.is_some()
        || model.output_risk_codes_json.is_some()
        || model.response_forwarded.is_some()
        || model.output_bytes.is_some()
        || model.proposal_count.is_some()
        || model.completed_at.is_some()
    {
        return Err(JournalError::Conflict {
            entity: "model_call",
            id: completion.model_call_id.clone(),
            expected: 0,
            actual: 1,
        });
    }
    Ok(())
}

fn validate_completed_model_retry_tx(
    connection: &Connection,
    binding: &ModelJournalBinding,
    completion: &ModelCallCompletion,
    proposals: &[ProposedToolCall],
    model: &StoredModelCall,
) -> Result<(), JournalError> {
    let stored_risks: Option<Vec<EventCode>> = model
        .output_risk_codes_json
        .as_deref()
        .map(|json| persisted_json(json, "model output risk codes"))
        .transpose()?;
    let proposal_count = u64::try_from(proposals.len())
        .map_err(|_| JournalError::Integrity("model proposal count overflowed u64".to_owned()))?;
    if model.story_id != binding.story_id
        || model.session_id != binding.session_id
        || model.response_hash.as_ref() != Some(&completion.response_hash)
        || model.output_filter_state.as_deref() != Some(completion.output_filter_state.as_str())
        || stored_risks.as_deref() != Some(completion.output_risk_codes.as_slice())
        || model.response_forwarded != Some(completion.response_forwarded)
        || model.output_bytes != Some(completion.output_bytes)
        || model.proposal_count != Some(proposal_count)
        || model.completed_at != Some(completion.completed_at)
    {
        return Err(model_completion_conflict(&completion.model_call_id));
    }

    let mut statement = connection.prepare(
        r#"SELECT proposal_id, model_call_id, upstream_tool_call_id,
                  story_id, session_id, provider, action, argument_hash,
                  redacted_arguments_json, linked_operation_id
           FROM tool_proposals WHERE story_id = ?1 AND session_id = ?2
             AND model_call_id = ?3 ORDER BY proposal_id"#,
    )?;
    let stored = statement
        .query_map(
            params![
                binding.story_id.to_string(),
                binding.session_id.to_string(),
                completion.model_call_id
            ],
            |row| {
                Ok(StoredProposal {
                    proposal_id: row.get(0)?,
                    model_call_id: row.get(1)?,
                    upstream_tool_call_id: row.get(2)?,
                    story_id: row.get(3)?,
                    session_id: row.get(4)?,
                    provider: row.get(5)?,
                    action: row.get(6)?,
                    argument_hash: row.get(7)?,
                    redacted_arguments_json: row.get(8)?,
                    linked_operation_id: row.get(9)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if stored.len() != proposals.len() {
        return Err(model_completion_conflict(&completion.model_call_id));
    }
    let submitted = proposals
        .iter()
        .map(|proposal| (proposal.proposal_id.as_str(), proposal))
        .collect::<HashMap<_, _>>();
    for stored in stored {
        let Some(proposal) = submitted.get(stored.proposal_id.as_str()) else {
            return Err(model_completion_conflict(&completion.model_call_id));
        };
        let argument_hash: Sha256Digest =
            persisted_string(stored.argument_hash, "proposal argument hash")?;
        if stored.model_call_id != proposal.model_call_id
            || stored.story_id != binding.story_id.to_string()
            || stored.session_id != binding.session_id.to_string()
            || stored.upstream_tool_call_id != proposal.upstream_tool_call_id
            || stored.provider != proposal.provider
            || stored.action != proposal.action
            || argument_hash != proposal.argument_hash
            || stored.redacted_arguments_json != canonical_json(&proposal.redacted_arguments)?
        {
            return Err(model_completion_conflict(&completion.model_call_id));
        }
    }
    Ok(())
}

fn model_completion_conflict(model_call_id: &str) -> JournalError {
    JournalError::Conflict {
        entity: "model_call",
        id: model_call_id.to_owned(),
        expected: 0,
        actual: 1,
    }
}

fn insert_tool_proposal_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
    proposal: &ProposedToolCall,
    now: &str,
) -> Result<(), JournalError> {
    if row_exists(
        connection,
        "SELECT 1 FROM tool_proposals WHERE proposal_id = ?1",
        &proposal.proposal_id,
    )? {
        return Err(JournalError::Conflict {
            entity: "tool_proposal",
            id: proposal.proposal_id.clone(),
            expected: 0,
            actual: 1,
        });
    }
    connection.execute(
        r#"INSERT INTO tool_proposals (
            proposal_id, story_id, session_id, model_call_id,
            upstream_tool_call_id, provider, action, argument_hash,
            redacted_arguments_json, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
        params![
            proposal.proposal_id,
            story_id.to_string(),
            session_id.to_string(),
            proposal.model_call_id,
            proposal.upstream_tool_call_id,
            proposal.provider,
            proposal.action,
            proposal.argument_hash.as_str(),
            canonical_json(&proposal.redacted_arguments)?,
            now,
        ],
    )?;
    Ok(())
}

pub(crate) fn verify_model_lifecycle_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
) -> Result<(), JournalError> {
    let usage = load_model_usage_tx(connection, story_id, session_id)?;
    verify_model_usage_aggregate_tx(connection, story_id, session_id, usage)
}

fn verify_model_usage_aggregate_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
    usage: StoredModelUsage,
) -> Result<(), JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, event_type, provider, redacted_payload_json, recorded_at
           FROM events
           WHERE story_id = ?1 AND session_id = ?2
             AND event_type IN ('model_call', 'tool_proposal')
           ORDER BY sequence"#,
    )?;
    type RawLifecycleEvent = (i64, String, Option<String>, String, String);
    let raw_events = statement
        .query_map(
            params![story_id.to_string(), session_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?
        .collect::<Result<Vec<RawLifecycleEvent>, _>>()?;
    let mut lifecycles = HashMap::<String, StoredModelLifecycle>::new();
    let mut proposal_events = HashMap::<u64, StoredProposalEvent>::new();
    for (sequence, event_type, provider, payload_json, recorded_at) in raw_events {
        let sequence = rust_u64(sequence, "model lifecycle event sequence")?;
        let payload: StoryEventPayload = persisted_json(&payload_json, "model lifecycle payload")?;
        if canonical_json(&payload)? != payload_json {
            return Err(JournalError::Integrity(
                "stored model lifecycle event payload is noncanonical".to_owned(),
            ));
        }
        let recorded_at_raw = recorded_at;
        let recorded_at = crate::persisted_time(&recorded_at_raw, "model lifecycle event time")?;
        if format_time(recorded_at)? != recorded_at_raw {
            return Err(JournalError::Integrity(
                "stored model lifecycle event time is noncanonical".to_owned(),
            ));
        }
        if let Some(provider) = provider.as_deref() {
            validate_event_code("stored model lifecycle provider", provider)?;
        }
        match (event_type.as_str(), payload) {
            (
                "model_call",
                StoryEventPayload::ModelCall {
                    model_call_id,
                    phase,
                    model_id,
                    content_hash,
                    filter_state,
                    risk_codes,
                    forwarded,
                    content_bytes,
                    proposal_count,
                },
            ) => {
                let lifecycle = lifecycles
                    .entry(model_call_id.as_str().to_owned())
                    .or_default();
                let event = StoredModelEvent {
                    sequence,
                    provider,
                    model_id,
                    content_hash,
                    filter_state,
                    risk_codes,
                    forwarded,
                    content_bytes,
                    proposal_count,
                    recorded_at,
                };
                let slot = match phase.as_str() {
                    MODEL_REQUEST_RECEIVED => &mut lifecycle.request,
                    INPUT_FILTER_DECISION => &mut lifecycle.filter,
                    MODEL_RESPONSE_RECEIVED => &mut lifecycle.response,
                    _ => {
                        return Err(JournalError::Integrity(
                            "stored model lifecycle event phase is unknown".to_owned(),
                        ));
                    }
                };
                if slot.replace(event).is_some() {
                    return Err(JournalError::Integrity(
                        "stored model lifecycle contains a duplicate phase".to_owned(),
                    ));
                }
            }
            (
                "tool_proposal",
                StoryEventPayload::ToolProposal {
                    proposal_id,
                    upstream_tool_call_id,
                    provider: payload_provider,
                    action,
                    argument_hash,
                },
            ) => {
                let event = StoredProposalEvent {
                    provider,
                    proposal_id: proposal_id.as_str().to_owned(),
                    upstream_tool_call_id: upstream_tool_call_id
                        .as_ref()
                        .map(|value| value.as_str().to_owned()),
                    payload_provider: payload_provider.as_str().to_owned(),
                    action: action.as_str().to_owned(),
                    argument_hash,
                    recorded_at,
                };
                if proposal_events.insert(sequence, event).is_some() {
                    return Err(JournalError::Integrity(
                        "stored tool-proposal event sequence is duplicated".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(JournalError::Integrity(
                    "stored model lifecycle event kind disagrees with its payload".to_owned(),
                ));
            }
        }
    }

    let model_call_ids = connection
        .prepare(
            r#"SELECT model_call_id FROM model_calls
               WHERE story_id = ?1 AND session_id = ?2
               ORDER BY model_call_id"#,
        )?
        .query_map(
            params![story_id.to_string(), session_id.to_string()],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut models = HashMap::new();
    for model_call_id in model_call_ids {
        validate_event_code("stored model call id", &model_call_id)?;
        let model = load_model_call_tx(connection, &model_call_id)?;
        if model.story_id != story_id || model.session_id != session_id {
            return Err(JournalError::Integrity(
                "stored model call does not belong to its queried story and session".to_owned(),
            ));
        }
        models.insert(model_call_id, model);
    }

    let mut matched_proposal_sequences = HashSet::new();
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut response_count = 0_u64;
    for (model_call_id, lifecycle) in &lifecycles {
        let model = models.get(model_call_id).ok_or_else(|| {
            JournalError::Integrity(
                "sealed model event references a missing model-call row".to_owned(),
            )
        })?;
        if !matches!(
            model.endpoint_kind.as_str(),
            "chat_completions" | "responses"
        ) {
            return Err(JournalError::Integrity(
                "stored model endpoint kind is unsupported".to_owned(),
            ));
        }
        let request = lifecycle.request.as_ref().ok_or_else(|| {
            JournalError::Integrity(
                "domain model lifecycle is missing its request event".to_owned(),
            )
        })?;
        let filter = lifecycle.filter.as_ref().ok_or_else(|| {
            JournalError::Integrity("domain model lifecycle is missing its filter event".to_owned())
        })?;
        if request.sequence.checked_add(1) != Some(filter.sequence)
            || request.provider.is_none()
            || request.provider != filter.provider
            || request.recorded_at != model.created_at
            || filter.recorded_at != model.created_at
            || request.model_id.as_ref().map(EventCode::as_str) != Some(model.model_id.as_str())
            || filter.model_id.as_ref().map(EventCode::as_str) != Some(model.model_id.as_str())
            || request.content_hash != model.prompt_hash
            || filter.content_hash != model.prompt_hash
            || request.filter_state.is_some()
            || !request.risk_codes.is_empty()
            || request.forwarded.is_some()
            || request.proposal_count.is_some()
            || filter.filter_state.as_ref().map(EventCode::as_str)
                != Some(model.input_filter_state.as_str())
            || filter.content_bytes != request.content_bytes
            || filter.proposal_count.is_some()
            || !event_codes_are_unique(&filter.risk_codes)
        {
            return Err(JournalError::Integrity(
                "domain model begin events disagree with their committed row".to_owned(),
            ));
        }
        if model.input_filter_state == "blocked" {
            if filter.forwarded != Some(false) {
                return Err(JournalError::Integrity(
                    "blocked input-filter event does not prove no forward".to_owned(),
                ));
            }
        } else if filter.forwarded.is_some() {
            return Err(JournalError::Integrity(
                "pre-forward filter event claims forwarding occurred".to_owned(),
            ));
        }
        input_bytes = input_bytes
            .checked_add(request.content_bytes)
            .ok_or_else(|| {
                JournalError::Integrity("model input aggregate overflowed".to_owned())
            })?;

        let proposals =
            load_lifecycle_proposals_tx(connection, story_id, session_id, model_call_id)?;
        match lifecycle.response.as_ref() {
            Some(response) => {
                if model.input_filter_state == "blocked" {
                    return Err(JournalError::Integrity(
                        "blocked model input has a response lifecycle".to_owned(),
                    ));
                }
                let stored_risks: Vec<EventCode> = model
                    .output_risk_codes_json
                    .as_deref()
                    .ok_or_else(|| {
                        JournalError::Integrity(
                            "model response event has no stored risk codes".to_owned(),
                        )
                    })
                    .and_then(|json| persisted_json(json, "model output risk codes"))?;
                if canonical_json(&stored_risks)?
                    != model.output_risk_codes_json.as_deref().unwrap_or_default()
                    || !event_codes_are_unique(&stored_risks)
                {
                    return Err(JournalError::Integrity(
                        "stored model output risk codes are noncanonical or duplicated".to_owned(),
                    ));
                }
                let completed_at = model.completed_at.ok_or_else(|| {
                    JournalError::Integrity(
                        "model response event has no completed model-call row".to_owned(),
                    )
                })?;
                if response.sequence <= filter.sequence
                    || response.provider != request.provider
                    || response.recorded_at != completed_at
                    || response.model_id.as_ref().map(EventCode::as_str)
                        != Some(model.model_id.as_str())
                    || model.response_hash.as_ref() != Some(&response.content_hash)
                    || response.filter_state.as_ref().map(EventCode::as_str)
                        != model.output_filter_state.as_deref()
                    || response.risk_codes != stored_risks
                    || response.forwarded != model.response_forwarded
                    || Some(response.content_bytes) != model.output_bytes
                    || response.proposal_count != model.proposal_count
                    || (response
                        .filter_state
                        .as_ref()
                        .is_some_and(|state| state.as_str() == "blocked")
                        && response.forwarded == Some(true))
                {
                    return Err(JournalError::Integrity(
                        "domain model response event disagrees with its committed row".to_owned(),
                    ));
                }
                let proposal_count = response.proposal_count.ok_or_else(|| {
                    JournalError::Integrity("model response event has no proposal count".to_owned())
                })?;
                if u64::try_from(proposals.len()).map_err(|_| {
                    JournalError::Integrity("model proposal row count overflowed".to_owned())
                })? != proposal_count
                {
                    return Err(JournalError::Integrity(
                        "model response proposal count disagrees with proposal rows".to_owned(),
                    ));
                }
                let mut proposals_by_id = proposals
                    .into_iter()
                    .map(|proposal| (proposal.proposal_id.clone(), proposal))
                    .collect::<HashMap<_, _>>();
                for offset in 0..proposal_count {
                    let sequence = response
                        .sequence
                        .checked_add(1)
                        .and_then(|sequence| sequence.checked_add(offset))
                        .ok_or_else(|| {
                            JournalError::Integrity(
                                "tool-proposal event sequence overflowed".to_owned(),
                            )
                        })?;
                    let proposal_event = proposal_events.get(&sequence).ok_or_else(|| {
                        JournalError::Integrity(
                            "model response is not immediately followed by its proposal events"
                                .to_owned(),
                        )
                    })?;
                    let proposal = proposals_by_id
                        .remove(&proposal_event.proposal_id)
                        .ok_or_else(|| {
                            JournalError::Integrity(
                                "tool-proposal event has no matching proposal row".to_owned(),
                            )
                        })?;
                    verify_lifecycle_proposal(
                        &proposal,
                        proposal_event,
                        story_id,
                        session_id,
                        model_call_id,
                        completed_at,
                    )?;
                    matched_proposal_sequences.insert(sequence);
                }
                if !proposals_by_id.is_empty() {
                    return Err(JournalError::Integrity(
                        "model proposal rows are not fully represented by sealed events".to_owned(),
                    ));
                }
                output_bytes = output_bytes
                    .checked_add(response.content_bytes)
                    .ok_or_else(|| {
                        JournalError::Integrity("model output aggregate overflowed".to_owned())
                    })?;
                response_count = response_count.checked_add(1).ok_or_else(|| {
                    JournalError::Integrity("model response aggregate overflowed".to_owned())
                })?;
            }
            None => {
                if !model_completion_is_empty(model) {
                    return Err(JournalError::Integrity(
                        "completed model-call row has no sealed response event".to_owned(),
                    ));
                }
                if !proposals.is_empty() {
                    return Err(JournalError::Integrity(
                        "incomplete domain model call has pre-existing proposal rows".to_owned(),
                    ));
                }
            }
        }
    }

    for (model_call_id, model) in &models {
        if !lifecycles.contains_key(model_call_id) && !model_completion_is_empty(model) {
            return Err(JournalError::Integrity(
                "low-level-only model row contains domain completion fields".to_owned(),
            ));
        }
    }
    if proposal_events
        .keys()
        .any(|sequence| !matched_proposal_sequences.contains(sequence))
    {
        return Err(JournalError::Integrity(
            "sealed tool-proposal event is not owned by an adjacent model response".to_owned(),
        ));
    }

    let calls = u64::try_from(lifecycles.len())
        .map_err(|_| JournalError::Integrity("model call aggregate overflowed".to_owned()))?;
    let version = calls.checked_add(response_count).ok_or_else(|| {
        JournalError::Integrity("model usage version aggregate overflowed".to_owned())
    })?;
    if usage.version != version
        || usage.calls_committed != calls
        || usage.input_bytes_committed != input_bytes
        || usage.output_bytes_committed != output_bytes
    {
        return Err(JournalError::Integrity(
            "model usage counters disagree with sealed model events".to_owned(),
        ));
    }
    Ok(())
}

fn event_codes_are_unique(codes: &[EventCode]) -> bool {
    let mut seen = HashSet::new();
    codes.iter().all(|code| seen.insert(code.as_str()))
}

fn model_completion_is_empty(model: &StoredModelCall) -> bool {
    model.response_hash.is_none()
        && model.output_filter_state.is_none()
        && model.output_risk_codes_json.is_none()
        && model.response_forwarded.is_none()
        && model.output_bytes.is_none()
        && model.proposal_count.is_none()
        && model.completed_at.is_none()
}

fn load_lifecycle_proposals_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
    model_call_id: &str,
) -> Result<Vec<StoredLifecycleProposal>, JournalError> {
    type Raw = (
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
    );
    let rows = connection
        .prepare(
            r#"SELECT proposal_id, story_id, session_id, model_call_id,
                      upstream_tool_call_id, provider, action, argument_hash,
                      redacted_arguments_json, created_at
               FROM tool_proposals
               WHERE story_id = ?1 AND session_id = ?2 AND model_call_id = ?3
               ORDER BY proposal_id"#,
        )?
        .query_map(
            params![story_id.to_string(), session_id.to_string(), model_call_id],
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
                    row.get(9)?,
                ))
            },
        )?
        .collect::<Result<Vec<Raw>, _>>()?;
    rows.into_iter()
        .map(|raw| {
            validate_event_code("stored lifecycle proposal id", &raw.0)?;
            validate_optional_event_code(
                "stored lifecycle upstream tool call id",
                raw.4.as_deref(),
            )?;
            validate_event_code("stored lifecycle proposal provider", &raw.5)?;
            validate_event_code("stored lifecycle proposal action", &raw.6)?;
            let redacted: SafeArgumentView =
                persisted_json(&raw.8, "model lifecycle safe arguments")?;
            if canonical_json(&redacted)? != raw.8 {
                return Err(JournalError::Integrity(
                    "stored model lifecycle safe arguments are noncanonical".to_owned(),
                ));
            }
            let created_at = crate::persisted_time(&raw.9, "model proposal created_at")?;
            if format_time(created_at)? != raw.9 {
                return Err(JournalError::Integrity(
                    "stored model proposal timestamp is noncanonical".to_owned(),
                ));
            }
            Ok(StoredLifecycleProposal {
                proposal_id: raw.0,
                story_id: persisted_string(raw.1, "model proposal story id")?,
                session_id: persisted_string(raw.2, "model proposal session id")?,
                model_call_id: raw.3,
                upstream_tool_call_id: raw.4,
                provider: raw.5,
                action: raw.6,
                argument_hash: persisted_string(raw.7, "model proposal argument hash")?,
                created_at,
            })
        })
        .collect()
}

fn verify_lifecycle_proposal(
    proposal: &StoredLifecycleProposal,
    event: &StoredProposalEvent,
    story_id: StoryId,
    session_id: SessionId,
    model_call_id: &str,
    completed_at: OffsetDateTime,
) -> Result<(), JournalError> {
    if proposal.story_id != story_id
        || proposal.session_id != session_id
        || proposal.model_call_id != model_call_id
        || proposal.proposal_id != event.proposal_id
        || proposal.upstream_tool_call_id != event.upstream_tool_call_id
        || proposal.provider != event.payload_provider
        || event.provider.as_deref() != Some(proposal.provider.as_str())
        || proposal.action != event.action
        || proposal.argument_hash != event.argument_hash
        || proposal.created_at != completed_at
        || event.recorded_at != completed_at
    {
        return Err(JournalError::Integrity(
            "sealed tool-proposal event disagrees with its committed row".to_owned(),
        ));
    }
    Ok(())
}

fn validate_model_context_tx(
    connection: &Connection,
    story_id: StoryId,
    session_id: SessionId,
    now: OffsetDateTime,
) -> Result<(), JournalError> {
    verify_story_evidence_tx(connection, story_id)?;
    let story = load_story_record(connection, story_id)?;
    let session = load_session_record(connection, session_id)?;
    if story.story.authority.session_id != session_id
        || session.record.story_id != story_id
        || session.record.authority != story.story.authority
    {
        return Err(JournalError::Integrity(
            "model call story, session, and authority do not identify one context".to_owned(),
        ));
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
            from: crate::enum_text(&story.story.status)?,
            to: "record_model_evidence".to_owned(),
        });
    }
    if !session.active || session.record.authority.authz_state != "active" {
        return Err(JournalError::InvalidTransition {
            entity: "session",
            from: session.record.authority.authz_state,
            to: "record_model_evidence".to_owned(),
        });
    }
    if now >= session.record.expires_at {
        return Err(JournalError::InvalidTransition {
            entity: "session",
            from: "expired".to_owned(),
            to: "record_model_evidence".to_owned(),
        });
    }
    if now < story.updated_at {
        return Err(JournalError::InvalidTransition {
            entity: "model_event_time",
            from: format_time(story.updated_at)?,
            to: format_time(now)?,
        });
    }
    Ok(())
}

fn validate_link_request(
    input: &NewOperation,
    query: &ProposalLinkQuery,
) -> Result<(), JournalError> {
    if input.parent_model_call_id.is_some() || input.proposed_tool_call_id.is_some() {
        return Err(JournalError::Integrity(
            "proposal-aware operation creation requires empty caller causal ids".to_owned(),
        ));
    }
    if input.story_id != query.story_id
        || input.session_id != query.session_id
        || input.provider != query.provider
        || input.action != query.action
        || input.argument_hash != query.argument_hash
    {
        return Err(JournalError::Integrity(
            "proposal link query does not match the operation commitment".to_owned(),
        ));
    }
    validate_optional_event_code(
        "upstream tool call id",
        query.upstream_tool_call_id.as_deref(),
    )?;
    validate_event_code("proposal provider", &query.provider)?;
    validate_event_code("proposal action", &query.action)
}

fn resolve_proposal_tx(
    connection: &Connection,
    query: &ProposalLinkQuery,
) -> Result<ProposalResolution, JournalError> {
    let proposals = load_candidate_proposals_tx(connection, query)?;
    if query.upstream_tool_call_id.is_some() {
        let unlinked = proposals
            .iter()
            .filter(|proposal| proposal.linked_operation_id.is_none())
            .collect::<Vec<_>>();
        return match unlinked.as_slice() {
            [candidate] => Ok(linked(clone_stored_proposal(candidate))),
            candidates if candidates.len() > 1 => Ok(unresolved(
                CausalGapReason::AmbiguousCommitment,
                u64::try_from(candidates.len()).map_err(|_| {
                    JournalError::Integrity("causal candidate count overflowed u64".to_owned())
                })?,
            )),
            [] if proposals.is_empty() => Ok(unresolved(CausalGapReason::NoMatchingProposal, 0)),
            [] => Ok(unresolved(
                CausalGapReason::ProposalAlreadyClaimed,
                u64::try_from(proposals.len()).map_err(|_| {
                    JournalError::Integrity("causal candidate count overflowed u64".to_owned())
                })?,
            )),
            _ => unreachable!("exact-id candidate cardinality was fully matched"),
        };
    }

    let mut unlinked = proposals
        .iter()
        .filter(|proposal| proposal.linked_operation_id.is_none());
    let first = unlinked.next();
    let second = unlinked.next();
    match (first, second) {
        (Some(candidate), None) => Ok(linked(clone_stored_proposal(candidate))),
        (Some(_), Some(_)) => {
            let count = proposals
                .iter()
                .filter(|proposal| proposal.linked_operation_id.is_none())
                .count();
            Ok(unresolved(
                CausalGapReason::AmbiguousCommitment,
                u64::try_from(count).map_err(|_| {
                    JournalError::Integrity("causal candidate count overflowed u64".to_owned())
                })?,
            ))
        }
        (None, None) if proposals.is_empty() => {
            Ok(unresolved(CausalGapReason::MissingUpstreamId, 0))
        }
        (None, None) => Ok(unresolved(
            CausalGapReason::ProposalAlreadyClaimed,
            u64::try_from(proposals.len()).map_err(|_| {
                JournalError::Integrity("causal candidate count overflowed u64".to_owned())
            })?,
        )),
        (None, Some(_)) => unreachable!("an iterator cannot yield a second item without a first"),
    }
}

fn load_candidate_proposals_tx(
    connection: &Connection,
    query: &ProposalLinkQuery,
) -> Result<Vec<StoredProposal>, JournalError> {
    let sql = if query.upstream_tool_call_id.is_some() {
        r#"SELECT proposal_id, model_call_id, upstream_tool_call_id,
                  story_id, session_id, provider, action, argument_hash,
                  redacted_arguments_json, linked_operation_id
           FROM tool_proposals
           WHERE story_id = ?1 AND session_id = ?2
             AND provider = ?3 AND action = ?4 AND argument_hash = ?5
             AND upstream_tool_call_id = ?6
           ORDER BY proposal_id"#
    } else {
        r#"SELECT proposal_id, model_call_id, upstream_tool_call_id,
                  story_id, session_id, provider, action, argument_hash,
                  redacted_arguments_json, linked_operation_id
           FROM tool_proposals
           WHERE story_id = ?1 AND session_id = ?2
             AND provider = ?3 AND action = ?4 AND argument_hash = ?5
             AND ?6 IS NULL
           ORDER BY proposal_id"#
    };
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map(
        params![
            query.story_id.to_string(),
            query.session_id.to_string(),
            query.provider,
            query.action,
            query.argument_hash.as_str(),
            query.upstream_tool_call_id,
        ],
        |row| {
            Ok(StoredProposal {
                proposal_id: row.get(0)?,
                model_call_id: row.get(1)?,
                upstream_tool_call_id: row.get(2)?,
                story_id: row.get(3)?,
                session_id: row.get(4)?,
                provider: row.get(5)?,
                action: row.get(6)?,
                argument_hash: row.get(7)?,
                redacted_arguments_json: row.get(8)?,
                linked_operation_id: row.get(9)?,
            })
        },
    )?;
    let proposals = rows.collect::<Result<Vec<_>, _>>()?;
    for proposal in &proposals {
        validate_stored_proposal(proposal, query)?;
    }
    Ok(proposals)
}

fn linked(selected: StoredProposal) -> ProposalResolution {
    ProposalResolution {
        result: CausalLinkResult::Linked {
            proposal_id: selected.proposal_id.clone(),
            model_call_id: selected.model_call_id.clone(),
        },
        selected: Some(selected),
    }
}

fn unresolved(reason: CausalGapReason, candidate_count: u64) -> ProposalResolution {
    ProposalResolution {
        selected: None,
        result: CausalLinkResult::Unresolved {
            reason,
            candidate_count,
        },
    }
}

fn clone_stored_proposal(value: &StoredProposal) -> StoredProposal {
    StoredProposal {
        proposal_id: value.proposal_id.clone(),
        model_call_id: value.model_call_id.clone(),
        upstream_tool_call_id: value.upstream_tool_call_id.clone(),
        story_id: value.story_id.clone(),
        session_id: value.session_id.clone(),
        provider: value.provider.clone(),
        action: value.action.clone(),
        argument_hash: value.argument_hash.clone(),
        redacted_arguments_json: value.redacted_arguments_json.clone(),
        linked_operation_id: value.linked_operation_id.clone(),
    }
}

fn append_causal_link_tx(
    transaction: &Transaction<'_>,
    input: &NewOperation,
    result: &CausalLinkResult,
) -> Result<(), JournalError> {
    let (proposal_id, status, reason_code, candidate_count) = match result {
        CausalLinkResult::Linked { proposal_id, .. } => (
            Some(event_code("proposal id", proposal_id)?),
            event_code("causal status", "resolved")?,
            None,
            1,
        ),
        CausalLinkResult::Unresolved {
            reason,
            candidate_count,
        } => (
            None,
            event_code("causal status", "unresolved")?,
            Some(event_code("causal gap reason", reason.as_str())?),
            *candidate_count,
        ),
    };
    append_event_and_frame_tx(
        transaction,
        NewStoryEvent {
            obs_id: ObservationId::new(),
            event_id: EventId::new(),
            story_id: input.story_id,
            session_id: input.session_id,
            operation_id: Some(input.operation_id),
            provider: Some(event_code("operation provider", &input.provider)?),
            payload: StoryEventPayload::CausalLink {
                proposal_id,
                status,
                reason_code,
                candidate_count,
            },
            recorded_at: input.now,
        },
    )?;
    Ok(())
}

fn load_existing_causal_result_tx(
    connection: &Connection,
    operation_id: OperationId,
    query: &ProposalLinkQuery,
) -> Result<(CausalLinkResult, Option<String>, Option<String>), JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT sequence, provider, redacted_payload_json
           FROM events
           WHERE operation_id = ?1 AND story_id = ?2 AND session_id = ?3
             AND event_type = 'causal_link'
           ORDER BY sequence"#,
    )?;
    let payloads = statement
        .query_map(
            params![
                operation_id.to_string(),
                query.story_id.to_string(),
                query.session_id.to_string()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let [(causal_sequence, provider, payload_json)] = payloads.as_slice() else {
        return Err(JournalError::Integrity(
            "proposal-aware operation must have exactly one causal-link event".to_owned(),
        ));
    };
    if provider.as_deref() != Some(query.provider.as_str()) {
        return Err(JournalError::Integrity(
            "causal-link event provider does not match the operation".to_owned(),
        ));
    }
    let proposed_sequences = connection
        .prepare(
            r#"SELECT sequence FROM events
               WHERE operation_id = ?1 AND story_id = ?2 AND session_id = ?3
                 AND event_type = 'operation_proposed'
               ORDER BY sequence"#,
        )?
        .query_map(
            params![
                operation_id.to_string(),
                query.story_id.to_string(),
                query.session_id.to_string()
            ],
            |row| row.get::<_, i64>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let [proposed_sequence] = proposed_sequences.as_slice() else {
        return Err(JournalError::Integrity(
            "proposal-aware operation must have exactly one operation-proposed event".to_owned(),
        ));
    };
    if proposed_sequence.checked_add(1) != Some(*causal_sequence) {
        return Err(JournalError::Integrity(
            "causal-link event does not immediately follow operation proposal".to_owned(),
        ));
    }
    let payload: StoryEventPayload = crate::persisted_json(payload_json, "causal link event")?;
    if canonical_json(&payload)? != *payload_json {
        return Err(JournalError::Integrity(
            "stored causal-link event payload is noncanonical".to_owned(),
        ));
    }
    match payload {
        StoryEventPayload::CausalLink {
            proposal_id: Some(proposal_id),
            status,
            reason_code: None,
            candidate_count: 1,
        } if status.as_str() == "resolved" => {
            let proposal = load_linked_proposal_tx(connection, proposal_id.as_str(), operation_id)?;
            validate_stored_proposal(&proposal, query)?;
            Ok((
                CausalLinkResult::Linked {
                    proposal_id: proposal.proposal_id,
                    model_call_id: proposal.model_call_id.clone(),
                },
                Some(proposal.model_call_id),
                proposal.upstream_tool_call_id,
            ))
        }
        StoryEventPayload::CausalLink {
            proposal_id: None,
            status,
            reason_code: Some(reason),
            candidate_count,
        } if status.as_str() == "unresolved" => {
            let linked_rows: i64 = connection.query_row(
                "SELECT count(*) FROM tool_proposals WHERE linked_operation_id = ?1",
                params![operation_id.to_string()],
                |row| row.get(0),
            )?;
            if linked_rows != 0 {
                return Err(JournalError::Integrity(
                    "unresolved causal event has a linked proposal row".to_owned(),
                ));
            }
            Ok((
                CausalLinkResult::Unresolved {
                    reason: CausalGapReason::from_code(reason.as_str())?,
                    candidate_count,
                },
                None,
                None,
            ))
        }
        _ => Err(JournalError::Integrity(
            "stored causal-link event has inconsistent semantics".to_owned(),
        )),
    }
}

fn load_linked_proposal_tx(
    connection: &Connection,
    proposal_id: &str,
    operation_id: OperationId,
) -> Result<StoredProposal, JournalError> {
    connection
        .query_row(
            r#"SELECT proposal_id, model_call_id, upstream_tool_call_id,
                      story_id, session_id, provider, action, argument_hash,
                      redacted_arguments_json, linked_operation_id
               FROM tool_proposals
               WHERE proposal_id = ?1 AND linked_operation_id = ?2"#,
            params![proposal_id, operation_id.to_string()],
            |row| {
                Ok(StoredProposal {
                    proposal_id: row.get(0)?,
                    model_call_id: row.get(1)?,
                    upstream_tool_call_id: row.get(2)?,
                    story_id: row.get(3)?,
                    session_id: row.get(4)?,
                    provider: row.get(5)?,
                    action: row.get(6)?,
                    argument_hash: row.get(7)?,
                    redacted_arguments_json: row.get(8)?,
                    linked_operation_id: row.get(9)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| JournalError::Integrity("resolved proposal link row is missing".to_owned()))
}

fn validate_stored_proposal(
    proposal: &StoredProposal,
    query: &ProposalLinkQuery,
) -> Result<(), JournalError> {
    validate_event_code("stored proposal id", &proposal.proposal_id)?;
    validate_event_code("stored model call id", &proposal.model_call_id)?;
    validate_optional_event_code(
        "stored upstream tool call id",
        proposal.upstream_tool_call_id.as_deref(),
    )?;
    validate_event_code("stored proposal provider", &proposal.provider)?;
    validate_event_code("stored proposal action", &proposal.action)?;
    let story_id: StoryId = persisted_string(proposal.story_id.clone(), "proposal story id")?;
    let session_id: SessionId =
        persisted_string(proposal.session_id.clone(), "proposal session id")?;
    let argument_hash: Sha256Digest =
        persisted_string(proposal.argument_hash.clone(), "proposal argument hash")?;
    let redacted_arguments: SafeArgumentView =
        crate::persisted_json(&proposal.redacted_arguments_json, "proposal safe arguments")?;
    if canonical_json(&redacted_arguments)? != proposal.redacted_arguments_json {
        return Err(JournalError::Integrity(
            "stored proposal safe arguments are noncanonical".to_owned(),
        ));
    }
    if let Some(linked_operation_id) = proposal.linked_operation_id.as_ref() {
        let _: OperationId = persisted_string(linked_operation_id.clone(), "linked operation id")?;
    }
    if story_id != query.story_id
        || session_id != query.session_id
        || proposal.provider != query.provider
        || proposal.action != query.action
        || argument_hash != query.argument_hash
        || (query.upstream_tool_call_id.is_some()
            && proposal.upstream_tool_call_id != query.upstream_tool_call_id)
    {
        return Err(JournalError::Integrity(
            "stored proposal link does not match retry query".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_operation_causal_link_tx(
    connection: &Connection,
    operation: &SecurityOperation,
) -> Result<(), JournalError> {
    let query = ProposalLinkQuery {
        story_id: operation.story_id,
        session_id: operation.session_id,
        upstream_tool_call_id: operation.proposed_tool_call_id.clone(),
        provider: operation.provider.clone(),
        action: operation.action.clone(),
        argument_hash: operation.argument_hash.clone(),
    };
    let causal_rows: i64 = connection.query_row(
        r#"SELECT count(*) FROM events
           WHERE story_id = ?1 AND operation_id = ?2 AND event_type = 'causal_link'"#,
        params![
            operation.story_id.to_string(),
            operation.operation_id.to_string()
        ],
        |row| row.get(0),
    )?;
    if causal_rows == 0 {
        let linked_rows: i64 = connection.query_row(
            "SELECT count(*) FROM tool_proposals WHERE linked_operation_id = ?1",
            params![operation.operation_id.to_string()],
            |row| row.get(0),
        )?;
        if linked_rows == 0 {
            return Ok(());
        }
        return Err(JournalError::Integrity(
            "operation without causal-link evidence has a linked proposal row".to_owned(),
        ));
    }
    let (_, parent_model_call_id, proposed_tool_call_id) =
        load_existing_causal_result_tx(connection, operation.operation_id, &query)?;
    if operation.parent_model_call_id != parent_model_call_id
        || operation.proposed_tool_call_id != proposed_tool_call_id
    {
        return Err(JournalError::Integrity(
            "operation causal fields do not match the sealed proposal link".to_owned(),
        ));
    }
    Ok(())
}

fn validate_filter_state(value: &EventCode) -> Result<(), JournalError> {
    if matches!(value.as_str(), "safe" | "flagged" | "blocked") {
        Ok(())
    } else {
        Err(JournalError::Integrity(
            "input filter state must be safe, flagged, or blocked".to_owned(),
        ))
    }
}

fn validate_event_code(label: &'static str, value: &str) -> Result<(), JournalError> {
    event_code(label, value).map(|_| ())
}

fn validate_optional_event_code(
    label: &'static str,
    value: Option<&str>,
) -> Result<(), JournalError> {
    value.map_or(Ok(()), |value| validate_event_code(label, value))
}

fn event_code(label: &'static str, value: &str) -> Result<EventCode, JournalError> {
    EventCode::try_from(value.to_owned())
        .map_err(|_| JournalError::Integrity(format!("{label} is not a valid event code")))
}

fn row_exists(connection: &Connection, sql: &str, id: &str) -> Result<bool, JournalError> {
    connection
        .query_row(sql, params![id], |_| Ok(()))
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}
