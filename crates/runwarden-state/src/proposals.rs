use runwarden_kernel::operation::{SafeArgumentView, SecurityOperation};
use runwarden_kernel::story::{EventId, ObservationId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::events::{NewStoryEvent, append_event_and_frame_tx};
use crate::operations::{
    NewOperation, append_operation_proposed_tx, existing_invocation_operation_id_tx,
    insert_operation_rows_tx, load_operation_creation_context_tx, prepare_operation,
    require_operation_id_available_tx, retry_operation_tx, validate_new_operation_context,
};
use crate::sessions::load_session_record;
use crate::snapshots::{load_operation_tx, verify_story_evidence_tx};
use crate::stories::load_story_record;
use crate::{JournalError, StateStore, canonical_json, format_time, persisted_string};

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

impl StateStore {
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
        let model: Option<(String, String, String, String)> = transaction
            .query_row(
                r#"SELECT story_id, session_id, input_filter_state, created_at
                   FROM model_calls WHERE model_call_id = ?1"#,
                params![proposal.model_call_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (story_id, session_id, input_filter_state, created_at) =
            model.ok_or_else(|| JournalError::NotFound {
                entity: "model_call",
                id: proposal.model_call_id.clone(),
            })?;
        let story_id: StoryId = persisted_string(story_id, "proposal story id")?;
        let session_id: SessionId = persisted_string(session_id, "proposal session id")?;
        validate_model_context_tx(&transaction, story_id, session_id, now)?;
        if input_filter_state == "blocked" || input_filter_state == "pending" {
            return Err(JournalError::InvalidTransition {
                entity: "model_call",
                from: input_filter_state,
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
