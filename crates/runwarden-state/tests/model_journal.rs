mod common;

use common::{JournalFixture, mutation_time};
use runwarden_kernel::operation::SafeArgumentView;
use runwarden_kernel::resource::DataClass;
use runwarden_kernel::session::NetworkAuthority;
use runwarden_kernel::story::{
    EnforcementMode, EventId, EvidenceStatus, ObservationId, StoryStatus,
};
use runwarden_kernel::trace::{
    EventCode, Sha256Digest, StoryEventKind, StoryEventPayload, canonical_json_v1,
};
use runwarden_state::{
    DemoActivation, FilterDecisionEvent, JournalError, ModelCallCompletion, ModelCallIntent,
    ModelJournalBinding, NewStoryEvent, ProposedToolCall,
};
use rusqlite::{Connection, params};
use serde::Serialize;

const TOKEN: &[u8] = b"model-journal-instance-token";
const UPSTREAM_PROVIDER: &str = "runwarden.model.upstream";
const UPSTREAM_ORIGIN: &str = "https://model.example.test";

struct ModelFixture {
    journal: JournalFixture,
    binding: ModelJournalBinding,
    token_hash: String,
}

impl ModelFixture {
    fn new(max_model_calls: u64) -> Self {
        let mut journal = JournalFixture::new(EnforcementMode::Enforced);
        journal.story.authority.networks = vec![NetworkAuthority {
            provider: UPSTREAM_PROVIDER.to_owned(),
            allowed_origins: vec![UPSTREAM_ORIGIN.to_owned()],
            maximum_classification: DataClass::Internal,
        }];
        journal.story.authority.budgets.max_model_calls = max_model_calls;
        let authority_json = canonical(&journal.story.authority);
        let story_json = canonical(&journal.story);
        let connection = Connection::open(journal.state_dir.join("runwarden.db")).unwrap();
        connection
            .execute(
                "UPDATE sessions SET authority_json = ?1 WHERE session_id = ?2",
                params![
                    authority_json,
                    journal.story.authority.session_id.to_string()
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE stories SET safe_story_json = ?1 WHERE story_id = ?2",
                params![story_json, journal.story.story_id.to_string()],
            )
            .unwrap();
        drop(connection);

        let token_hash = Sha256Digest::from_bytes(TOKEN).as_str().to_owned();
        journal
            .store
            .activate_demo(&DemoActivation {
                instance_id: "model-journal-test".to_owned(),
                story_id: journal.story.story_id,
                session_id: journal.story.authority.session_id,
                process_id: std::process::id().max(1),
                host_id: "model-journal-host".to_owned(),
                instance_token_hash: token_hash.clone(),
                now: mutation_time(&journal.story, 0),
            })
            .unwrap();
        let binding = journal
            .store
            .bind_model_journal(
                &token_hash,
                UPSTREAM_PROVIDER,
                UPSTREAM_ORIGIN,
                mutation_time(&journal.story, 0),
            )
            .unwrap();
        Self {
            journal,
            binding,
            token_hash,
        }
    }

    fn begin(&self, id: &str, second: i64, bytes: u64) -> Result<(), JournalError> {
        self.journal.store.begin_model_call(
            &self.binding,
            ModelCallIntent {
                model_call_id: id.to_owned(),
                story_id: self.binding.story_id(),
                session_id: self.binding.session_id(),
                endpoint_kind: "chat_completions".to_owned(),
                model_id: "model-demo".to_owned(),
                prompt_hash: Sha256Digest::from_bytes(format!("prompt-{id}").as_bytes()),
            },
            FilterDecisionEvent {
                filter_state: code("safe"),
                risk_codes: Vec::new(),
                content_bytes: bytes,
                recorded_at: mutation_time(&self.journal.story, second),
            },
        )
    }

    fn completion(&self, id: &str, second: i64, bytes: u64) -> ModelCallCompletion {
        ModelCallCompletion {
            model_call_id: id.to_owned(),
            response_hash: Sha256Digest::from_bytes(format!("response-{id}").as_bytes()),
            output_filter_state: code("safe"),
            output_risk_codes: Vec::new(),
            response_forwarded: true,
            output_bytes: bytes,
            completed_at: mutation_time(&self.journal.story, second),
        }
    }
}

fn canonical(value: &impl Serialize) -> String {
    String::from_utf8(canonical_json_v1(&serde_json::to_value(value).unwrap())).unwrap()
}

fn code(value: &str) -> EventCode {
    EventCode::try_from(value.to_owned()).unwrap()
}

fn model_usage(fixture: &ModelFixture) -> (i64, i64, i64, i64) {
    Connection::open(fixture.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .query_row(
            r#"SELECT version, calls_committed,
                      input_bytes_committed, output_bytes_committed
               FROM model_usage WHERE session_id = ?1"#,
            params![fixture.binding.session_id().to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

fn proposal(id: &str, model_call_id: &str) -> ProposedToolCall {
    ProposedToolCall {
        proposal_id: id.to_owned(),
        model_call_id: model_call_id.to_owned(),
        upstream_tool_call_id: Some(format!("upstream-{id}")),
        provider: "email.send".to_owned(),
        action: "send".to_owned(),
        argument_hash: Sha256Digest::from_bytes(id.as_bytes()),
        redacted_arguments: SafeArgumentView::Email {
            recipients: vec!["judge@example.test".to_owned()],
            subject_hash: Sha256Digest::from_bytes(b"subject"),
            body_hash: Sha256Digest::from_bytes(b"body"),
        },
    }
}

#[test]
fn begin_and_complete_commit_rows_budget_and_typed_events_atomically() {
    let fixture = ModelFixture::new(2);
    fixture.begin("model-call-1", 1, 17).unwrap();
    assert_eq!(model_usage(&fixture), (1, 1, 17, 0));

    let completion = fixture.completion("model-call-1", 2, 23);
    let proposed = proposal("proposal-1", "model-call-1");
    fixture
        .journal
        .store
        .complete_model_call(&fixture.binding, completion.clone(), vec![proposed.clone()])
        .unwrap();
    assert_eq!(model_usage(&fixture), (2, 1, 17, 23));

    let evidence = fixture
        .journal
        .store
        .story_evidence(fixture.binding.story_id())
        .unwrap();
    assert_eq!(evidence.events.len(), 4);
    assert_eq!(evidence.replay_frames.len(), 4);
    assert_eq!(
        evidence
            .events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            StoryEventKind::ModelCall,
            StoryEventKind::ModelCall,
            StoryEventKind::ModelCall,
            StoryEventKind::ToolProposal,
        ]
    );
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("prompt-model-call-1")
    );

    fixture
        .journal
        .store
        .complete_model_call(&fixture.binding, completion, vec![proposed])
        .unwrap();
    assert_eq!(model_usage(&fixture), (2, 1, 17, 23));
    assert_eq!(
        fixture
            .journal
            .store
            .story_evidence(fixture.binding.story_id())
            .unwrap()
            .events
            .len(),
        4
    );

    let duplicate = fixture.journal.store.complete_model_call(
        &fixture.binding,
        fixture.completion("model-call-1", 3, 23),
        Vec::new(),
    );
    assert!(matches!(duplicate, Err(JournalError::Conflict { .. })));
    assert_eq!(model_usage(&fixture), (2, 1, 17, 23));
    assert!(
        fixture
            .journal
            .store
            .record_tool_proposal(
                proposal("late-proposal", "model-call-1"),
                mutation_time(&fixture.journal.story, 4),
            )
            .is_err()
    );
}

#[test]
fn per_call_binding_egress_expiry_and_call_budget_fail_before_intent_commit() {
    let fixture = ModelFixture::new(1);
    assert!(
        fixture
            .journal
            .store
            .bind_model_journal(
                &fixture.token_hash,
                UPSTREAM_PROVIDER,
                "https://other.example.test",
                mutation_time(&fixture.journal.story, 0),
            )
            .is_err()
    );
    fixture.begin("model-call-budget-1", 1, 1).unwrap();
    assert!(fixture.begin("model-call-budget-2", 2, 1).is_err());
    assert_eq!(model_usage(&fixture), (1, 1, 1, 0));

    Connection::open(fixture.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE active_instances SET instance_token_hash = ?1 WHERE singleton = 1",
            params![Sha256Digest::from_bytes(b"replacement").as_str()],
        )
        .unwrap();
    assert!(fixture.begin("model-call-replaced-token", 3, 1).is_err());

    let expired = ModelFixture::new(2);
    assert!(
        expired
            .begin("model-call-expired", 24 * 60 * 60, 1,)
            .is_err()
    );
    assert_eq!(model_usage(&expired), (0, 0, 0, 0));
}

#[test]
fn concurrent_begins_cas_one_remaining_model_call_exactly_once() {
    use std::sync::{Arc, Barrier};

    let fixture = ModelFixture::new(1);
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["model-call-concurrent-a", "model-call-concurrent-b"]
        .into_iter()
        .map(|id| {
            let barrier = Arc::clone(&barrier);
            let store = fixture.journal.store.clone();
            let binding = fixture.binding.clone();
            let recorded_at = mutation_time(&fixture.journal.story, 1);
            std::thread::spawn(move || {
                barrier.wait();
                store.begin_model_call(
                    &binding,
                    ModelCallIntent {
                        model_call_id: id.to_owned(),
                        story_id: binding.story_id(),
                        session_id: binding.session_id(),
                        endpoint_kind: "chat_completions".to_owned(),
                        model_id: "model-demo".to_owned(),
                        prompt_hash: Sha256Digest::from_bytes(id.as_bytes()),
                    },
                    FilterDecisionEvent {
                        filter_state: code("safe"),
                        risk_codes: Vec::new(),
                        content_bytes: 1,
                        recorded_at,
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    assert_eq!(model_usage(&fixture), (1, 1, 1, 0));
    let evidence = fixture
        .journal
        .store
        .story_evidence(fixture.binding.story_id())
        .unwrap();
    assert_eq!(evidence.events.len(), 2);
    assert_eq!(evidence.replay_frames.len(), 2);
}

#[test]
fn second_begin_event_failure_rolls_back_model_row_usage_and_first_event() {
    let fixture = ModelFixture::new(2);
    Connection::open(fixture.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE stories SET version = ?1 WHERE story_id = ?2",
            params![i64::MAX - 1, fixture.binding.story_id().to_string()],
        )
        .unwrap();
    assert!(fixture.begin("model-call-rollback", 1, 10).is_err());
    assert_eq!(model_usage(&fixture), (0, 0, 0, 0));
    let connection = Connection::open(fixture.journal.state_dir.join("runwarden.db")).unwrap();
    let rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM model_calls WHERE model_call_id = 'model-call-rollback'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let events: i64 = connection
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    let frames: i64 = connection
        .query_row("SELECT count(*) FROM story_frames", [], |row| row.get(0))
        .unwrap();
    assert_eq!((rows, events, frames), (0, 0, 0));
}

#[test]
fn proposal_insert_failure_rolls_back_completion_row_usage_and_response_event() {
    let fixture = ModelFixture::new(2);
    fixture
        .begin("model-call-complete-rollback", 1, 10)
        .unwrap();
    fixture
        .journal
        .store
        .record_model_call(
            ModelCallIntent {
                model_call_id: "low-level-model-call".to_owned(),
                story_id: fixture.binding.story_id(),
                session_id: fixture.binding.session_id(),
                endpoint_kind: "chat_completions".to_owned(),
                model_id: "model-demo".to_owned(),
                prompt_hash: Sha256Digest::from_bytes(b"low-level-prompt"),
            },
            code("safe"),
            mutation_time(&fixture.journal.story, 2),
        )
        .unwrap();
    fixture
        .journal
        .store
        .record_tool_proposal(
            proposal("duplicate-proposal", "low-level-model-call"),
            mutation_time(&fixture.journal.story, 3),
        )
        .unwrap();
    let result = fixture.journal.store.complete_model_call(
        &fixture.binding,
        fixture.completion("model-call-complete-rollback", 4, 11),
        vec![proposal(
            "duplicate-proposal",
            "model-call-complete-rollback",
        )],
    );
    assert!(matches!(result, Err(JournalError::Conflict { .. })));
    assert_eq!(model_usage(&fixture), (1, 1, 10, 0));
    let connection = Connection::open(fixture.journal.state_dir.join("runwarden.db")).unwrap();
    let completed: Option<String> = connection
        .query_row(
            "SELECT completed_at FROM model_calls WHERE model_call_id = 'model-call-complete-rollback'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(completed.is_none());
    assert_eq!(
        fixture
            .journal
            .store
            .story_evidence(fixture.binding.story_id())
            .unwrap()
            .events
            .len(),
        2
    );
}

#[test]
fn low_level_proposal_api_rejects_domain_owned_model_calls() {
    let fixture = ModelFixture::new(2);
    fixture.begin("model-call-domain-owned", 1, 10).unwrap();
    let result = fixture.journal.store.record_tool_proposal(
        proposal("mixed-proposal", "model-call-domain-owned"),
        mutation_time(&fixture.journal.story, 2),
    );
    assert!(matches!(
        result,
        Err(JournalError::InvalidTransition {
            entity: "model_call",
            ..
        })
    ));
    let rows: i64 = Connection::open(fixture.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .query_row(
            "SELECT count(*) FROM tool_proposals WHERE model_call_id = 'model-call-domain-owned'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
    assert_eq!(model_usage(&fixture), (1, 1, 10, 0));
}

#[test]
fn authoritative_reads_reject_tampered_model_usage() {
    let fixture = ModelFixture::new(2);
    fixture.begin("model-call-usage-tamper", 1, 10).unwrap();
    fixture
        .journal
        .store
        .complete_model_call(
            &fixture.binding,
            fixture.completion("model-call-usage-tamper", 2, 11),
            Vec::new(),
        )
        .unwrap();
    Connection::open(fixture.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            r#"UPDATE model_usage SET output_bytes_committed = output_bytes_committed + 1
               WHERE session_id = ?1"#,
            params![fixture.binding.session_id().to_string()],
        )
        .unwrap();
    assert!(matches!(
        fixture
            .journal
            .store
            .story_evidence(fixture.binding.story_id()),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture
            .journal
            .store
            .story_snapshot(fixture.binding.story_id()),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn authoritative_reads_reject_tampered_model_and_proposal_rows() {
    let model = ModelFixture::new(2);
    model.begin("model-call-row-tamper", 1, 10).unwrap();
    model
        .journal
        .store
        .complete_model_call(
            &model.binding,
            model.completion("model-call-row-tamper", 2, 11),
            Vec::new(),
        )
        .unwrap();
    Connection::open(model.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE model_calls SET response_hash = ?1 WHERE model_call_id = 'model-call-row-tamper'",
            params![Sha256Digest::from_bytes(b"tampered-response").as_str()],
        )
        .unwrap();
    assert!(matches!(
        model.journal.store.story_evidence(model.binding.story_id()),
        Err(JournalError::Integrity(_))
    ));

    let proposal_row = ModelFixture::new(2);
    proposal_row
        .begin("model-call-proposal-tamper", 1, 10)
        .unwrap();
    proposal_row
        .journal
        .store
        .complete_model_call(
            &proposal_row.binding,
            proposal_row.completion("model-call-proposal-tamper", 2, 11),
            vec![proposal(
                "proposal-row-tamper",
                "model-call-proposal-tamper",
            )],
        )
        .unwrap();
    Connection::open(proposal_row.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE tool_proposals SET action = 'tampered' WHERE proposal_id = 'proposal-row-tamper'",
            [],
        )
        .unwrap();
    assert!(matches!(
        proposal_row
            .journal
            .store
            .story_evidence(proposal_row.binding.story_id()),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn post_side_effect_invalidation_seals_invalid_status_and_verification_event() {
    let fixture = ModelFixture::new(2);
    fixture.begin("model-call-invalid", 1, 10).unwrap();
    Connection::open(fixture.journal.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE active_instances SET instance_token_hash = ?1 WHERE singleton = 1",
            params![Sha256Digest::from_bytes(b"replacement-after-forward").as_str()],
        )
        .unwrap();
    fixture
        .journal
        .store
        .mark_model_evidence_invalid(
            &fixture.binding,
            "model_completion_commit_failed",
            mutation_time(&fixture.journal.story, 2),
        )
        .unwrap();
    let evidence = fixture
        .journal
        .store
        .story_evidence(fixture.binding.story_id())
        .unwrap();
    assert_eq!(evidence.story.status, StoryStatus::EvidenceInvalid);
    assert_eq!(evidence.story.evidence_status, EvidenceStatus::Invalid);
    assert!(matches!(
        evidence.events.last().unwrap().payload(),
        StoryEventPayload::EvidenceVerification {
            status: EvidenceStatus::Invalid,
            error_codes,
            event_chain_verified: true,
            report_claims_verified: false,
            ..
        } if error_codes.iter().any(|code| code.as_str() == "model_completion_commit_failed")
    ));
}

#[test]
fn public_append_rejects_model_domain_events() {
    let fixture = ModelFixture::new(2);
    let model_result = fixture.journal.store.append_event(NewStoryEvent {
        obs_id: ObservationId::new(),
        event_id: EventId::new(),
        story_id: fixture.binding.story_id(),
        session_id: fixture.binding.session_id(),
        operation_id: None,
        provider: None,
        payload: StoryEventPayload::ModelCall {
            model_call_id: code("forged-model-call"),
            phase: code("model_request_received"),
            model_id: Some(code("forged-model")),
            content_hash: Sha256Digest::from_bytes(b"forged"),
            filter_state: None,
            risk_codes: Vec::new(),
            forwarded: None,
            content_bytes: 6,
            proposal_count: None,
        },
        recorded_at: mutation_time(&fixture.journal.story, 1),
    });
    assert!(matches!(
        model_result,
        Err(JournalError::InvalidTransition {
            entity: "standalone_event",
            ..
        })
    ));
    let proposal_result = fixture.journal.store.append_event(NewStoryEvent {
        obs_id: ObservationId::new(),
        event_id: EventId::new(),
        story_id: fixture.binding.story_id(),
        session_id: fixture.binding.session_id(),
        operation_id: None,
        provider: Some(code("email.send")),
        payload: StoryEventPayload::ToolProposal {
            proposal_id: code("forged-proposal"),
            upstream_tool_call_id: Some(code("forged-upstream-id")),
            provider: code("email.send"),
            action: code("send"),
            argument_hash: Sha256Digest::from_bytes(b"forged-proposal"),
        },
        recorded_at: mutation_time(&fixture.journal.story, 1),
    });
    assert!(matches!(
        proposal_result,
        Err(JournalError::InvalidTransition {
            entity: "standalone_event",
            ..
        })
    ));
    assert!(
        fixture
            .journal
            .store
            .story_evidence(fixture.binding.story_id())
            .unwrap()
            .events
            .is_empty()
    );
}
