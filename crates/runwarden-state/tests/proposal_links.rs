mod common;

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::story::{EnforcementMode, SessionId};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventKind, StoryEventPayload};
use runwarden_state::{
    CausalGapReason, CausalLinkResult, JournalError, ModelCallIntent, ProposalLinkQuery,
    ProposedToolCall,
};

fn record_model_call(fixture: &JournalFixture, model_call_id: &str, second: i64) {
    fixture
        .store
        .record_model_call(
            ModelCallIntent {
                model_call_id: model_call_id.to_owned(),
                story_id: fixture.story.story_id,
                session_id: fixture.story.authority.session_id,
                endpoint_kind: "chat_completions".to_owned(),
                model_id: "model-demo".to_owned(),
                prompt_hash: runwarden_kernel::trace::Sha256Digest::from_bytes(b"redacted prompt"),
            },
            EventCode::try_from("safe".to_owned()).unwrap(),
            mutation_time(&fixture.story, second),
        )
        .unwrap();
}

fn record_proposal(
    fixture: &JournalFixture,
    model_call_id: &str,
    proposal_id: &str,
    upstream_tool_call_id: Option<&str>,
    second: i64,
) {
    fixture
        .store
        .record_tool_proposal(
            proposal(fixture, model_call_id, proposal_id, upstream_tool_call_id),
            mutation_time(&fixture.story, second),
        )
        .unwrap();
}

fn proposal(
    fixture: &JournalFixture,
    model_call_id: &str,
    proposal_id: &str,
    upstream_tool_call_id: Option<&str>,
) -> ProposedToolCall {
    let operation = fixture.operation(250, "send");
    ProposedToolCall {
        proposal_id: proposal_id.to_owned(),
        model_call_id: model_call_id.to_owned(),
        upstream_tool_call_id: upstream_tool_call_id.map(str::to_owned),
        provider: operation.provider,
        action: operation.action,
        argument_hash: operation.argument_hash,
        redacted_arguments: operation.arguments,
    }
}

fn operation_and_query(
    fixture: &JournalFixture,
    invocation_suffix: u8,
    upstream_tool_call_id: Option<&str>,
    second: i64,
) -> (runwarden_state::NewOperation, ProposalLinkQuery) {
    let mut operation = fixture.operation(invocation_suffix, "send");
    operation.parent_model_call_id = None;
    operation.proposed_tool_call_id = None;
    operation.now = mutation_time(&fixture.story, second);
    let query = ProposalLinkQuery {
        story_id: operation.story_id,
        session_id: operation.session_id,
        upstream_tool_call_id: upstream_tool_call_id.map(str::to_owned),
        provider: operation.provider.clone(),
        action: operation.action.clone(),
        argument_hash: operation.argument_hash.clone(),
    };
    (operation, query)
}

#[test]
fn exact_upstream_id_links_atomically_and_retry_returns_the_sealed_result() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-exact", 1);
    record_proposal(
        &fixture,
        "model-call-exact",
        "proposal-exact",
        Some("call-upstream-1"),
        2,
    );

    let (operation, query) = operation_and_query(&fixture, 1, Some("call-upstream-1"), 3);
    let first = fixture
        .store
        .create_operation_with_proposal(operation, query.clone())
        .unwrap();
    assert!(first.created);
    assert_eq!(
        first.operation.parent_model_call_id.as_deref(),
        Some("model-call-exact")
    );
    assert_eq!(
        first.operation.proposed_tool_call_id.as_deref(),
        Some("call-upstream-1")
    );
    assert!(matches!(
        &first.causal_link,
        CausalLinkResult::Linked {
            proposal_id,
            model_call_id,
        } if proposal_id == "proposal-exact" && model_call_id == "model-call-exact"
    ));

    let before_retry = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(
        before_retry
            .events
            .iter()
            .filter(|event| event.operation_id == Some(first.operation.operation_id))
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            StoryEventKind::OperationProposed,
            StoryEventKind::CausalLink
        ]
    );
    assert!(
        !serde_json::to_string(&before_retry)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );

    let (retry_operation, retry_query) =
        operation_and_query(&fixture, 1, Some("call-upstream-1"), 4);
    let retry = fixture
        .store
        .create_operation_with_proposal(retry_operation, retry_query)
        .unwrap();
    assert!(!retry.created);
    assert_eq!(retry.operation.operation_id, first.operation.operation_id);
    assert_eq!(retry.causal_link, first.causal_link);
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        before_retry.events.len()
    );
}

#[test]
fn unique_commitment_without_upstream_id_links_but_ambiguity_is_explicit() {
    let unique = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&unique, "model-call-unique", 1);
    record_proposal(
        &unique,
        "model-call-unique",
        "proposal-unique",
        Some("call-unique-fallback"),
        2,
    );
    let (operation, query) = operation_and_query(&unique, 2, None, 3);
    let linked = unique
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap();
    assert!(matches!(
        linked.causal_link,
        CausalLinkResult::Linked { .. }
    ));
    assert_eq!(
        linked.operation.parent_model_call_id.as_deref(),
        Some("model-call-unique")
    );
    assert_eq!(
        linked.operation.proposed_tool_call_id.as_deref(),
        Some("call-unique-fallback")
    );

    let ambiguous = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&ambiguous, "model-call-a", 1);
    record_model_call(&ambiguous, "model-call-b", 2);
    record_proposal(&ambiguous, "model-call-a", "proposal-a", None, 3);
    record_proposal(&ambiguous, "model-call-b", "proposal-b", None, 4);
    let (operation, query) = operation_and_query(&ambiguous, 3, None, 5);
    let outcome = ambiguous
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap();
    assert!(matches!(
        outcome.causal_link,
        CausalLinkResult::Unresolved {
            reason: CausalGapReason::AmbiguousCommitment,
            candidate_count: 2,
        }
    ));
    assert!(outcome.operation.parent_model_call_id.is_none());
    assert!(outcome.operation.proposed_tool_call_id.is_none());
    let evidence = ambiguous
        .store
        .story_evidence(ambiguous.story.story_id)
        .unwrap();
    assert!(evidence.events.iter().any(|event| {
        event.operation_id == Some(outcome.operation.operation_id)
            && matches!(
                event.payload(),
                StoryEventPayload::CausalLink {
                    status,
                    reason_code: Some(reason),
                    candidate_count: 2,
                    ..
                } if status.as_str() == "unresolved"
                    && reason.as_str() == "ambiguous_commitment"
            )
    }));
}

#[test]
fn candidates_are_session_scoped_and_claimed_proposals_cannot_link_twice() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-primary", 1);
    record_proposal(
        &fixture,
        "model-call-primary",
        "proposal-primary",
        Some("call-primary"),
        2,
    );
    let (first_operation, first_query) = operation_and_query(&fixture, 4, Some("call-primary"), 3);
    fixture
        .store
        .create_operation_with_proposal(first_operation, first_query)
        .unwrap();

    let (second_operation, second_query) =
        operation_and_query(&fixture, 5, Some("call-primary"), 4);
    let second = fixture
        .store
        .create_operation_with_proposal(second_operation, second_query)
        .unwrap();
    assert!(matches!(
        second.causal_link,
        CausalLinkResult::Unresolved {
            reason: CausalGapReason::ProposalAlreadyClaimed,
            candidate_count: 1,
        }
    ));

    record_model_call(&fixture, "model-call-reused-upstream", 5);
    record_proposal(
        &fixture,
        "model-call-reused-upstream",
        "proposal-reused-upstream",
        Some("call-primary"),
        6,
    );
    let (third_operation, third_query) = operation_and_query(&fixture, 25, Some("call-primary"), 7);
    let third = fixture
        .store
        .create_operation_with_proposal(third_operation, third_query)
        .unwrap();
    assert!(matches!(
        third.causal_link,
        CausalLinkResult::Linked { proposal_id, .. }
            if proposal_id == "proposal-reused-upstream"
    ));

    let other = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&other, "model-call-other-session", 1);
    record_proposal(
        &other,
        "model-call-other-session",
        "proposal-other-session",
        None,
        2,
    );
    let isolated = JournalFixture::new(EnforcementMode::Enforced);
    let (operation, query) = operation_and_query(&isolated, 6, None, 1);
    let outcome = isolated
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap();
    assert!(matches!(
        outcome.causal_link,
        CausalLinkResult::Unresolved {
            reason: CausalGapReason::MissingUpstreamId,
            candidate_count: 0,
        }
    ));
}

#[test]
fn proposal_aware_creation_rejects_prefilled_or_mismatched_causal_inputs() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let (mut prefilled, query) = operation_and_query(&fixture, 7, None, 1);
    prefilled.parent_model_call_id = Some("caller-controlled".to_owned());
    assert!(matches!(
        fixture
            .store
            .create_operation_with_proposal(prefilled, query),
        Err(JournalError::Integrity(_))
    ));

    let (operation, mut mismatch) = operation_and_query(&fixture, 8, None, 1);
    mismatch.action = "different".to_owned();
    assert!(matches!(
        fixture
            .store
            .create_operation_with_proposal(operation, mismatch),
        Err(JournalError::Integrity(_))
    ));
    assert!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .is_empty()
    );
}

#[test]
fn duplicate_upstream_ids_within_one_model_call_are_rejected() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-duplicates", 1);
    record_proposal(
        &fixture,
        "model-call-duplicates",
        "proposal-first",
        Some("call-duplicate"),
        2,
    );
    let duplicate = fixture.store.record_tool_proposal(
        proposal(
            &fixture,
            "model-call-duplicates",
            "proposal-second",
            Some("call-duplicate"),
        ),
        mutation_time(&fixture.story, 3),
    );
    assert!(matches!(duplicate, Err(JournalError::Sqlite(_))));
}

#[test]
fn schema_and_resolver_both_reject_cross_session_edges() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-primary-session", 0);
    let primary_operation = fixture
        .store
        .create_operation(fixture.operation(20, "send"))
        .unwrap()
        .operation;
    let foreign_session = SessionId::new();
    let foreign_model_call = "model-call-foreign-session";
    let foreign_proposal = "proposal-foreign-session";
    let argument_hash = fixture.operation(21, "send").argument_hash;
    let redacted_arguments = serde_json::to_string(&fixture.operation(22, "send").arguments)
        .expect("serialize safe proposal arguments");
    let connection = rusqlite::Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO sessions (
                session_id, story_id, authority_json, policy_snapshot_hash,
                expires_at, active, version
            )
            SELECT ?1, story_id, authority_json, policy_snapshot_hash,
                   expires_at, active, version
            FROM sessions WHERE session_id = ?2"#,
            rusqlite::params![
                foreign_session.to_string(),
                fixture.story.authority.session_id.to_string()
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO model_calls (
                model_call_id, story_id, session_id, endpoint_kind, model_id,
                prompt_hash, input_filter_state, created_at
            ) VALUES (?1, ?2, ?3, 'chat_completions', 'model-demo', ?4,
                      'safe', '2026-01-01T00:00:00Z')"#,
            rusqlite::params![
                foreign_model_call,
                fixture.story.story_id.to_string(),
                foreign_session.to_string(),
                Sha256Digest::from_bytes(b"foreign prompt").as_str(),
            ],
        )
        .unwrap();

    let wrong_model_session = connection.execute(
        r#"INSERT INTO tool_proposals (
            proposal_id, story_id, session_id, model_call_id, provider,
            action, argument_hash, redacted_arguments_json, created_at
        ) VALUES (
            'proposal-wrong-model-session', ?1, ?2, 'model-call-primary-session',
            'email.send', 'send', ?3, ?4, '2026-01-01T00:00:00Z'
        )"#,
        rusqlite::params![
            fixture.story.story_id.to_string(),
            foreign_session.to_string(),
            argument_hash.as_str(),
            redacted_arguments,
        ],
    );
    assert!(wrong_model_session.is_err());

    connection
        .execute(
            r#"INSERT INTO tool_proposals (
                proposal_id, story_id, session_id, model_call_id, provider,
                action, argument_hash, redacted_arguments_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, 'email.send', 'send', ?5, ?6,
                      '2026-01-01T00:00:00Z')"#,
            rusqlite::params![
                foreign_proposal,
                fixture.story.story_id.to_string(),
                foreign_session.to_string(),
                foreign_model_call,
                argument_hash.as_str(),
                redacted_arguments,
            ],
        )
        .unwrap();
    drop(connection);

    let (operation, query) = operation_and_query(&fixture, 23, None, 2);
    let isolated = fixture
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap();
    assert!(matches!(
        isolated.causal_link,
        CausalLinkResult::Unresolved {
            reason: CausalGapReason::MissingUpstreamId,
            candidate_count: 0,
        }
    ));

    let connection = rusqlite::Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    let wrong_operation_session = connection.execute(
        r#"UPDATE tool_proposals SET linked_operation_id = ?1
           WHERE proposal_id = ?2"#,
        rusqlite::params![primary_operation.operation_id.to_string(), foreign_proposal],
    );
    assert!(wrong_operation_session.is_err());
}

#[test]
fn causal_snapshot_rejects_a_tampered_proposal_row() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-tamper", 1);
    record_proposal(
        &fixture,
        "model-call-tamper",
        "proposal-tamper",
        Some("call-tamper"),
        2,
    );
    let (operation, query) = operation_and_query(&fixture, 24, Some("call-tamper"), 3);
    let linked = fixture
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap();

    rusqlite::Connection::open(fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE tool_proposals SET provider = 'tampered.provider' WHERE proposal_id = ?1",
            rusqlite::params!["proposal-tamper"],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.operation(linked.operation.operation_id),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn causal_snapshot_rejects_a_one_sided_link_to_a_direct_operation() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-one-sided", 1);
    record_proposal(
        &fixture,
        "model-call-one-sided",
        "proposal-one-sided",
        Some("call-one-sided"),
        2,
    );
    let mut operation = fixture.operation(30, "send");
    operation.now = mutation_time(&fixture.story, 3);
    let direct = fixture.store.create_operation(operation).unwrap().operation;

    rusqlite::Connection::open(fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE tool_proposals SET linked_operation_id = ?1 WHERE proposal_id = 'proposal-one-sided'",
            rusqlite::params![direct.operation_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.operation(direct.operation_id),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture.store.story_snapshot(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn second_event_failure_rolls_back_operation_claim_and_first_event() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-rollback", 1);
    record_proposal(
        &fixture,
        "model-call-rollback",
        "proposal-rollback",
        Some("call-rollback"),
        2,
    );
    rusqlite::Connection::open(fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE stories SET version = ?1 WHERE story_id = ?2",
            rusqlite::params![i64::MAX - 1, fixture.story.story_id.to_string(),],
        )
        .unwrap();

    let (operation, query) = operation_and_query(&fixture, 26, Some("call-rollback"), 3);
    let operation_id = operation.operation_id;
    let error = fixture
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap_err();
    assert!(matches!(error, JournalError::Integrity(_)));
    assert!(!error.to_string().contains(PRIVATE_MARKER));

    let connection = rusqlite::Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let operation_rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM operations WHERE operation_id = ?1",
            rusqlite::params![operation_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let resource_rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM resource_claims WHERE operation_id = ?1",
            rusqlite::params![operation_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let event_rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM events WHERE operation_id = ?1",
            rusqlite::params![operation_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let frame_rows: i64 = connection
        .query_row("SELECT count(*) FROM story_frames", [], |row| row.get(0))
        .unwrap();
    let linked_operation_id: Option<String> = connection
        .query_row(
            "SELECT linked_operation_id FROM tool_proposals WHERE proposal_id = 'proposal-rollback'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        (operation_rows, resource_rows, event_rows, frame_rows),
        (0, 0, 0, 0)
    );
    assert!(linked_operation_id.is_none());
}

#[test]
fn concurrent_operations_claim_one_proposal_exactly_once() {
    use std::sync::{Arc, Barrier};

    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    record_model_call(&fixture, "model-call-contention", 1);
    record_proposal(
        &fixture,
        "model-call-contention",
        "proposal-contention",
        Some("call-contention"),
        2,
    );
    let (operation_a, query_a) = operation_and_query(&fixture, 27, Some("call-contention"), 3);
    let (operation_b, query_b) = operation_and_query(&fixture, 28, Some("call-contention"), 3);
    let barrier = Arc::new(Barrier::new(2));
    let handles = [
        (fixture.store.clone(), operation_a, query_a),
        (fixture.store.clone(), operation_b, query_b),
    ]
    .into_iter()
    .map(|(store, operation, query)| {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            store.create_operation_with_proposal(operation, query)
        })
    })
    .collect::<Vec<_>>();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome.causal_link, CausalLinkResult::Linked { .. }))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome.causal_link,
                CausalLinkResult::Unresolved {
                    reason: CausalGapReason::ProposalAlreadyClaimed,
                    candidate_count: 1,
                }
            ))
            .count(),
        1
    );
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 4);
    assert_eq!(evidence.replay_frames.len(), 4);
}

#[test]
fn unresolved_invocation_retry_is_not_rewritten_by_a_later_proposal() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let (operation, query) = operation_and_query(&fixture, 29, None, 1);
    let first = fixture
        .store
        .create_operation_with_proposal(operation, query)
        .unwrap();
    assert!(matches!(
        first.causal_link,
        CausalLinkResult::Unresolved {
            reason: CausalGapReason::MissingUpstreamId,
            candidate_count: 0,
        }
    ));

    record_model_call(&fixture, "model-call-after-gap", 2);
    record_proposal(
        &fixture,
        "model-call-after-gap",
        "proposal-after-gap",
        None,
        3,
    );
    let (retry_operation, retry_query) = operation_and_query(&fixture, 29, None, 4);
    let retry = fixture
        .store
        .create_operation_with_proposal(retry_operation, retry_query)
        .unwrap();
    assert!(!retry.created);
    assert_eq!(retry.operation.operation_id, first.operation.operation_id);
    assert_eq!(retry.causal_link, first.causal_link);

    let connection = rusqlite::Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let linked_operation_id: Option<String> = connection
        .query_row(
            "SELECT linked_operation_id FROM tool_proposals WHERE proposal_id = 'proposal-after-gap'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(linked_operation_id.is_none());
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        2
    );
}
