mod common;

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{OperationState, PolicyCheck, PolicyCheckStatus};
use runwarden_kernel::story::{EventId, ObservationId};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEvent, StoryEventPayload};
use runwarden_state::{JournalError, NewStoryEvent, RecordPolicyInput};
use rusqlite::{Connection, params};

fn export_fixture() -> JournalFixture {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = fixture
        .store
        .create_operation(fixture.operation(131, "send"))
        .unwrap()
        .operation;
    fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Allowed,
            reason: "legacy export policy".to_owned(),
            next_state: OperationState::PolicyEvaluated,
            checks: vec![PolicyCheck {
                check_id: "legacy-export-policy".to_owned(),
                layer: "authority".to_owned(),
                status: PolicyCheckStatus::Passed,
                reason: "safe export path".to_owned(),
                observation_ref: None,
            }],
            now: mutation_time(&fixture.story, 2),
        })
        .unwrap();
    fixture
        .store
        .append_event(NewStoryEvent {
            obs_id: ObservationId::new(),
            event_id: EventId::new(),
            story_id: fixture.story.story_id,
            session_id: fixture.story.authority.session_id,
            operation_id: None,
            provider: None,
            payload: StoryEventPayload::InputConsumed {
                asset_id: EventCode::try_from("legacy-safe-input".to_owned()).unwrap(),
                content_hash: Sha256Digest::from_bytes(b"legacy-safe-input"),
            },
            recorded_at: mutation_time(&fixture.story, 3),
        })
        .unwrap();
    fixture
}

fn parse_jsonl(bytes: &[u8]) -> Vec<StoryEvent> {
    assert_eq!(bytes.last(), Some(&b'\n'));
    let body = bytes.strip_suffix(b"\n").unwrap();
    assert!(!body.is_empty());
    body.split(|byte| *byte == b'\n')
        .map(|line| {
            assert!(!line.is_empty());
            serde_json::from_slice::<StoryEvent>(line).unwrap()
        })
        .collect()
}

#[test]
fn legacy_jsonl_for_an_empty_verified_chain_is_empty_bytes() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    assert_eq!(
        fixture
            .store
            .export_legacy_jsonl(fixture.story.story_id)
            .unwrap(),
        Vec::<u8>::new()
    );
}

#[test]
fn legacy_jsonl_is_verified_deterministic_newline_terminated_and_redacted() {
    let fixture = export_fixture();
    let first = fixture
        .store
        .export_legacy_jsonl(fixture.story.story_id)
        .unwrap();
    let second = fixture
        .store
        .export_legacy_jsonl(fixture.story.story_id)
        .unwrap();
    assert_eq!(first, second);
    assert!(
        !first
            .windows(PRIVATE_MARKER.len())
            .any(|window| { window == PRIVATE_MARKER.as_bytes() })
    );
    assert!(!String::from_utf8_lossy(&first).contains("private_arguments_json"));

    let events = parse_jsonl(&first);
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(events, evidence.events);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.sequence, u64::try_from(index + 1).unwrap());
        event.verify().unwrap();
        if index == 0 {
            assert!(event.previous_hash.is_none());
        } else {
            assert_eq!(
                event.previous_hash.as_ref().map(Sha256Digest::as_str),
                Some(events[index - 1].event_hash())
            );
        }
    }

    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let private_json: String = connection
        .query_row(
            "SELECT CAST(private_arguments_json AS TEXT) FROM operations LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(private_json.contains(PRIVATE_MARKER));
}

#[test]
fn legacy_export_rejects_an_individually_valid_event_with_a_broken_chain_link() {
    let fixture = export_fixture();
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 3);
    let original = &evidence.events[1];
    let wrong_previous = Sha256Digest::from_bytes(b"wrong-previous-event");
    assert_ne!(wrong_previous.as_str(), evidence.events[0].event_hash());
    let forged = StoryEvent::seal(
        original.obs_id,
        original.event_id,
        original.story_id,
        original.session_id,
        original.sequence,
        original.operation_id,
        original.provider.clone(),
        original.payload().clone(),
        Some(wrong_previous.clone()),
        original.recorded_at,
    );
    forged.verify().unwrap();

    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    // Simulate offline database tampering. Normal StateStore connections keep
    // foreign keys enabled and would reject this edit before export sees it.
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "UPDATE events SET previous_hash = ?1, event_hash = ?2 WHERE story_id = ?3 AND sequence = 2",
            params![
                wrong_previous.as_str(),
                forged.event_hash(),
                fixture.story.story_id.to_string(),
            ],
        )
        .unwrap();
    let error = fixture
        .store
        .export_legacy_jsonl(fixture.story.story_id)
        .unwrap_err();
    assert!(matches!(error, JournalError::Integrity(_)));
    assert!(!error.to_string().contains(PRIVATE_MARKER));
}
