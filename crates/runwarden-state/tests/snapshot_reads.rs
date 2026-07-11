mod common;

use common::{JournalFixture, PRIVATE_MARKER};
use runwarden_kernel::story::EnforcementMode;
use runwarden_kernel::trace::canonical_json_v1;
use runwarden_state::snapshots::STORY_SNAPSHOT_SQL;
use runwarden_state::{JournalError, StoryStatusUpdate};
use rusqlite::{Connection, params};

#[test]
fn snapshot_query_and_output_are_private_material_free() {
    assert!(!STORY_SNAPSHOT_SQL.contains("private_arguments_json"));
    assert!(!STORY_SNAPSHOT_SQL.contains("policy_reason"));
    assert!(!STORY_SNAPSHOT_SQL.contains("invocation_key"));

    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    fixture
        .store
        .create_operation(fixture.operation(4, "send"))
        .unwrap();
    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    assert_eq!(snapshot.event_count, 1);
    assert!(snapshot.final_event_hash.is_some());
    assert_eq!(snapshot.operations.len(), 1);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}

#[test]
fn empty_story_snapshot_and_evidence_are_coherent() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    assert_eq!(snapshot.event_count, 0);
    assert!(snapshot.final_event_hash.is_none());
    assert!(snapshot.operations.is_empty());
    fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .verify_structure()
        .unwrap();
}

#[test]
fn snapshot_order_is_event_order_and_unframed_status_updates_are_rejected() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let first = fixture
        .store
        .create_operation(fixture.operation(20, "send_first"))
        .unwrap()
        .operation;
    let second = fixture
        .store
        .create_operation(fixture.operation(21, "send_second"))
        .unwrap()
        .operation;
    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    assert_eq!(snapshot.operations[0].operation_id, first.operation_id);
    assert_eq!(snapshot.operations[1].operation_id, second.operation_id);
    assert_eq!(snapshot.event_count, 2);

    assert!(matches!(
        fixture.store.update_story_status(StoryStatusUpdate {
            story_id: fixture.story.story_id,
            expected_version: 2,
            status: runwarden_kernel::story::StoryStatus::Failed,
            evidence_status: runwarden_kernel::story::EvidenceStatus::Incomplete,
            final_outcome_summary: "unframed".to_owned(),
            now: common::mutation_time(&fixture.story, 3),
        }),
        Err(JournalError::InvalidTransition {
            entity: "story_after_event",
            ..
        })
    ));
    assert_eq!(
        fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap(),
        snapshot
    );
}

#[test]
fn relational_event_rows_cannot_be_hidden_to_enable_an_unframed_story_cas() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    fixture
        .store
        .create_operation(fixture.operation(60, "send"))
        .unwrap();
    let original = fixture.store.story(fixture.story.story_id).unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let raw: String = connection
        .query_row(
            "SELECT safe_story_json FROM stories WHERE story_id = ?1",
            params![fixture.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut forged: serde_json::Value = serde_json::from_str(&raw).unwrap();
    forged["event_count"] = serde_json::json!(0);
    forged["final_event_hash"] = serde_json::Value::Null;
    let forged = String::from_utf8(canonical_json_v1(&forged)).unwrap();
    connection
        .execute(
            "UPDATE stories SET safe_story_json = ?1 WHERE story_id = ?2",
            params![forged, fixture.story.story_id.to_string()],
        )
        .unwrap();

    assert!(matches!(
        fixture.store.update_story_status(StoryStatusUpdate {
            story_id: fixture.story.story_id,
            expected_version: 1,
            status: runwarden_kernel::story::StoryStatus::Failed,
            evidence_status: runwarden_kernel::story::EvidenceStatus::Incomplete,
            final_outcome_summary: "forged zero".to_owned(),
            now: common::mutation_time(&fixture.story, 2),
        }),
        Err(JournalError::InvalidTransition {
            entity: "story_after_event",
            ..
        })
    ));
    assert_eq!(
        fixture.store.story(fixture.story.story_id).unwrap(),
        original
    );
    let version: i64 = connection
        .query_row(
            "SELECT version FROM stories WHERE story_id = ?1",
            params![fixture.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 1);

    let mut invalid_hash: serde_json::Value = serde_json::from_str(&raw).unwrap();
    invalid_hash["final_event_hash"] = serde_json::json!("not-a-digest");
    let invalid_hash = String::from_utf8(canonical_json_v1(&invalid_hash)).unwrap();
    connection
        .execute(
            "UPDATE stories SET safe_story_json = ?1 WHERE story_id = ?2",
            params![invalid_hash, fixture.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.story(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn an_unframed_report_claim_on_an_empty_story_is_rejected() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let claim = serde_json::json!({
        "claim_id": "fabricated-empty-claim",
        "text": "This claim has no committed observation.",
        "observation_refs": [runwarden_kernel::story::ObservationId::new()],
        "support_expectation": {
            "provider": "email.send"
        }
    });
    let claim = String::from_utf8(canonical_json_v1(&claim)).unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            r#"INSERT INTO report_claims (story_id, claim_id, claim_json)
               VALUES (?1, 'fabricated-empty-claim', ?2)"#,
            params![fixture.story.story_id.to_string(), claim],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.story_snapshot(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture.store.story_evidence(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
}
