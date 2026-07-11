mod common;

use common::{JournalFixture, PRIVATE_MARKER};
use runwarden_kernel::story::EnforcementMode;
use runwarden_state::snapshots::STORY_SNAPSHOT_SQL;
use runwarden_state::{JournalError, StoryStatusUpdate};

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
