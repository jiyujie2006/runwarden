mod common;

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::operation::SideEffectState;
use runwarden_kernel::story::{EventId, ObservationId, SecurityStory, StoryId};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEventPayload, canonical_json_v1};
use runwarden_state::{JournalError, NewStoryEvent};
use rusqlite::{Connection, params};

fn event_input(
    story: &SecurityStory,
    obs_id: ObservationId,
    event_id: EventId,
    label: &str,
    recorded_second: i64,
) -> NewStoryEvent {
    NewStoryEvent {
        obs_id,
        event_id,
        story_id: story.story_id,
        session_id: story.authority.session_id,
        operation_id: None,
        provider: None,
        payload: StoryEventPayload::InputConsumed {
            asset_id: EventCode::try_from(label.to_owned()).unwrap(),
            content_hash: Sha256Digest::from_bytes(label.as_bytes()),
        },
        recorded_at: mutation_time(story, recorded_second),
    }
}

fn append_numbered(fixture: &JournalFixture, count: usize, first_second: i64) {
    for index in 0..count {
        fixture
            .store
            .append_event(event_input(
                &fixture.story,
                ObservationId::new(),
                EventId::new(),
                &format!("ordered-{index}"),
                first_second + i64::try_from(index).unwrap(),
            ))
            .unwrap();
    }
}

fn seeded_fixture(count: usize) -> JournalFixture {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    append_numbered(&fixture, count, 1);
    fixture
}

fn assert_frame_tamper_rejected(tamper: impl FnOnce(&Connection, StoryId)) {
    let fixture = seeded_fixture(3);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    tamper(&connection, fixture.story.story_id);
    assert!(matches!(
        fixture.store.replay_frames(fixture.story.story_id, 2, 10),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture.store.story_evidence(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn pagination_is_strictly_after_sequence_ordered_and_bounded() {
    let fixture = seeded_fixture(7);
    let story_id = fixture.story.story_id;

    let first = fixture.store.events_after(story_id, 0, 3).unwrap();
    let second = fixture.store.events_after(story_id, 3, 3).unwrap();
    let final_page = fixture.store.events_after(story_id, 6, 3).unwrap();
    assert_eq!(
        first.iter().map(|event| event.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        second
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
    assert_eq!(final_page[0].sequence, 7);
    assert!(
        fixture
            .store
            .events_after(story_id, 7, 3)
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .store
            .events_after(story_id, u64::MAX, 3)
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .store
            .replay_frames(story_id, u64::MAX, 3)
            .unwrap()
            .is_empty()
    );

    let frames = fixture.store.replay_frames(story_id, 3, 3).unwrap();
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.sequence)
            .collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
    for frame in &frames {
        frame.verify().unwrap();
    }
    assert_eq!(
        fixture
            .store
            .events_after(story_id, 0, 10_000)
            .unwrap()
            .len(),
        7
    );
    assert!(fixture.store.events_after(story_id, 0, 0).is_err());
    assert!(fixture.store.events_after(story_id, 0, 10_001).is_err());
    assert!(fixture.store.replay_frames(story_id, 0, 0).is_err());
    assert!(fixture.store.replay_frames(story_id, 0, 10_001).is_err());
}

#[test]
fn duplicate_observation_and_event_ids_roll_back_without_sequence_gaps() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let obs_id = ObservationId::new();
    let event_id = EventId::new();
    let first = fixture
        .store
        .append_event(event_input(
            &fixture.story,
            obs_id,
            event_id,
            "first-unique-event",
            1,
        ))
        .unwrap();
    assert_eq!(first.event.sequence, 1);
    assert_eq!(first.story_version, 1);

    let duplicate_observation = fixture.store.append_event(event_input(
        &fixture.story,
        obs_id,
        EventId::new(),
        "duplicate-observation",
        2,
    ));
    assert!(matches!(
        duplicate_observation,
        Err(JournalError::Conflict {
            entity: "observation",
            ..
        })
    ));
    let duplicate_event = fixture.store.append_event(event_input(
        &fixture.story,
        ObservationId::new(),
        event_id,
        "duplicate-event",
        2,
    ));
    assert!(matches!(
        duplicate_event,
        Err(JournalError::Conflict {
            entity: "event",
            ..
        })
    ));

    let second = fixture
        .store
        .append_event(event_input(
            &fixture.story,
            ObservationId::new(),
            EventId::new(),
            "second-unique-event",
            3,
        ))
        .unwrap();
    assert_eq!(second.event.sequence, 2);
    assert_eq!(second.story_version, 2);
    let events = fixture
        .store
        .events_after(fixture.story.story_id, 0, 10)
        .unwrap();
    let frames = fixture
        .store
        .replay_frames(fixture.story.story_id, 0, 10)
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(frames.len(), 2);
    assert_eq!(
        events[1].previous_hash.as_ref().map(Sha256Digest::as_str),
        Some(events[0].event_hash())
    );
    assert_eq!(
        frames[1].previous_frame_hash.as_deref(),
        Some(frames[0].frame_hash.as_str())
    );
    fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .verify_structure()
        .unwrap();
}

#[test]
fn event_hash_tampering_is_rejected_by_event_and_evidence_reads() {
    let fixture = seeded_fixture(3);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection
        .execute(
            "UPDATE events SET event_hash = ?1 WHERE story_id = ?2 AND sequence = 2",
            params![
                Sha256Digest::from_bytes(b"tampered-event-hash").as_str(),
                fixture.story.story_id.to_string(),
            ],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.events_after(fixture.story.story_id, 3, 10),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture.store.story_evidence(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn frame_hash_tampering_is_rejected() {
    assert_frame_tamper_rejected(|connection, story_id| {
        connection
            .execute(
                "UPDATE story_frames SET frame_hash = ?1 WHERE story_id = ?2 AND sequence = 2",
                params![
                    Sha256Digest::from_bytes(b"tampered-frame-hash").as_str(),
                    story_id.to_string(),
                ],
            )
            .unwrap();
    });
}

#[test]
fn previous_frame_hash_tampering_is_rejected() {
    assert_frame_tamper_rejected(|connection, story_id| {
        connection
            .execute(
                "UPDATE story_frames SET previous_frame_hash = ?1 WHERE story_id = ?2 AND sequence = 2",
                params![
                    Sha256Digest::from_bytes(b"tampered-previous-frame").as_str(),
                    story_id.to_string(),
                ],
            )
            .unwrap();
    });
}

#[test]
fn intermediate_snapshot_tampering_is_rejected() {
    assert_frame_tamper_rejected(|connection, story_id| {
        let raw: String = connection
            .query_row(
                "SELECT safe_story_json FROM story_frames WHERE story_id = ?1 AND sequence = 2",
                params![story_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let mut snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
        snapshot["final_outcome_summary"] = "tampered replay snapshot".into();
        let canonical = String::from_utf8(canonical_json_v1(&snapshot)).unwrap();
        connection
            .execute(
                "UPDATE story_frames SET safe_story_json = ?1 WHERE story_id = ?2 AND sequence = 2",
                params![canonical, story_id.to_string()],
            )
            .unwrap();
    });
}

#[test]
fn frame_story_version_tampering_is_rejected() {
    assert_frame_tamper_rejected(|connection, story_id| {
        connection
            .execute(
                "UPDATE story_frames SET story_version = story_version + 7 WHERE story_id = ?1 AND sequence = 2",
                params![story_id.to_string()],
            )
            .unwrap();
    });
}

#[test]
fn standalone_append_rejects_domain_owned_execution_and_causal_events() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let attempted = fixture.store.append_event(NewStoryEvent {
        obs_id: ObservationId::new(),
        event_id: EventId::new(),
        story_id: fixture.story.story_id,
        session_id: fixture.story.authority.session_id,
        operation_id: None,
        provider: None,
        payload: StoryEventPayload::ProviderExecution {
            execution_status: EventCode::try_from("completed".to_owned()).unwrap(),
            side_effect_state: SideEffectState::Completed,
            output_hash: None,
            receipt_hash: None,
        },
        recorded_at: mutation_time(&fixture.story, 1),
    });
    assert!(matches!(
        attempted,
        Err(JournalError::InvalidTransition {
            entity: "standalone_event",
            ..
        })
    ));
    let causal = fixture.store.append_event(NewStoryEvent {
        obs_id: ObservationId::new(),
        event_id: EventId::new(),
        story_id: fixture.story.story_id,
        session_id: fixture.story.authority.session_id,
        operation_id: None,
        provider: None,
        payload: StoryEventPayload::CausalLink {
            proposal_id: None,
            status: EventCode::try_from("unresolved".to_owned()).unwrap(),
            reason_code: Some(EventCode::try_from("no_matching_proposal".to_owned()).unwrap()),
            candidate_count: 0,
        },
        recorded_at: mutation_time(&fixture.story, 1),
    });
    assert!(matches!(
        causal,
        Err(JournalError::InvalidTransition {
            entity: "standalone_event",
            ..
        })
    ));
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        0
    );
}

#[test]
fn standalone_append_rejects_non_native_and_finalized_stories() {
    let legacy = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let connection = Connection::open(legacy.state_dir.join("runwarden.db")).unwrap();
    let raw: String = connection
        .query_row(
            "SELECT safe_story_json FROM stories WHERE story_id = ?1",
            params![legacy.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut story: serde_json::Value = serde_json::from_str(&raw).unwrap();
    story["provenance"] = "legacy_derived".into();
    story["evidence_status"] = "incomplete".into();
    let rewritten = String::from_utf8(canonical_json_v1(&story)).unwrap();
    connection
        .execute(
            r#"UPDATE stories SET evidence_status = 'incomplete', safe_story_json = ?1
               WHERE story_id = ?2"#,
            params![rewritten, legacy.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        legacy.store.append_event(event_input(
            &legacy.story,
            ObservationId::new(),
            EventId::new(),
            "legacy-must-stay-eventless",
            1,
        )),
        Err(JournalError::InvalidTransition {
            entity: "story_provenance",
            ..
        })
    ));

    let verified = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let connection = Connection::open(verified.state_dir.join("runwarden.db")).unwrap();
    let raw: String = connection
        .query_row(
            "SELECT safe_story_json FROM stories WHERE story_id = ?1",
            params![verified.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut story: serde_json::Value = serde_json::from_str(&raw).unwrap();
    story["evidence_status"] = "verified".into();
    let rewritten = String::from_utf8(canonical_json_v1(&story)).unwrap();
    connection
        .execute(
            r#"UPDATE stories SET evidence_status = 'verified', safe_story_json = ?1
               WHERE story_id = ?2"#,
            params![rewritten, verified.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        verified.store.append_event(event_input(
            &verified.story,
            ObservationId::new(),
            EventId::new(),
            "verified-head-is-frozen",
            1,
        )),
        Err(JournalError::InvalidTransition {
            entity: "story_evidence",
            ..
        })
    ));
}

#[test]
fn regressing_event_time_rolls_back_without_a_sequence_gap() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let first = fixture
        .store
        .append_event(event_input(
            &fixture.story,
            ObservationId::new(),
            EventId::new(),
            "time-first",
            2,
        ))
        .unwrap();
    assert_eq!(first.event.sequence, 1);
    assert!(matches!(
        fixture.store.append_event(event_input(
            &fixture.story,
            ObservationId::new(),
            EventId::new(),
            "time-regression",
            1,
        )),
        Err(JournalError::InvalidTransition {
            entity: "event_time",
            ..
        })
    ));
    let second = fixture
        .store
        .append_event(event_input(
            &fixture.story,
            ObservationId::new(),
            EventId::new(),
            "time-second",
            3,
        ))
        .unwrap();
    assert_eq!(second.event.sequence, 2);
    assert_eq!(second.story_version, 2);
}

#[test]
fn standalone_append_refuses_to_seal_an_unframed_live_mutation() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = fixture
        .store
        .create_operation(fixture.operation(112, "send"))
        .unwrap()
        .operation;
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE operations SET state = 'policy_evaluated' WHERE operation_id = ?1",
            params![operation.operation_id.to_string()],
        )
        .unwrap();

    assert!(matches!(
        fixture.store.append_event(event_input(
            &fixture.story,
            ObservationId::new(),
            EventId::new(),
            "must-not-seal-tamper",
            2,
        )),
        Err(JournalError::Integrity(_))
    ));
    let event_rows: i64 = connection
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(event_rows, 1);
}

#[test]
fn stored_story_version_and_event_head_tampering_are_rejected() {
    let version_fixture = seeded_fixture(3);
    let connection = Connection::open(version_fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE stories SET version = version + 1 WHERE story_id = ?1",
            params![version_fixture.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        version_fixture
            .store
            .events_after(version_fixture.story.story_id, u64::MAX, 10),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        version_fixture
            .store
            .replay_frames(version_fixture.story.story_id, u64::MAX, 10),
        Err(JournalError::Integrity(_))
    ));

    let head_fixture = seeded_fixture(3);
    let connection = Connection::open(head_fixture.state_dir.join("runwarden.db")).unwrap();
    let raw: String = connection
        .query_row(
            "SELECT safe_story_json FROM stories WHERE story_id = ?1",
            params![head_fixture.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut story: serde_json::Value = serde_json::from_str(&raw).unwrap();
    story["event_count"] = 1.into();
    story["final_event_hash"] = serde_json::Value::Null;
    let tampered = String::from_utf8(canonical_json_v1(&story)).unwrap();
    connection
        .execute(
            "UPDATE stories SET safe_story_json = ?1 WHERE story_id = ?2",
            params![tampered, head_fixture.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        head_fixture
            .store
            .events_after(head_fixture.story.story_id, u64::MAX, 10),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        head_fixture
            .store
            .replay_frames(head_fixture.story.story_id, u64::MAX, 10),
        Err(JournalError::Integrity(_))
    ));

    let time_fixture = seeded_fixture(3);
    let connection = Connection::open(time_fixture.state_dir.join("runwarden.db")).unwrap();
    let forged_time = mutation_time(&time_fixture.story, 10)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    connection
        .execute(
            "UPDATE stories SET updated_at = ?1 WHERE story_id = ?2",
            params![forged_time, time_fixture.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        time_fixture
            .store
            .events_after(time_fixture.story.story_id, u64::MAX, 10),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn replay_snapshots_never_embed_event_history_or_private_arguments() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = fixture
        .store
        .create_operation(fixture.operation(111, "send"))
        .unwrap()
        .operation;
    append_numbered(&fixture, 2, 2);

    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let private_json: String = connection
        .query_row(
            "SELECT CAST(private_arguments_json AS TEXT) FROM operations WHERE operation_id = ?1",
            params![operation.operation_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(private_json.contains(PRIVATE_MARKER));

    let frames = fixture
        .store
        .replay_frames(fixture.story.story_id, 0, 10)
        .unwrap();
    assert_eq!(frames.len(), 3);
    for frame in &frames {
        let snapshot = serde_json::to_value(&frame.story).unwrap();
        assert!(snapshot.get("events").is_none());
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains(PRIVATE_MARKER)
        );
    }
    let mut statement = connection
        .prepare("SELECT safe_story_json FROM story_frames WHERE story_id = ?1 ORDER BY sequence")
        .unwrap();
    let rows = statement
        .query_map(params![fixture.story.story_id.to_string()], |row| {
            row.get::<_, String>(0)
        })
        .unwrap();
    for row in rows {
        let raw = row.unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(snapshot.get("events").is_none());
        assert!(!raw.contains(PRIVATE_MARKER));
    }
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}
