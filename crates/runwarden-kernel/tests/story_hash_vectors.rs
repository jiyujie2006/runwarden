use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::session::{AuthoritySnapshot, BudgetSnapshot, EvidenceAuthority};
use runwarden_kernel::story::{
    EnforcementMode, EventId, EvidenceStatus, ObservationId, OperationId, RunMode, SchemaVersion,
    SecurityStory, SessionId, StoryEvidenceView, StoryId, StoryIdentity, StoryProvenance,
    StoryReplayFrame, StoryStatus,
};
use runwarden_kernel::trace::{
    EventCode, Sha256Digest, StoryEvent, StoryEventPayload, canonical_json_v1,
};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

fn event_id(suffix: u8) -> EventId {
    EventId::try_from(Uuid::parse_str(&format!("01980a8c-0000-7000-8000-{suffix:012x}")).unwrap())
        .unwrap()
}

fn observation_id(suffix: u8) -> ObservationId {
    ObservationId::try_from(format!("obs_01980a8c-0000-7000-8000-{suffix:012x}").as_str()).unwrap()
}

fn story_id() -> StoryId {
    StoryId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000001").unwrap()).unwrap()
}

fn operation_id() -> OperationId {
    OperationId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000002").unwrap()).unwrap()
}

fn session_id() -> SessionId {
    SessionId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000004").unwrap()).unwrap()
}

fn at(raw: &str) -> OffsetDateTime {
    OffsetDateTime::parse(raw, &Rfc3339).unwrap()
}

fn policy_payload() -> StoryEventPayload {
    StoryEventPayload::PolicyDecision {
        decision: PolicyDecision::Denied,
        reason_code: EventCode::try_from("egress_denied".to_string()).unwrap(),
        policy_snapshot_hash: Sha256Digest::try_from(format!("sha256:{}", "a".repeat(64))).unwrap(),
    }
}

fn policy_event(
    sequence: u64,
    suffix: u8,
    previous_hash: Option<Sha256Digest>,
    recorded_at: OffsetDateTime,
) -> StoryEvent {
    StoryEvent::seal(
        observation_id(suffix + 2),
        event_id(suffix),
        story_id(),
        session_id(),
        sequence,
        Some(operation_id()),
        Some(EventCode::try_from("external.api.request".to_string()).unwrap()),
        policy_payload(),
        previous_hash,
        recorded_at,
    )
}

fn fixed_policy_event() -> StoryEvent {
    policy_event(1, 3, None, at("2026-07-10T00:00:00Z"))
}

fn rehash_exported_event(event: &mut serde_json::Value) {
    let mut material = event.clone();
    material
        .as_object_mut()
        .unwrap()
        .remove("event_hash")
        .unwrap();
    event["event_hash"] =
        serde_json::to_value(Sha256Digest::from_bytes(&canonical_json_v1(&material))).unwrap();
}

fn story(event_count: u64, final_event_hash: &str) -> SecurityStory {
    SecurityStory {
        schema_version: SchemaVersion::current(),
        story_id: story_id(),
        title: "sealed story".to_string(),
        scenario_id: "redacted-event-vector".to_string(),
        attack_category: "prompt_injection".to_string(),
        run_mode: RunMode::Deterministic,
        enforcement_mode: EnforcementMode::Enforced,
        provenance: StoryProvenance::Native,
        status: StoryStatus::BlockedBeforeSideEffect,
        evidence_status: EvidenceStatus::Verified,
        identity: StoryIdentity {
            agent_id: "agent-1".to_string(),
            model_id: "model-1".to_string(),
            actor_id: "actor-1".to_string(),
            reviewer_id: None,
        },
        authority: AuthoritySnapshot {
            session_id: session_id(),
            actor_id: "actor-1".to_string(),
            authz_id: "authz-1".to_string(),
            authz_state: "active".to_string(),
            expires_at: at("2026-07-10T01:00:00Z"),
            allowed_providers: vec!["external.api.request".to_string()],
            files: Vec::new(),
            networks: Vec::new(),
            email: None,
            stores: Vec::new(),
            code: None,
            inputs: Vec::new(),
            evidence: EvidenceAuthority {
                current_story_only: true,
                allowed_operations: vec![operation_id()],
            },
            artifacts: Vec::new(),
            budgets: BudgetSnapshot {
                max_argument_bytes: 1,
                max_file_bytes: 0,
                max_network_bytes: 0,
                max_calls: 1,
                max_wall_time_ms: 1,
                max_model_calls: 0,
                max_model_input_bytes: 0,
                max_model_output_bytes: 0,
            },
            policy_snapshot_hash: format!("sha256:{}", "a".repeat(64)),
        },
        safe_attack_preview: "redacted".to_string(),
        attack_content_hash: Sha256Digest::from_bytes(b"attack").as_str().to_string(),
        stage_statuses: Vec::new(),
        operations: Vec::new(),
        event_count,
        report_claims: Vec::new(),
        final_outcome_summary: "blocked".to_string(),
        final_event_hash: Some(final_event_hash.to_string()),
    }
}

fn fixed_evidence_view() -> StoryEvidenceView {
    let first = fixed_policy_event();
    let second = policy_event(
        2,
        6,
        Some(Sha256Digest::try_from(first.event_hash().to_string()).unwrap()),
        at("2026-07-10T00:00:01Z"),
    );
    let first_story = story(1, first.event_hash());
    let final_story = story(2, second.event_hash());
    let first_frame = StoryReplayFrame::seal(
        1,
        1,
        first.event_hash().to_string(),
        None,
        at("2026-07-10T00:00:00Z"),
        first_story,
    )
    .unwrap();
    let second_frame = StoryReplayFrame::seal(
        2,
        2,
        second.event_hash().to_string(),
        Some(first_frame.frame_hash.clone()),
        at("2026-07-10T00:00:01Z"),
        final_story.clone(),
    )
    .unwrap();

    StoryEvidenceView {
        story: final_story,
        events: vec![first, second],
        replay_frames: vec![first_frame, second_frame],
    }
}

#[test]
fn payload_deserialization_rejects_unknown_or_raw_fields() {
    for invalid in [
        json!({"kind":"policy_decision","decision":"denied","prompt":"secret"}),
        json!({"kind":"policy_decision","decision":"denied","headers":{"x":"secret"}}),
        json!({"kind":"policy_decision","decision":"denied","extra":[{"query":"secret"}]}),
    ] {
        assert!(serde_json::from_value::<StoryEventPayload>(invalid).is_err());
    }

    let valid_fields = json!({
        "kind": "policy_decision",
        "decision": "denied",
        "reason_code": "egress_denied",
        "policy_snapshot_hash": format!("sha256:{}", "a".repeat(64)),
    });
    for (field, raw_value) in [
        ("prompt", json!("secret")),
        ("headers", json!({"x": "secret"})),
        ("extra", json!([{"query": "secret"}])),
    ] {
        let mut invalid = valid_fields.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), raw_value);
        assert!(serde_json::from_value::<StoryEventPayload>(invalid).is_err());
    }
}

#[test]
fn event_codes_validate_construction_and_deserialization() {
    let valid = EventCode::try_from("Az09.:/@_-".to_string()).unwrap();
    assert_eq!(valid.as_str(), "Az09.:/@_-");
    assert_eq!(
        serde_json::from_value::<EventCode>(json!(valid.as_str())).unwrap(),
        valid
    );
    let maximum = EventCode::try_from("x".repeat(128)).unwrap();
    assert_eq!(maximum.as_str().len(), 128);

    for invalid in [
        String::new(),
        "contains space".to_string(),
        "non-ascii-é".to_string(),
        "x".repeat(129),
        "allowed\n".to_string(),
        "allowed\r".to_string(),
        "allowed\u{2028}".to_string(),
        "allowed\u{2029}".to_string(),
    ] {
        assert!(EventCode::try_from(invalid.clone()).is_err());
        assert!(serde_json::from_value::<EventCode>(json!(invalid)).is_err());
    }
}

#[test]
fn sealed_event_uses_rfc3339_hash_material_and_detects_change() {
    let event = fixed_policy_event();
    assert!(event.verify().is_ok());
    assert_eq!(
        event.event_hash(),
        "sha256:6ef820788694fc3cbf998b9ece8460273c3736db792a703899f2a4c89449a42f"
    );

    let mut exported = serde_json::to_value(&event).unwrap();
    assert_eq!(exported["recorded_at"], json!("2026-07-10T00:00:00Z"));
    let event_hash = exported
        .as_object_mut()
        .unwrap()
        .remove("event_hash")
        .unwrap();
    assert_eq!(
        event_hash,
        json!(Sha256Digest::from_bytes(&canonical_json_v1(&exported)).as_str())
    );

    let mut changed = serde_json::to_value(&event).unwrap();
    changed["payload"]["decision"] = json!("allowed");
    let changed: StoryEvent = serde_json::from_value(changed).unwrap();
    assert!(changed.verify().is_err());
}

#[test]
fn event_deserialization_rejects_unknown_envelope_fields() {
    for (field, raw_value) in [
        ("prompt", json!("secret")),
        ("headers", json!({"authorization": "secret"})),
        ("extra", json!([{"query": "secret"}])),
    ] {
        let mut event = serde_json::to_value(fixed_policy_event()).unwrap();
        event
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), raw_value);
        assert!(serde_json::from_value::<StoryEvent>(event).is_err());
    }
}

#[test]
fn verify_rejects_rehashed_event_type_payload_mismatch() {
    let mut forged = serde_json::to_value(fixed_policy_event()).unwrap();
    forged["event_type"] = json!("provider_execution");
    rehash_exported_event(&mut forged);

    let forged: StoryEvent = serde_json::from_value(forged).unwrap();
    assert!(forged.verify().is_err());
}

#[test]
fn event_hash_commits_observation_and_previous_hash() {
    let view = fixed_evidence_view();
    let second = &view.events[1];

    let mut changed_observation = serde_json::to_value(second).unwrap();
    changed_observation["obs_id"] = json!(observation_id(9).to_string());
    let changed_observation: StoryEvent = serde_json::from_value(changed_observation).unwrap();
    assert!(changed_observation.verify().is_err());

    let mut changed_previous = serde_json::to_value(second).unwrap();
    changed_previous["previous_hash"] = json!(Sha256Digest::from_bytes(b"changed previous"));
    let changed_previous: StoryEvent = serde_json::from_value(changed_previous).unwrap();
    assert!(changed_previous.verify().is_err());
}

#[test]
fn evidence_view_verifies_event_and_frame_chains() {
    fixed_evidence_view().verify_structure().unwrap();
}

#[test]
fn evidence_view_rejects_tampered_links_and_sequence_gaps() {
    let mut broken_event_link = fixed_evidence_view();
    broken_event_link.events[1] = policy_event(
        2,
        6,
        Some(Sha256Digest::from_bytes(b"wrong previous event")),
        at("2026-07-10T00:00:01Z"),
    );
    assert!(broken_event_link.verify_structure().is_err());

    let mut broken_frame_link = fixed_evidence_view();
    let final_story = broken_frame_link.story.clone();
    broken_frame_link.replay_frames[1] = StoryReplayFrame::seal(
        2,
        2,
        broken_frame_link.events[1].event_hash().to_string(),
        Some(
            Sha256Digest::from_bytes(b"wrong previous frame")
                .as_str()
                .to_string(),
        ),
        at("2026-07-10T00:00:01Z"),
        final_story,
    )
    .unwrap();
    assert!(broken_frame_link.verify_structure().is_err());

    let mut event_gap = fixed_evidence_view();
    let first_hash = event_gap.events[0].event_hash().to_string();
    event_gap.events[1] = policy_event(
        3,
        6,
        Some(Sha256Digest::try_from(first_hash).unwrap()),
        at("2026-07-10T00:00:01Z"),
    );
    assert!(event_gap.verify_structure().is_err());

    let mut frame_gap = fixed_evidence_view();
    frame_gap.replay_frames[1].sequence = 3;
    assert!(frame_gap.verify_structure().is_err());
}

#[test]
fn evidence_view_anchors_final_event_hash_to_chain_tail() {
    let mut mismatched = fixed_evidence_view();
    mismatched.story.final_event_hash = Some(
        Sha256Digest::from_bytes(b"wrong final event")
            .as_str()
            .to_string(),
    );
    mismatched.replay_frames[1] = StoryReplayFrame::seal(
        2,
        2,
        mismatched.events[1].event_hash().to_string(),
        Some(mismatched.replay_frames[0].frame_hash.clone()),
        at("2026-07-10T00:00:01Z"),
        mismatched.story.clone(),
    )
    .unwrap();
    assert!(mismatched.verify_structure().is_err());

    let placeholder_hash = Sha256Digest::from_bytes(b"no event");
    let mut empty_story = story(0, placeholder_hash.as_str());
    let mut empty = StoryEvidenceView {
        story: empty_story.clone(),
        events: Vec::new(),
        replay_frames: Vec::new(),
    };
    assert!(empty.verify_structure().is_err());

    empty_story.final_event_hash = None;
    empty.story = empty_story;
    empty.verify_structure().unwrap();
}

#[test]
fn evidence_view_rejects_resealed_frame_with_wrong_aggregate_event_count() {
    let mut mismatched = fixed_evidence_view();
    let mut first_story = mismatched.replay_frames[0].story.clone();
    first_story.event_count = 2;
    let first_frame = StoryReplayFrame::seal(
        1,
        1,
        mismatched.events[0].event_hash().to_string(),
        None,
        at("2026-07-10T00:00:00Z"),
        first_story,
    )
    .unwrap();
    let second_frame = StoryReplayFrame::seal(
        2,
        2,
        mismatched.events[1].event_hash().to_string(),
        Some(first_frame.frame_hash.clone()),
        at("2026-07-10T00:00:01Z"),
        mismatched.story.clone(),
    )
    .unwrap();
    mismatched.replay_frames = vec![first_frame, second_frame];

    assert!(mismatched.verify_structure().is_err());
}

#[test]
fn evidence_view_rejects_resealed_frame_with_wrong_aggregate_final_event_hash() {
    let mut mismatched = fixed_evidence_view();
    let mut first_story = mismatched.replay_frames[0].story.clone();
    first_story.final_event_hash = Some(
        Sha256Digest::from_bytes(b"wrong frame event")
            .as_str()
            .to_string(),
    );
    let first_frame = StoryReplayFrame::seal(
        1,
        1,
        mismatched.events[0].event_hash().to_string(),
        None,
        at("2026-07-10T00:00:00Z"),
        first_story,
    )
    .unwrap();
    let second_frame = StoryReplayFrame::seal(
        2,
        2,
        mismatched.events[1].event_hash().to_string(),
        Some(first_frame.frame_hash.clone()),
        at("2026-07-10T00:00:01Z"),
        mismatched.story.clone(),
    )
    .unwrap();
    mismatched.replay_frames = vec![first_frame, second_frame];

    assert!(mismatched.verify_structure().is_err());
}
