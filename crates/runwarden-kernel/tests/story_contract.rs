use runwarden_kernel::story::{
    ApprovalId, EnforcementMode, EventId, EvidenceStatus, ExecutionLeaseId, InvocationKey,
    ObservationId, OperationId, RunMode, SECURITY_STORY_SCHEMA_VERSION, SessionId, StoryId,
};

#[test]
fn story_ids_are_uuid_v7_strings() {
    let id = StoryId::new();
    assert_eq!(id.as_uuid().get_version_num(), 7);
    let json = serde_json::to_string(&id).expect("story id serializes");
    assert_eq!(json.len(), 38);
    assert!(json.starts_with('"') && json.ends_with('"'));
}

#[test]
fn ids_reject_non_v7_uuid_strings() {
    let v4 = "00000000-0000-4000-8000-000000000000";
    assert!(serde_json::from_str::<StoryId>(&format!("\"{v4}\"")).is_err());
    assert!(
        serde_json::from_str::<ObservationId>("\"obs_00000000-0000-4000-8000-000000000000\"")
            .is_err()
    );
}

#[test]
fn story_modes_and_evidence_states_use_snake_case() {
    assert_eq!(serde_json::to_value(RunMode::Recorded).unwrap(), "recorded");
    assert_eq!(
        serde_json::to_value(EvidenceStatus::Incomplete).unwrap(),
        "incomplete"
    );
}

#[test]
fn all_typed_uuid_identifiers_round_trip_as_v7_strings() {
    macro_rules! assert_id_contract {
        ($id:expr, $type:ty) => {{
            let id: $type = $id;
            assert_eq!(id.as_uuid().get_version_num(), 7);
            assert_eq!(id.to_string(), id.as_uuid().to_string());

            let json = serde_json::to_string(&id).expect("identifier serializes");
            let round_trip: $type = serde_json::from_str(&json).expect("identifier deserializes");
            assert_eq!(round_trip, id);
        }};
    }

    assert_id_contract!(StoryId::new(), StoryId);
    assert_id_contract!(SessionId::new(), SessionId);
    assert_id_contract!(OperationId::new(), OperationId);
    assert_id_contract!(EventId::new(), EventId);
    assert_id_contract!(ApprovalId::new(), ApprovalId);
    assert_id_contract!(ExecutionLeaseId::new(), ExecutionLeaseId);
}

#[test]
fn observation_ids_use_the_obs_prefix_and_round_trip() {
    let id = ObservationId::new();
    let rendered = id.to_string();
    assert_eq!(rendered.len(), 40);
    assert!(rendered.starts_with("obs_"));

    let json = serde_json::to_string(&id).expect("observation id serializes");
    assert_eq!(json, format!("\"{rendered}\""));
    assert_eq!(
        serde_json::from_str::<ObservationId>(&json).expect("observation id deserializes"),
        id
    );
    assert!(
        serde_json::from_str::<ObservationId>("\"01900000-0000-7000-8000-000000000000\"").is_err()
    );
}

#[test]
fn invocation_keys_are_validated_lowercase_hmac_strings() {
    let key = InvocationKey::from_hmac_bytes([0xab; 32]);
    let expected = format!("inv_{}", "ab".repeat(32));
    assert_eq!(key.as_str(), expected);
    assert_eq!(serde_json::to_value(&key).unwrap(), expected);
    assert_eq!(
        serde_json::from_value::<InvocationKey>(expected.clone().into()).unwrap(),
        key
    );

    for invalid in [
        "ab".repeat(32),
        format!("inv_{}", "ab".repeat(31)),
        format!("inv_{}", "AB".repeat(32)),
        format!("inv_{}g", "ab".repeat(31)),
    ] {
        assert!(serde_json::from_value::<InvocationKey>(invalid.into()).is_err());
    }
}

#[test]
fn story_contract_version_and_remaining_enums_are_frozen() {
    assert_eq!(SECURITY_STORY_SCHEMA_VERSION, "1.0.0");
    assert_eq!(serde_json::to_value(RunMode::Live).unwrap(), "live");
    assert_eq!(
        serde_json::to_value(RunMode::Deterministic).unwrap(),
        "deterministic"
    );
    assert_eq!(
        serde_json::to_value(EnforcementMode::MonitorOnly).unwrap(),
        "monitor_only"
    );
    assert_eq!(
        serde_json::to_value(EnforcementMode::Enforced).unwrap(),
        "enforced"
    );
    assert_eq!(
        serde_json::to_value(EvidenceStatus::Pending).unwrap(),
        "pending"
    );
    assert_eq!(
        serde_json::to_value(EvidenceStatus::Verified).unwrap(),
        "verified"
    );
    assert_eq!(
        serde_json::to_value(EvidenceStatus::Invalid).unwrap(),
        "invalid"
    );
}
