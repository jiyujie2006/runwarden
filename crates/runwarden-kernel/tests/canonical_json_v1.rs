use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use serde_json::json;

#[test]
fn canonical_json_v1_matches_the_frozen_vector() {
    let material = json!({
        "story_id": "01980a8c-0000-7000-8000-000000000001",
        "session_id": "01980a8c-0000-7000-8000-000000000004",
        "event_id": "01980a8c-0000-7000-8000-000000000003",
        "sequence": 1,
        "operation_id": "01980a8c-0000-7000-8000-000000000002",
        "event_type": "policy_decision",
        "provider": "external.api.request",
        "payload": {"decision": "denied", "argument_hash": "sha256:abc"},
        "previous_hash": null,
        "recorded_at": "2026-07-10T00:00:00Z"
    });
    let digest = runwarden_kernel::evidence::hex_sha256(&canonical_json_v1(&material));

    assert_eq!(
        digest,
        "f263be6bde1a71177e0f9170cf30d22f6fe7aa50ab9c771b4a709b9903bc0ae1"
    );
}

#[test]
fn canonical_json_v1_recursively_sorts_object_keys_by_utf8_bytes() {
    let material = json!({
        "é": 5,
        "array": [{"y": 2, "x": 1}, 3],
        "ä": 4,
        "a": {"b": 2, "a": 1},
    });

    assert_eq!(
        canonical_json_v1(&material),
        "{\"a\":{\"a\":1,\"b\":2},\"array\":[{\"x\":1,\"y\":2},3],\"ä\":4,\"é\":5}".as_bytes()
    );
}

#[test]
fn sha256_digest_requires_the_frozen_text_format() {
    let digest = Sha256Digest::from_bytes(b"runwarden");
    assert_eq!(digest.as_str().len(), "sha256:".len() + 64);
    assert_eq!(
        serde_json::from_value::<Sha256Digest>(json!(digest.as_str())).unwrap(),
        digest
    );

    for invalid in [
        "0".repeat(64),
        format!("sha256:{}", "0".repeat(63)),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}g", "0".repeat(63)),
    ] {
        assert!(serde_json::from_value::<Sha256Digest>(json!(invalid)).is_err());
    }
}
