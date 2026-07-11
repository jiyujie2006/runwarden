use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::resource::{
    DataClass, ExecutionLimits, FileAccess, MemoryAccess, NetworkCapability, ResourceClaim,
};
use runwarden_kernel::session::{
    ArtifactAuthority, AuthoritySnapshot, BudgetCharge, BudgetSnapshot, BudgetUsageSnapshot,
    CodeAuthority, EmailAuthority, EvidenceAuthority, FileAuthority, InputAuthority,
    NetworkAuthority, StoreAuthority,
};
use runwarden_kernel::story::{OperationId, SessionId};
use serde_json::json;
use time::OffsetDateTime;

#[test]
fn equivalent_file_claims_have_a_stable_digest() {
    let claim = ResourceClaim::File {
        root: "workspace".to_string(),
        path: WorkspaceRelativePath::try_from("reports/q2.md".to_string()).unwrap(),
        access: FileAccess::Read,
        classification: DataClass::Internal,
    };

    assert_eq!(claim.digest(), claim.clone().digest());
    assert!(claim.digest().as_str().starts_with("sha256:"));
}

#[test]
fn changed_resource_changes_the_claim_digest() {
    let first = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_string()],
        classification: DataClass::Internal,
    };
    let second = ResourceClaim::Email {
        recipients: vec!["attacker@example.test".to_string()],
        classification: DataClass::Internal,
    };

    assert_ne!(first.digest(), second.digest());
}

#[test]
fn workspace_relative_paths_round_trip_as_normalized_strings() {
    let path = WorkspaceRelativePath::try_from("reports/2026/q2.md".to_string()).unwrap();

    assert_eq!(path.as_str(), "reports/2026/q2.md");
    assert_eq!(
        serde_json::to_value(&path).unwrap(),
        json!("reports/2026/q2.md")
    );
    assert_eq!(
        serde_json::from_value::<WorkspaceRelativePath>(json!("reports/2026/q2.md")).unwrap(),
        path
    );
}

#[test]
fn workspace_relative_paths_reject_unsafe_lexical_forms() {
    for invalid in [
        "",
        "/absolute/path",
        "reports\\q2.md",
        "C:/reports/q2.md",
        "C:reports/q2.md",
        "reports//q2.md",
        "./reports/q2.md",
        "reports/./q2.md",
        "../reports/q2.md",
        "reports/../q2.md",
        "reports/q2.md/",
        "reports/\0q2.md",
        "reports\n/../q2.md",
        "reports\r/./q2.md",
        "reports\u{2028}/../q2.md",
        "reports\u{2029}/./q2.md",
        "reports/q2.md\n",
        "reports/q2.md\r",
        "reports/q2.md\u{2028}",
        "reports/q2.md\u{2029}",
    ] {
        assert!(
            WorkspaceRelativePath::try_from(invalid.to_string()).is_err(),
            "{invalid:?} must be rejected"
        );
        assert!(
            serde_json::from_value::<WorkspaceRelativePath>(json!(invalid)).is_err(),
            "deserialization must reject {invalid:?}"
        );
    }
}

#[test]
fn data_class_order_is_explicit() {
    assert!(DataClass::Public.is_within(&DataClass::Public));
    assert!(DataClass::Internal.is_within(&DataClass::Confidential));
    assert!(!DataClass::Restricted.is_within(&DataClass::Confidential));
}

#[test]
fn resource_claims_reject_unknown_variant_fields() {
    assert!(
        serde_json::from_value::<ResourceClaim>(json!({
            "kind": "email",
            "recipients": ["finance@example.test"],
            "classification": "internal",
            "caller_override": true
        }))
        .is_err()
    );
}

#[test]
fn execution_limits_reject_unknown_fields() {
    assert!(
        serde_json::from_value::<ExecutionLimits>(json!({
            "wall_time_ms": 1_000,
            "cpu_time_ms": 500,
            "memory_bytes": 67_108_864,
            "output_bytes": 4_096,
            "process_count": 1,
            "unbounded": true
        }))
        .is_err()
    );
}

#[test]
fn authority_snapshot_round_trips_typed_boundaries_and_separate_budgets() {
    let operation_id = OperationId::new();
    let snapshot = AuthoritySnapshot {
        session_id: SessionId::new(),
        actor_id: "agent-1".to_string(),
        authz_id: "authz-1".to_string(),
        authz_state: "active".to_string(),
        expires_at: OffsetDateTime::from_unix_timestamp(1_784_160_000).unwrap(),
        allowed_providers: vec!["external.api.request".to_string()],
        files: vec![FileAuthority {
            root: "workspace".to_string(),
            path_prefix: "reports".to_string(),
            access: vec![FileAccess::Read, FileAccess::Write],
            maximum_classification: DataClass::Confidential,
        }],
        networks: vec![NetworkAuthority {
            provider: "external.api.request".to_string(),
            allowed_origins: vec!["https://api.example.test".to_string()],
            maximum_classification: DataClass::Internal,
        }],
        email: Some(EmailAuthority {
            allowed_recipients: vec!["reviewer@example.test".to_string()],
            maximum_classification: DataClass::Internal,
        }),
        stores: vec![StoreAuthority {
            namespace: "assessment".to_string(),
            key_prefix: "story/".to_string(),
            access: vec![MemoryAccess::Read],
        }],
        code: Some(CodeAuthority {
            allowed_runtimes: vec!["python3".to_string()],
            workspace: "sandbox".to_string(),
            network: NetworkCapability::None,
            maximum_limits: ExecutionLimits {
                wall_time_ms: 1_000,
                cpu_time_ms: 500,
                memory_bytes: 64 * 1024 * 1024,
                output_bytes: 4_096,
                process_count: 1,
            },
        }),
        inputs: vec![InputAuthority {
            allowed_sources: vec!["scenario.prompt".to_string()],
            maximum_classification: DataClass::Restricted,
        }],
        evidence: EvidenceAuthority {
            current_story_only: true,
            allowed_operations: vec![operation_id],
        },
        artifacts: vec![ArtifactAuthority {
            path_prefix: WorkspaceRelativePath::try_from("exports/stories".to_string()).unwrap(),
            allowed_formats: vec!["json".to_string()],
        }],
        budgets: BudgetSnapshot {
            max_argument_bytes: 1_024,
            max_file_bytes: 2_048,
            max_network_bytes: 4_096,
            max_calls: 8,
            max_wall_time_ms: 2_000,
            max_model_calls: 3,
            max_model_input_bytes: 8_192,
            max_model_output_bytes: 1_024,
        },
        policy_snapshot_hash: "sha256:policy".to_string(),
    };

    let value = serde_json::to_value(&snapshot).unwrap();
    assert_eq!(value["files"][0]["maximum_classification"], "confidential");
    assert_eq!(value["artifacts"][0]["path_prefix"], "exports/stories");
    assert_eq!(value["budgets"]["max_argument_bytes"], 1_024);
    assert_eq!(value["budgets"]["max_calls"], 8);
    assert_eq!(value["budgets"]["max_model_calls"], 3);
    assert_eq!(
        serde_json::from_value::<AuthoritySnapshot>(value).unwrap(),
        snapshot
    );
}

#[test]
fn authority_and_usage_views_reject_ambiguous_or_unknown_fields() {
    let usage = BudgetUsageSnapshot {
        version: 7,
        calls_reserved: 2,
        calls_committed: 1,
        file_bytes_reserved: 200,
        file_bytes_committed: 100,
        network_bytes_reserved: 400,
        network_bytes_committed: 300,
    };
    let charge = BudgetCharge {
        calls: 1,
        file_bytes: 100,
        network_bytes: 300,
    };

    assert_eq!(serde_json::to_value(usage).unwrap()["calls_reserved"], 2);
    assert_eq!(serde_json::to_value(charge).unwrap()["network_bytes"], 300);
    assert!(
        serde_json::from_value::<BudgetUsageSnapshot>(json!({
            "version": 7,
            "calls_reserved": 2,
            "calls_committed": 1,
            "file_bytes_reserved": 200,
            "file_bytes_committed": 100,
            "network_bytes_reserved": 400,
            "network_bytes_committed": 300,
            "caller_override": true
        }))
        .is_err()
    );
}
