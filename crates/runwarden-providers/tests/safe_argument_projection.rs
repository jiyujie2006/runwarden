use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::SafeArgumentView;
use runwarden_kernel::resource::{DataClass, FileAccess, MemoryAccess, ResourceClaim};
use runwarden_providers::project_safe_arguments;
use serde_json::json;

#[test]
fn private_argument_material_is_replaced_by_hashes() {
    let cases = [
        (
            json!({"path":"out.txt","content":"file-secret"}),
            ResourceClaim::File {
                root: "contest-workspace".to_owned(),
                path: WorkspaceRelativePath::try_from("out.txt".to_owned()).unwrap(),
                access: FileAccess::Write,
                classification: DataClass::Internal,
            },
            vec!["file-secret"],
        ),
        (
            json!({"to":["reviewer@example.test"],"subject":"subject-secret","body":"body-secret"}),
            ResourceClaim::Email {
                recipients: vec!["reviewer@example.test".to_owned()],
                classification: DataClass::Internal,
            },
            vec!["subject-secret", "body-secret"],
        ),
        (
            json!({"method":"POST","url":"https://api.example.test/v1","body":"network-secret"}),
            ResourceClaim::Network {
                method: "POST".to_owned(),
                origin: "https://api.example.test".to_owned(),
                classification: DataClass::Internal,
            },
            vec!["network-secret"],
        ),
        (
            json!({"key":"profile","value":"store-secret"}),
            ResourceClaim::Memory {
                namespace: "session-memory".to_owned(),
                key: "profile".to_owned(),
                access: MemoryAccess::Write,
            },
            vec!["store-secret"],
        ),
    ];

    for (arguments, claim, secrets) in cases {
        let view = project_safe_arguments(&arguments, &claim).unwrap();
        let encoded = serde_json::to_string(&view).unwrap();
        for secret in secrets {
            assert!(!encoded.contains(secret), "projection leaked {secret}");
        }
    }
}

#[test]
fn projection_rejects_claim_argument_confusion_and_opaque_legacy() {
    let claim = ResourceClaim::Memory {
        namespace: "session-memory".to_owned(),
        key: "approved-key".to_owned(),
        access: MemoryAccess::Read,
    };
    assert!(project_safe_arguments(&json!({"key":"changed-key"}), &claim).is_err());

    let file = ResourceClaim::File {
        root: "contest-workspace".to_owned(),
        path: WorkspaceRelativePath::try_from("approved.txt".to_owned()).unwrap(),
        access: FileAccess::Read,
        classification: DataClass::Internal,
    };
    assert!(project_safe_arguments(&json!({"path":"changed.txt"}), &file).is_err());

    let email = ResourceClaim::Email {
        recipients: vec!["approved@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    assert!(
        project_safe_arguments(
            &json!({"to":["changed@example.test"],"body":"secret"}),
            &email
        )
        .is_err()
    );

    let network = ResourceClaim::Network {
        method: "GET".to_owned(),
        origin: "https://approved.example.test".to_owned(),
        classification: DataClass::Internal,
    };
    assert!(
        project_safe_arguments(
            &json!({"url":"https://changed.example.test/path"}),
            &network
        )
        .is_err()
    );

    let opaque = ResourceClaim::OpaqueLegacy {
        provider: "legacy".to_owned(),
        redacted_summary: "legacy".to_owned(),
    };
    assert!(project_safe_arguments(&json!({}), &opaque).is_err());
}

#[test]
fn read_views_do_not_invent_write_hashes() {
    let claim = ResourceClaim::File {
        root: "contest-workspace".to_owned(),
        path: WorkspaceRelativePath::try_from("input.txt".to_owned()).unwrap(),
        access: FileAccess::Read,
        classification: DataClass::Internal,
    };
    let view = project_safe_arguments(&json!({"path":"input.txt"}), &claim).unwrap();
    assert!(matches!(
        view,
        SafeArgumentView::File {
            content_hash: None,
            ..
        }
    ));
}
