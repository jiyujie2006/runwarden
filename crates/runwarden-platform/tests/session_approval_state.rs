use std::path::PathBuf;

use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::manifest::{
    ActiveAssessmentManifest, ActorManifest, AssessmentManifest, AuthorizationManifest,
    AuthzManifestState, BudgetManifest, RootManifest, SessionManifest, TargetManifest,
};
use runwarden_platform::{
    ApprovalListFilter, RunwardenPlatform, validate_record_id, validate_session_id,
};

fn assessment_manifest() -> AssessmentManifest {
    AssessmentManifest {
        version: "0.1".to_string(),
        name: "enterprise-agent-security".to_string(),
        mode: "offline".to_string(),
        provider_allowlist: vec![
            "runwarden.input.inspect".to_string(),
            "runwarden.evidence.inspect".to_string(),
        ],
        roots: vec![RootManifest {
            name: "workspace".to_string(),
            path: PathBuf::from("/srv/runwarden/workspace"),
        }],
        targets: vec![TargetManifest {
            name: "environment".to_string(),
            value: "enterprise_ops".to_string(),
        }],
        budgets: BudgetManifest {
            max_argument_bytes: Some(4096),
        },
        authorization: Some(AuthorizationManifest {
            id: "authz-active".to_string(),
            state: AuthzManifestState::Active,
        }),
        actor: Some(ActorManifest {
            id: "agent-1".to_string(),
        }),
        active_assessment: ActiveAssessmentManifest { enabled: true },
    }
}

fn session_manifest(session_id: &str) -> SessionManifest {
    SessionManifest::from_assessment(session_id, &assessment_manifest())
}

fn approval_record(approval_id: &str) -> ApprovalRecord {
    ApprovalRecord::new(
        approval_id,
        ApprovalBinding {
            session_id: "enterprise_ops".to_string(),
            provider: "external.mcp.browser.open_page".to_string(),
            action: "open_page".to_string(),
            argument_hash: "arg_hash_1".to_string(),
            authz_id: Some("authz-active".to_string()),
            actor_id: Some("agent-1".to_string()),
        },
    )
}

#[test]
fn platform_persists_and_reads_sessions_under_state_directory() {
    let workspace = tempfile::tempdir().expect("workspace");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");
    let enterprise = session_manifest("enterprise_ops");
    let alpha = session_manifest("alpha_ops");

    platform
        .write_session(&enterprise)
        .expect("write enterprise");
    platform.write_session(&alpha).expect("write alpha");

    let loaded = platform
        .read_session("enterprise_ops")
        .expect("read session");
    assert_eq!(loaded, enterprise);
    assert!(
        workspace
            .path()
            .join(".runwarden/sessions/enterprise_ops.json")
            .is_file()
    );
    assert_eq!(
        platform
            .list_sessions()
            .expect("list sessions")
            .into_iter()
            .map(|session| session.session_id)
            .collect::<Vec<_>>(),
        vec!["alpha_ops", "enterprise_ops"]
    );
}

#[test]
fn platform_persists_and_lists_approvals_under_state_directory() {
    let workspace = tempfile::tempdir().expect("workspace");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");
    let pending_b = approval_record("approval-b");
    let pending_a = approval_record("approval-a");
    let mut approved = approval_record("approval-c");
    approved.state = ApprovalState::Approved;

    platform
        .write_approval(&pending_b)
        .expect("write pending b");
    platform.write_approval(&approved).expect("write approved");
    platform
        .write_approval(&pending_a)
        .expect("write pending a");

    let loaded = platform.read_approval("approval-b").expect("read approval");
    assert_eq!(loaded, pending_b);
    assert!(
        workspace
            .path()
            .join(".runwarden/approvals/approval-b.json")
            .is_file()
    );
    assert_eq!(
        platform
            .list_approvals(ApprovalListFilter::Pending)
            .expect("pending approvals")
            .into_iter()
            .map(|approval| approval.approval_id)
            .collect::<Vec<_>>(),
        vec!["approval-a", "approval-b"]
    );
    assert_eq!(
        platform
            .list_approvals(ApprovalListFilter::All)
            .expect("all approvals")
            .into_iter()
            .map(|approval| approval.approval_id)
            .collect::<Vec<_>>(),
        vec!["approval-a", "approval-b", "approval-c"]
    );
}

#[test]
fn platform_rejects_unsafe_session_and_record_ids() {
    assert_eq!(
        validate_session_id("enterprise_ops").expect("safe session"),
        "enterprise_ops"
    );
    assert_eq!(
        validate_record_id("approval-1").expect("safe approval"),
        "approval-1"
    );

    for unsafe_id in ["", "../enterprise_ops", "enterprise/ops", "enterprise\\ops"] {
        assert_eq!(
            validate_session_id(unsafe_id)
                .expect_err("unsafe session id")
                .to_string(),
            format!("invalid session id: {unsafe_id}")
        );
        assert_eq!(
            validate_record_id(unsafe_id)
                .expect_err("unsafe record id")
                .to_string(),
            format!("invalid record id: {unsafe_id}")
        );
    }
}

#[test]
fn invalid_session_write_does_not_create_state_directory() {
    let workspace = tempfile::tempdir().expect("workspace");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    let err = platform
        .write_session(&session_manifest("../enterprise_ops"))
        .expect_err("invalid session write");

    assert_eq!(err.to_string(), "invalid session id: ../enterprise_ops");
    assert!(!workspace.path().join(".runwarden/sessions").exists());
}

#[test]
fn invalid_approval_write_does_not_create_state_directory() {
    let workspace = tempfile::tempdir().expect("workspace");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    let err = platform
        .write_approval(&approval_record("../approval-1"))
        .expect_err("invalid approval write");

    assert_eq!(err.to_string(), "invalid record id: ../approval-1");
    assert!(!workspace.path().join(".runwarden/approvals").exists());
}
