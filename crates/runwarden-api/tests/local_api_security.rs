use runwarden_api::{ApprovalDecision, ApprovalDecisionInput, LocalApiRequest, LocalApiSecurity};
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};

fn api() -> LocalApiSecurity {
    LocalApiSecurity::new(
        "launch-secret",
        ["127.0.0.1:8088"],
        ["http://127.0.0.1:8088"],
    )
}

fn approval_request() -> LocalApiRequest {
    LocalApiRequest::new("POST", "/approvals/approval-1/approve")
        .header("Host", "127.0.0.1:8088")
        .header("Origin", "http://127.0.0.1:8088")
        .bearer_token("launch-secret")
}

fn approval_record(id: &str) -> ApprovalRecord {
    ApprovalRecord::new(
        id,
        ApprovalBinding {
            session_id: "session-1".to_string(),
            provider: "external.shell.command".to_string(),
            action: "execute".to_string(),
            argument_hash: "sha256:abc123".to_string(),
            authz_id: Some("authz-1".to_string()),
            actor_id: Some("agent-1".to_string()),
        },
    )
}

fn approve_input() -> ApprovalDecisionInput {
    ApprovalDecisionInput {
        decision: ApprovalDecision::Approve,
        reviewer: "reviewer-alice".to_string(),
        reason: "reviewed exact command and scoped root".to_string(),
    }
}

#[test]
fn control_plane_mutation_rejects_missing_launch_token() {
    let mut request = approval_request();
    request.remove_header("authorization");

    let response = api().authorize_control_plane(&request);

    assert_eq!(response.status, 401);
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn control_plane_mutation_rejects_bad_host() {
    let request = approval_request().header("Host", "evil.test:8088");

    let response = api().authorize_control_plane(&request);

    assert_eq!(response.status, 403);
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn control_plane_mutation_rejects_bad_origin() {
    let request = approval_request().header("Origin", "http://evil.test");

    let response = api().authorize_control_plane(&request);

    assert_eq!(response.status, 403);
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn control_plane_mutation_allows_matching_token_host_origin_without_wildcard_cors() {
    let response = api().authorize_control_plane(&approval_request());

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("access-control-allow-origin"),
        Some(&"http://127.0.0.1:8088".to_string())
    );
    assert_ne!(
        response.headers.get("access-control-allow-origin"),
        Some(&"*".to_string())
    );
}

#[test]
fn control_plane_mutation_allows_generated_file_origin_with_launch_token() {
    let request = approval_request().header("Origin", "null");

    let response = api().authorize_control_plane(&request);

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("access-control-allow-origin"),
        Some(&"null".to_string())
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn approval_queue_lists_pending_records_after_security_gate() {
    let mut api = api();
    let pending = approval_record("approval-1");
    let mut approved = approval_record("approval-2");
    approved
        .approve("reviewer-alice", "already reviewed")
        .expect("approval can be approved");
    api.insert_approval(pending);
    api.insert_approval(approved);

    let response = api.approval_queue(
        &LocalApiRequest::new("GET", "/approvals")
            .header("Host", "127.0.0.1:8088")
            .header("Origin", "http://127.0.0.1:8088")
            .bearer_token("launch-secret"),
    );

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["approvals"]
            .as_array()
            .expect("approvals")
            .len(),
        1
    );
    assert_eq!(response.body["approvals"][0]["approval_id"], "approval-1");
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn approval_mutation_uses_security_gate_before_record_change() {
    let mut api = api();
    api.insert_approval(approval_record("approval-1"));
    let forged = approval_request().header("Origin", "http://evil.test");

    let response = api.decide_approval(&forged, "approval-1", approve_input());

    assert_eq!(response.status, 403);
    assert_eq!(response.body["side_effect_executed"], false);
    assert_eq!(
        api.approval_state("approval-1"),
        Some(ApprovalState::Pending)
    );
}

#[test]
fn approval_approve_mutation_updates_kernel_record_with_reviewer_reason() {
    let mut api = api();
    api.insert_approval(approval_record("approval-1"));

    let response = api.decide_approval(&approval_request(), "approval-1", approve_input());

    assert_eq!(response.status, 200);
    assert_eq!(response.body["side_effect_executed"], true);
    assert_eq!(response.body["approval"]["state"], "approved");
    assert_eq!(response.body["approval"]["reviewer"], "reviewer-alice");
    assert_eq!(
        response.body["approval"]["reason"],
        "reviewed exact command and scoped root"
    );
    assert_eq!(
        api.approval_state("approval-1"),
        Some(ApprovalState::Approved)
    );
}

#[test]
fn approval_deny_mutation_updates_kernel_record_with_reviewer_reason() {
    let mut api = api();
    api.insert_approval(approval_record("approval-1"));
    let input = ApprovalDecisionInput {
        decision: ApprovalDecision::Deny,
        reviewer: "reviewer-alice".to_string(),
        reason: "requested path is outside assessment scope".to_string(),
    };

    let response = api.decide_approval(&approval_request(), "approval-1", input);

    assert_eq!(response.status, 200);
    assert_eq!(response.body["side_effect_executed"], true);
    assert_eq!(response.body["approval"]["state"], "denied");
    assert_eq!(
        api.approval_state("approval-1"),
        Some(ApprovalState::Denied)
    );
}

#[test]
fn approval_mutation_rejects_missing_reason_without_record_change() {
    let mut api = api();
    api.insert_approval(approval_record("approval-1"));
    let mut input = approve_input();
    input.reason = " ".to_string();

    let response = api.decide_approval(&approval_request(), "approval-1", input);

    assert_eq!(response.status, 400);
    assert_eq!(response.body["side_effect_executed"], false);
    assert_eq!(
        api.approval_state("approval-1"),
        Some(ApprovalState::Pending)
    );
}

#[test]
fn artifact_download_token_is_single_use() {
    let mut api = api();
    let token = api.issue_artifact_download_token("artifact-1");

    let first = api.consume_artifact_download_token(&token);
    let replay = api.consume_artifact_download_token(&token);

    assert_eq!(first.status, 200);
    assert_eq!(replay.status, 403);
    assert_eq!(
        replay.body["error"],
        "artifact token is invalid or already used"
    );
}

#[test]
fn artifact_download_token_is_high_entropy_not_a_predictable_counter() {
    let mut api = api();
    let first = api.issue_artifact_download_token("artifact-1");
    let second = api.issue_artifact_download_token("artifact-2");

    assert_ne!(first, second);
    assert!(
        first.len() >= 48,
        "artifact tokens should carry enough entropy: {first}"
    );
    assert!(
        !first.starts_with("rw_artifact_token_"),
        "artifact tokens must not expose a predictable counter: {first}"
    );
}
