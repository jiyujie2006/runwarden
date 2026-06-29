use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::{ExecutionStatus, PolicyDecision, ProviderCall, ProviderOutcome};
use serde_json::json;

#[test]
fn provider_outcome_separates_policy_decision_from_execution_status() {
    let outcome = ProviderOutcome::denied_before_side_effect(
        "external.api.request",
        "request",
        "metadata API request is disabled",
    );

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.execution_status, ExecutionStatus::NotExecuted);
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn approval_record_consumes_once_and_rejects_replay() {
    let binding = ApprovalBinding {
        session_id: "session-1".to_string(),
        provider: "external.mcp.browser.fetch".to_string(),
        action: "fetch".to_string(),
        argument_hash: "arg-hash".to_string(),
        authz_id: Some("authz-1".to_string()),
        actor_id: Some("agent-1".to_string()),
    };
    let mut approval = ApprovalRecord::new("approval-1", binding.clone());

    approval
        .approve("reviewer-alice", "target is in scope")
        .expect("pending approval can be approved");
    approval
        .consume_once(&binding)
        .expect("approved binding can be consumed once");

    assert_eq!(approval.state, ApprovalState::Consumed);
    assert!(approval.consume_once(&binding).is_err());
}

#[test]
fn approval_record_rejects_argument_hash_swap() {
    let binding = ApprovalBinding {
        session_id: "session-1".to_string(),
        provider: "external.mcp.browser.fetch".to_string(),
        action: "fetch".to_string(),
        argument_hash: "arg-hash".to_string(),
        authz_id: Some("authz-1".to_string()),
        actor_id: Some("agent-1".to_string()),
    };
    let mut approval = ApprovalRecord::new("approval-1", binding.clone());
    approval
        .approve("reviewer-alice", "target is in scope")
        .expect("pending approval can be approved");

    let swapped = ApprovalBinding {
        argument_hash: "different".to_string(),
        ..binding
    };

    assert!(approval.consume_once(&swapped).is_err());
    assert_eq!(approval.state, ApprovalState::Approved);
}

#[test]
fn approval_record_can_be_denied_from_pending_with_reason() {
    let binding = ApprovalBinding {
        session_id: "session-1".to_string(),
        provider: "runwarden.report.render".to_string(),
        action: "render".to_string(),
        argument_hash: "arg-hash".to_string(),
        authz_id: Some("authz-1".to_string()),
        actor_id: Some("agent-1".to_string()),
    };
    let mut approval = ApprovalRecord::new("approval-1", binding);

    approval
        .deny("reviewer-alice", "out of scope")
        .expect("pending approval can be denied");

    assert_eq!(approval.state, ApprovalState::Denied);
    assert_eq!(approval.reviewer.as_deref(), Some("reviewer-alice"));
    assert_eq!(approval.reason.as_deref(), Some("out of scope"));
}

#[test]
fn provider_call_keeps_authority_fields_explicit() {
    let call = ProviderCall {
        session_id: "session-1".to_string(),
        provider: "runwarden.input.inspect".to_string(),
        action: "inspect".to_string(),
        arguments: json!({"root":"evidence"}),
        actor_id: Some("agent-1".to_string()),
        authz_id: Some("authz-1".to_string()),
        approval_id: None,
    };

    assert_eq!(call.actor_id.as_deref(), Some("agent-1"));
    assert_eq!(call.authz_id.as_deref(), Some("authz-1"));
}
