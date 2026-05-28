use runwarden_kernel::authority::{ApprovalRecord, ApprovalState};
use runwarden_kernel::kernel::{
    AuthzState, KernelEnforcer, KernelPolicy, ProviderRegistry, ScopedRoot,
};
use runwarden_kernel::{
    ErrorKind, ExecutionStatus, KernelProvider, PolicyDecision, ProviderCall, ProviderClass,
    ProviderKind, ProviderRisk, SideEffectKind,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};

fn provider(id: &str, risk: ProviderRisk, side_effects: Vec<SideEffectKind>) -> KernelProvider {
    KernelProvider {
        id: id.to_string(),
        class: ProviderClass::FirstParty,
        kind: ProviderKind::Evidence,
        risk,
        side_effects,
        input_schema: json!({}),
        output_schema: json!({}),
        evidence_contract: json!({}),
        authority_requirements: json!({}),
    }
}

fn call(provider: &str, arguments: serde_json::Value) -> ProviderCall {
    ProviderCall {
        session_id: "session-1".to_string(),
        provider: provider.to_string(),
        action: "inspect".to_string(),
        arguments,
        actor_id: Some("agent-1".to_string()),
        authz_id: Some("authz-active".to_string()),
        approval_id: None,
    }
}

fn registry_with(provider: KernelProvider) -> ProviderRegistry {
    let mut registry = ProviderRegistry::default();
    registry.register(provider);
    registry
}

fn base_policy(provider_id: &str) -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.allow_provider(provider_id);
    policy.add_scoped_root(ScopedRoot::new("evidence", "/srv/runwarden/evidence"));
    policy.allow_egress_host("example.com");
    policy.require_authz = true;
    policy.add_authz("authz-active", AuthzState::Active);
    policy.max_argument_bytes = Some(512);
    policy.active_assessment = true;
    policy
}

#[test]
fn provider_not_in_session_allowlist_is_denied_before_side_effect() {
    let registry = registry_with(provider(
        "runwarden.evidence.inspect",
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let policy = KernelPolicy::default();
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        "runwarden.evidence.inspect",
        json!({"root":"evidence","target_path":"/srv/runwarden/evidence/input.txt"}),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.execution_status, ExecutionStatus::NotExecuted);
    assert_eq!(
        outcome.envelope.error_kind,
        Some(ErrorKind::ProviderNotAllowed)
    );
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn provider_policy_outcome_includes_observation_id_and_trace_event() {
    let provider_id = "runwarden.evidence.inspect";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let policy = base_policy(provider_id);
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({"root":"evidence","target_path":"/srv/runwarden/evidence/input.txt"}),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Allowed);
    assert!(
        outcome.observation_id.starts_with("obs_"),
        "outcome should be bound to an obs_* id: {:?}",
        outcome.observation_id
    );
    assert_eq!(
        outcome.envelope.trace_event.as_deref(),
        Some("provider_policy_evaluated")
    );
}

#[test]
fn network_side_effect_requires_reviewer_approval_even_for_low_risk_provider() {
    let provider_id = "external.low_risk_network";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::Network],
    ));
    let policy = base_policy(provider_id);
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(provider_id, json!({"url":"https://example.com"})));

    assert_eq!(outcome.decision, PolicyDecision::RequiresReview);
    assert_eq!(outcome.execution_status, ExecutionStatus::NotExecuted);
    assert_eq!(
        outcome.envelope.error_kind,
        Some(ErrorKind::ApprovalInvalid)
    );
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn root_escape_is_denied_before_side_effect() {
    let provider_id = "runwarden.evidence.inspect";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let policy = base_policy(provider_id);
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({"root":"evidence","target_path":"/srv/runwarden/secrets/token.txt"}),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::RootEscape));
    assert!(!outcome.envelope.side_effect_executed);
}

#[cfg(unix)]
#[test]
fn symlink_escape_inside_scoped_root_is_denied_before_side_effect() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("root");
    let outside = tempfile::tempdir().expect("outside");
    fs::write(outside.path().join("secret.txt"), "secret").expect("secret");
    symlink(
        outside.path().join("secret.txt"),
        root.path().join("link.txt"),
    )
    .expect("symlink");

    let provider_id = "runwarden.evidence.inspect";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let mut policy = base_policy(provider_id);
    policy.add_scoped_root(ScopedRoot::new("evidence", root.path()));
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({"root":"evidence","target_path": root.path().join("link.txt").to_string_lossy()}),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::RootEscape));
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn private_network_egress_is_denied_even_when_host_allowlisted() {
    let provider_id = "runwarden.http.replay";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::NetworkActive,
        vec![SideEffectKind::Network],
    ));
    let mut policy = base_policy(provider_id);
    policy.allow_egress_host("169.254.169.254");
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({
            "root":"evidence",
            "target_path":"/srv/runwarden/evidence/request.har",
            "url":"http://169.254.169.254/latest/meta-data"
        }),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::EgressDenied));
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn ipv4_mapped_private_egress_is_denied_before_side_effect() {
    let provider_id = "runwarden.http.replay";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::NetworkActive,
        vec![SideEffectKind::Network],
    ));
    let policy = base_policy(provider_id);
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({
            "url": "http://[::ffff:127.0.0.1]/latest/meta-data"
        }),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::EgressDenied));
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn argument_budget_exceeded_is_denied_before_side_effect() {
    let provider_id = "runwarden.evidence.inspect";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let mut policy = base_policy(provider_id);
    policy.max_argument_bytes = Some(48);
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({
            "root":"evidence",
            "target_path":"/srv/runwarden/evidence/input.txt",
            "blob":"x".repeat(256)
        }),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::BudgetExceeded));
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn inactive_assessment_is_denied_before_side_effect() {
    let provider_id = "runwarden.evidence.inspect";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let mut policy = base_policy(provider_id);
    policy.active_assessment = false;
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({"root":"evidence","target_path":"/srv/runwarden/evidence/input.txt"}),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(
        outcome.envelope.error_kind,
        Some(ErrorKind::ActiveAssessmentRequired)
    );
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn revoked_authz_is_denied_before_side_effect() {
    let provider_id = "runwarden.evidence.inspect";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    ));
    let mut policy = base_policy(provider_id);
    policy.add_authz("authz-active", AuthzState::Revoked);
    let mut enforcer = KernelEnforcer::new(registry, policy);

    let outcome = enforcer.evaluate_call(&call(
        provider_id,
        json!({"root":"evidence","target_path":"/srv/runwarden/evidence/input.txt"}),
    ));

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::AuthzInvalid));
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn expired_and_denied_authz_are_denied_before_side_effect() {
    for state in [AuthzState::Expired, AuthzState::Denied] {
        let provider_id = "runwarden.evidence.inspect";
        let registry = registry_with(provider(
            provider_id,
            ProviderRisk::Low,
            vec![SideEffectKind::FileRead],
        ));
        let mut policy = base_policy(provider_id);
        policy.add_authz("authz-active", state);
        let mut enforcer = KernelEnforcer::new(registry, policy);

        let outcome = enforcer.evaluate_call(&call(
            provider_id,
            json!({"root":"evidence","target_path":"/srv/runwarden/evidence/input.txt"}),
        ));

        assert_eq!(outcome.decision, PolicyDecision::Denied);
        assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::AuthzInvalid));
        assert!(!outcome.envelope.side_effect_executed);
    }
}

#[test]
fn high_risk_provider_requires_bound_approval_then_consumes_once() {
    let provider_id = "runwarden.report.publish";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::ReportClaim,
        vec![SideEffectKind::ArtifactWrite],
    ));
    let policy = base_policy(provider_id);
    let mut enforcer = KernelEnforcer::new(registry, policy);
    let mut request = call(
        provider_id,
        json!({"root":"evidence","target_path":"/srv/runwarden/evidence/report.md"}),
    );

    let pending = enforcer.evaluate_call(&request);
    assert_eq!(pending.decision, PolicyDecision::RequiresReview);
    assert_eq!(
        pending.envelope.error_kind,
        Some(ErrorKind::ApprovalInvalid)
    );
    assert!(!pending.envelope.side_effect_executed);

    let mut approval =
        ApprovalRecord::new("approval-1", enforcer.approval_binding_for_call(&request));
    approval
        .approve("reviewer-alice", "report claim risk reviewed")
        .expect("approval can be approved");
    enforcer.add_approval(approval);
    request.approval_id = Some("approval-1".to_string());

    let allowed = enforcer.evaluate_call(&request);
    assert_eq!(allowed.decision, PolicyDecision::Allowed);
    assert!(!allowed.envelope.side_effect_executed);
    assert_eq!(
        enforcer.approval_state("approval-1"),
        Some(ApprovalState::Consumed)
    );

    let replay = enforcer.evaluate_call(&request);
    assert_eq!(replay.decision, PolicyDecision::Denied);
    assert_eq!(
        replay.envelope.error_kind,
        Some(ErrorKind::ApprovalConsumed)
    );
    assert!(!replay.envelope.side_effect_executed);
}

#[test]
fn high_risk_provider_rejects_approved_but_expired_approval_before_consuming() {
    let provider_id = "runwarden.report.publish";
    let registry = registry_with(provider(
        provider_id,
        ProviderRisk::ReportClaim,
        vec![SideEffectKind::ArtifactWrite],
    ));
    let policy = base_policy(provider_id);
    let mut enforcer = KernelEnforcer::new(registry, policy);
    let mut request = call(
        provider_id,
        json!({"root":"evidence","target_path":"/srv/runwarden/evidence/report.md"}),
    );
    let mut approval =
        ApprovalRecord::new("approval-1", enforcer.approval_binding_for_call(&request));
    approval
        .approve("reviewer-alice", "report claim risk reviewed")
        .expect("approval can be approved");
    approval.expires_at = Some(OffsetDateTime::now_utc() - Duration::seconds(1));
    enforcer.add_approval(approval);
    request.approval_id = Some("approval-1".to_string());

    let outcome = enforcer.evaluate_call(&request);

    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(
        outcome.envelope.error_kind,
        Some(ErrorKind::ApprovalExpired)
    );
    assert_eq!(
        enforcer.approval_state("approval-1"),
        Some(ApprovalState::Approved)
    );
    assert!(!outcome.envelope.side_effect_executed);
}

#[test]
fn high_risk_provider_rejects_denied_expired_and_revoked_approval_states() {
    for (state, error_kind) in [
        (ApprovalState::Denied, ErrorKind::ApprovalInvalid),
        (ApprovalState::Expired, ErrorKind::ApprovalExpired),
        (ApprovalState::Revoked, ErrorKind::ApprovalInvalid),
    ] {
        let provider_id = "runwarden.report.publish";
        let registry = registry_with(provider(
            provider_id,
            ProviderRisk::ReportClaim,
            vec![SideEffectKind::ArtifactWrite],
        ));
        let policy = base_policy(provider_id);
        let mut enforcer = KernelEnforcer::new(registry, policy);
        let mut request = call(
            provider_id,
            json!({"root":"evidence","target_path":"/srv/runwarden/evidence/report.md"}),
        );
        let mut approval =
            ApprovalRecord::new("approval-1", enforcer.approval_binding_for_call(&request));
        approval.state = state;
        enforcer.add_approval(approval);
        request.approval_id = Some("approval-1".to_string());

        let outcome = enforcer.evaluate_call(&request);

        assert_eq!(outcome.decision, PolicyDecision::Denied);
        assert_eq!(outcome.envelope.error_kind, Some(error_kind));
        assert!(!outcome.envelope.side_effect_executed);
    }
}
