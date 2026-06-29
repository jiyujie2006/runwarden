use runwarden_kernel::kernel::{KernelEnforcer, ProviderRegistry};
use runwarden_kernel::manifest::{AssessmentManifest, AuthzManifestState, SessionManifest};
use runwarden_kernel::{
    ErrorKind, KernelProvider, PolicyDecision, ProviderCall, ProviderClass, ProviderKind,
    ProviderRisk, SideEffectKind,
};
use serde_json::json;

fn provider(id: &str) -> KernelProvider {
    KernelProvider {
        id: id.to_string(),
        class: ProviderClass::FirstParty,
        kind: ProviderKind::Evidence,
        risk: ProviderRisk::Low,
        side_effects: vec![SideEffectKind::FileRead],
        input_schema: json!({}),
        output_schema: json!({}),
        evidence_contract: json!({}),
        authority_requirements: json!({}),
    }
}

fn call(provider: &str, authz_id: &str) -> ProviderCall {
    ProviderCall {
        session_id: "contest_ops".to_string(),
        provider: provider.to_string(),
        action: "inspect".to_string(),
        arguments: json!({
            "root": "evidence",
            "target_path": "/srv/runwarden/evidence/input.txt"
        }),
        actor_id: Some("agent-1".to_string()),
        authz_id: Some(authz_id.to_string()),
        approval_id: None,
    }
}

#[test]
fn session_from_assessment_manifest_builds_enforcing_policy() {
    let manifest = AssessmentManifest::from_toml_str(
        r#"
        version = "0.1"
        name = "prompt-injection-file-exfil"
        mode = "offline"
        provider_allowlist = ["runwarden.input.inspect"]

        [[roots]]
        name = "evidence"
        path = "/srv/runwarden/evidence"

        [budgets]
        max_argument_bytes = 512

        [actor]
        id = "agent-1"

        [authorization]
        id = "authz-active"
        state = "active"

        [active_assessment]
        enabled = true
        "#,
    )
    .expect("manifest parses");
    let session = SessionManifest::from_assessment("contest_ops", &manifest);

    assert_eq!(session.session_id, "contest_ops");
    assert_eq!(session.allowed_providers, vec!["runwarden.input.inspect"]);
    assert_eq!(session.authz_id.as_deref(), Some("authz-active"));
    assert_eq!(session.actor_id.as_deref(), Some("agent-1"));
    assert!(!session.manifest_hash.is_empty());

    let mut registry = ProviderRegistry::default();
    registry.register(provider("runwarden.input.inspect"));
    registry.register(provider("external.api.request"));
    let mut enforcer = KernelEnforcer::new(registry, session.to_kernel_policy());

    let allowed = enforcer.evaluate_call(&call("runwarden.input.inspect", "authz-active"));
    assert_eq!(allowed.decision, PolicyDecision::Allowed);

    let denied = enforcer.evaluate_call(&call("external.api.request", "authz-active"));
    assert_eq!(denied.decision, PolicyDecision::Denied);
    assert_eq!(
        denied.envelope.error_kind,
        Some(ErrorKind::ProviderNotAllowed)
    );
}

#[test]
fn session_policy_denies_revoked_authz_from_manifest() {
    let manifest = AssessmentManifest::from_toml_str(
        r#"
        version = "0.1"
        name = "revoked-authz"
        mode = "offline"
        provider_allowlist = ["runwarden.input.inspect"]

        [[roots]]
        name = "evidence"
        path = "/srv/runwarden/evidence"

        [authorization]
        id = "authz-revoked"
        state = "revoked"

        [active_assessment]
        enabled = true
        "#,
    )
    .expect("manifest parses");
    let session = SessionManifest::from_assessment("contest_ops", &manifest);

    assert_eq!(session.governance_state, AuthzManifestState::Revoked);

    let mut registry = ProviderRegistry::default();
    registry.register(provider("runwarden.input.inspect"));
    let mut enforcer = KernelEnforcer::new(registry, session.to_kernel_policy());

    let outcome = enforcer.evaluate_call(&call("runwarden.input.inspect", "authz-revoked"));
    assert_eq!(outcome.decision, PolicyDecision::Denied);
    assert_eq!(outcome.envelope.error_kind, Some(ErrorKind::AuthzInvalid));
}
