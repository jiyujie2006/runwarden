use runwarden_providers::runtime::{
    NetworkPolicy, ProviderRuntime, ProviderRuntimeDenialKind, ProviderRuntimePolicy,
    ProviderRuntimeRequest,
};

fn policy() -> ProviderRuntimePolicy {
    ProviderRuntimePolicy::locked_to_root("/srv/runwarden/providers")
}

fn request() -> ProviderRuntimeRequest {
    ProviderRuntimeRequest::new("runwarden-provider")
        .arg("--json")
        .cwd("/srv/runwarden/providers/example")
}

#[test]
fn shell_is_denied_by_default_before_process_spawn() {
    let request = request().use_shell(true);

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("shell is denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::ShellDenied);
    assert!(!denial.side_effect_executed);
}

#[test]
fn cwd_escape_is_denied_before_process_spawn() {
    let request = request().cwd("/srv/runwarden/secrets");

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("cwd escape denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::CwdEscape);
    assert!(!denial.side_effect_executed);
}

#[test]
fn parent_environment_inheritance_is_denied_when_scrubbed() {
    let request = request().inherit_parent_env(true);

    let denial =
        ProviderRuntime::prepare(&policy(), &request).expect_err("parent env inheritance denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::EnvInheritanceDenied);
    assert!(!denial.side_effect_executed);
}

#[test]
fn non_allowlisted_environment_variable_is_denied() {
    let request = request().env("AWS_SECRET_ACCESS_KEY", "secret");

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("env denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::EnvNotAllowed);
    assert!(!denial.side_effect_executed);
}

#[test]
fn network_request_is_denied_by_default() {
    let request = request().network_host("example.com");

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("network denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::NetworkDenied);
    assert!(!denial.side_effect_executed);
}

#[test]
fn timeout_and_output_caps_are_enforced_before_process_spawn() {
    let timeout_request = request().timeout_ms(60_000);
    let timeout_denial =
        ProviderRuntime::prepare(&policy(), &timeout_request).expect_err("timeout denied");
    assert_eq!(
        timeout_denial.kind,
        ProviderRuntimeDenialKind::TimeoutTooLarge
    );

    let output_request = request().stdout_limit_bytes(2_000_000);
    let output_denial =
        ProviderRuntime::prepare(&policy(), &output_request).expect_err("output cap denied");
    assert_eq!(
        output_denial.kind,
        ProviderRuntimeDenialKind::OutputLimitTooLarge
    );
}

#[test]
fn safe_request_returns_sanitized_launch_plan() {
    let mut policy = policy();
    policy.allow_env("RUNWARDEN_PROVIDER_TOKEN");
    policy.network_policy = NetworkPolicy::AllowHosts(["api.example.com".into()].into());

    let request = request()
        .env("RUNWARDEN_PROVIDER_TOKEN", "redacted")
        .network_host("api.example.com")
        .timeout_ms(1_000)
        .stdout_limit_bytes(4096)
        .stderr_limit_bytes(4096);

    let plan = ProviderRuntime::prepare(&policy, &request).expect("safe request prepares");

    assert_eq!(
        plan.cwd.to_string_lossy(),
        "/srv/runwarden/providers/example"
    );
    assert_eq!(
        plan.env.get("RUNWARDEN_PROVIDER_TOKEN").map(String::as_str),
        Some("redacted")
    );
    assert!(plan.kill_process_tree_on_timeout);
    assert!(!plan.side_effect_executed);
}
