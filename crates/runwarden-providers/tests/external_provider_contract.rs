use std::{
    fs,
    path::Path,
    sync::{Mutex, OnceLock},
};

use runwarden_kernel::{
    PolicyDecision, ProviderCall, ProviderClass, ProviderKind, ProviderManifest, ProviderOutcome,
    ProviderRisk, ProviderSchemaPin, SideEffectKind,
};
use runwarden_providers::external::{
    ExternalMcpAdapterRequest, certify_external_provider_manifest,
    execute_mediated_external_mcp_adapter, load_provider_manifest,
};
use tempfile::tempdir;

fn json_string(value: impl AsRef<str>) -> String {
    serde_json::to_string(value.as_ref()).expect("json string")
}

fn json_path(path: &Path) -> String {
    json_string(path.to_string_lossy())
}

fn execute_adapter(
    manifest: &ProviderManifest,
    request: &ExternalMcpAdapterRequest,
    runtime_root: Option<&Path>,
) -> serde_json::Value {
    static ADAPTER_EXECUTION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = ADAPTER_EXECUTION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("adapter execution lock");
    let outcome = provider_outcome(manifest, PolicyDecision::Allowed);
    execute_mediated_external_mcp_adapter(&outcome, manifest, request, runtime_root)
}

fn provider_outcome(manifest: &ProviderManifest, decision: PolicyDecision) -> ProviderOutcome {
    let call = ProviderCall {
        session_id: "session-test".to_string(),
        provider: manifest.provider_id.clone(),
        action: manifest
            .tool_identity
            .clone()
            .unwrap_or_else(|| "call".to_string()),
        arguments: serde_json::json!({}),
        actor_id: Some("agent-test".to_string()),
        authz_id: Some("authz-test".to_string()),
        approval_id: None,
    };
    ProviderOutcome::before_side_effect(decision, &call, "test", "test outcome", None)
}

fn stdio_manifest(working_root: &Path, command_allowlist: &[&str]) -> ProviderManifest {
    let schema = serde_json::json!({"type": "object"});
    ProviderManifest {
        schema_version: "1".to_string(),
        provider_id: "external.mcp.browser.open_page".to_string(),
        provider_class: ProviderClass::External,
        kind: ProviderKind::Mcp,
        risk: ProviderRisk::High,
        side_effects: vec![SideEffectKind::ProcessSpawn],
        transport: Some("stdio".to_string()),
        downstream_identity: Some("browser-mcp".to_string()),
        tool_identity: Some("open_page".to_string()),
        declared_permissions: vec!["process_spawn".to_string()],
        allowed_origins: Vec::new(),
        command_allowlist: command_allowlist
            .iter()
            .map(|value| value.to_string())
            .collect(),
        working_root: Some(working_root.to_string_lossy().to_string()),
        schema_pin: ProviderSchemaPin::new(schema.clone()),
        observed_schema: schema,
    }
}

#[cfg(unix)]
fn write_executable_script(path: &Path, content: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, content).expect("write script");
    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod");
}

#[test]
fn external_mcp_manifest_certifies_identity_permissions_and_schema_pin() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["https://example.com"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");

    assert_eq!(manifest.kind, ProviderKind::Mcp);
    assert_eq!(manifest.risk, ProviderRisk::NetworkActive);

    let report = certify_external_provider_manifest(&manifest);

    assert!(report.passed, "{report:?}");
    assert!(report.findings.is_empty());
    assert_eq!(
        report.contract.provider.id,
        "external.mcp.browser.open_page"
    );
    assert!(!report.side_effect_executed);
}

#[test]
fn external_mcp_stdio_manifest_requires_command_allowlist_and_working_root() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "high",
          "side_effects": ["process_spawn"],
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["process_spawn"],
          "allowed_origins": [],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");

    let report = certify_external_provider_manifest(&manifest);

    assert!(!report.passed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "stdio_command_allowlist_required")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "stdio_working_root_required")
    );
    assert!(!report.side_effect_executed);
}

#[test]
fn external_mcp_stdio_manifest_rejects_network_egress_requirements() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["https://example.com"],
          "command_allowlist": ["browser-mcp"],
          "working_root": ".",
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");

    let report = certify_external_provider_manifest(&manifest);

    assert!(!report.passed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "stdio_egress_controls_unsupported")
    );
}

#[test]
fn external_mcp_https_transport_is_not_certified_without_trusted_adapter() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "https",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["https://example.com"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");

    let report = certify_external_provider_manifest(&manifest);

    assert!(!report.passed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "mcp_transport_required")
    );
}

#[cfg(unix)]
#[test]
fn external_mcp_stdio_adapter_executes_framed_downstream_call() {
    let dir = tempdir().expect("tempdir");
    let manifest = stdio_manifest(dir.path(), &["cat"]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "open_page",
            "params": {"url": "https://example.com"}
        }),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "allowed");
    assert_eq!(result["execution_status"], "completed");
    assert_eq!(result["side_effect_executed"], true);
    assert_eq!(result["transport"], "stdio");
    assert!(
        result["stdout"]
            .as_str()
            .expect("stdout string")
            .contains("Content-Length:")
    );
}

#[cfg(unix)]
#[test]
fn mediated_external_mcp_adapter_refuses_denied_kernel_outcome() {
    let dir = tempdir().expect("tempdir");
    let manifest = stdio_manifest(dir.path(), &["cat"]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        request: serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "open_page"}),
        ..ExternalMcpAdapterRequest::default()
    };
    let outcome = provider_outcome(&manifest, PolicyDecision::Denied);

    let result =
        execute_mediated_external_mcp_adapter(&outcome, &manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_request_transport_must_match_manifest() {
    let dir = tempdir().expect("tempdir");
    let manifest = stdio_manifest(dir.path(), &["cat"]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("http".to_string()),
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        url: Some("http://127.0.0.1:9/mcp".to_string()),
        request: serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "open_page"}),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["error_kind"], "provider_not_allowed");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_manifest_transport_required_for_execution() {
    let dir = tempdir().expect("tempdir");
    let working_root = json_path(dir.path());
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "high",
          "side_effects": ["process_spawn"],
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["process_spawn"],
          "allowed_origins": [],
          "command_allowlist": ["cat"],
          "working_root": {},
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#,
        working_root
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        request: serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "open_page"}),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["error_kind"], "provider_not_allowed");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_stdio_rejects_request_args_before_spawn() {
    let dir = tempdir().expect("tempdir");
    let runtime_root = dir.path().join("runtime");
    fs::create_dir(&runtime_root).expect("runtime root");
    fs::write(dir.path().join("outside-secret.txt"), "outside secret").expect("outside secret");
    let manifest = stdio_manifest(&runtime_root, &["cat"]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("cat".to_string()),
        args: vec!["--config=/etc/passwd".to_string()],
        cwd: Some(runtime_root.clone()),
        request: serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "open_page"}),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(&runtime_root));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["error_kind"], "provider_not_allowed");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("request-supplied command arguments")
    );
    assert_eq!(result["side_effect_executed"], false);
    assert!(
        !result
            .get("stdout")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .contains("outside secret")
    );
}

#[test]
fn external_mcp_stdio_adapter_requires_trusted_runtime_root() {
    let dir = tempdir().expect("tempdir");
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "high",
          "side_effects": ["process_spawn"],
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["process_spawn"],
          "allowed_origins": [],
          "command_allowlist": ["cat"],
          "working_root": null,
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        request: serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "open_page"}),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, None);

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    #[cfg(unix)]
    assert_eq!(result["error_kind"], "root_escape");
    #[cfg(not(unix))]
    assert_eq!(result["error_kind"], "provider_not_allowed");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_stdio_adapter_rejects_shell_capable_command() {
    let dir = tempdir().expect("tempdir");
    let manifest = stdio_manifest(dir.path(), &["sh"]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("sh".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        args: vec!["-c".to_string(), "cat".to_string()],
        request: serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "open_page"}),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["error_kind"], "provider_not_allowed");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_http_adapter_rejects_literal_private_or_local_ip_hosts_before_connecting() {
    let cases = [
        "http://127.0.0.1:9/mcp",
        "http://10.0.0.1:9/mcp",
        "http://169.254.169.254:80/mcp",
        "http://[::1]:9/mcp",
        "http://[fd00::1]:9/mcp",
        "http://[::ffff:127.0.0.1]:9/mcp",
    ];

    for url in cases {
        let origin = url.strip_suffix("/mcp").expect("case URL has /mcp suffix");
        let manifest = load_provider_manifest(&format!(
            r#"{{
              "schema_version": "1",
              "provider_id": "external.mcp.browser.open_page",
              "provider_class": "external",
              "kind": "mcp",
              "risk": "network_active",
              "side_effects": ["network"],
              "transport": "http",
              "downstream_identity": "browser-mcp",
              "tool_identity": "open_page",
              "declared_permissions": ["network"],
              "allowed_origins": ["{origin}"],
              "schema_pin": {{
                "algorithm": "sha256",
                "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
                "schema": {{"type": "object"}}
              }},
              "observed_schema": {{"type": "object"}}
            }}"#
        ))
        .expect("manifest parses");
        let request = ExternalMcpAdapterRequest {
            transport: Some("http".to_string()),
            url: Some(url.to_string()),
            request: serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "open_page",
                "params": {"url": "https://example.com"}
            }),
            ..ExternalMcpAdapterRequest::default()
        };

        let result = execute_adapter(&manifest, &request, None);

        assert_eq!(result["decision"], "denied", "{url}: {result:?}");
        assert_eq!(
            result["execution_status"], "not_executed",
            "{url}: {result:?}"
        );
        assert_eq!(result["error_kind"], "egress_denied", "{url}: {result:?}");
        assert!(
            !result["side_effect_executed"].as_bool().unwrap_or(true),
            "{url}: {result:?}"
        );
    }
}

#[test]
fn external_mcp_http_adapter_rejects_dns_resolution_to_private_host() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["http://localhost:9"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("http".to_string()),
        url: Some("http://localhost:9/mcp".to_string()),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "open_page",
            "params": {"url": "https://example.com"}
        }),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, None);

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["error_kind"], "egress_denied");
    assert!(!result["side_effect_executed"].as_bool().unwrap_or(true));
}

#[test]
fn external_mcp_sse_adapter_rejects_literal_private_ip_host_before_connecting() {
    let origin = "http://127.0.0.1:9";
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "sse",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["http://127.0.0.1:9"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("sse".to_string()),
        url: Some(format!("{origin}/events")),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, None);

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["execution_status"], "not_executed");
    assert_eq!(result["error_kind"], "egress_denied");
    assert!(!result["side_effect_executed"].as_bool().unwrap_or(true));
}

#[test]
fn external_mcp_http_adapter_rejects_timeout_above_runtime_policy_before_connect() {
    let origin = "http://127.0.0.1:9";
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["{origin}"],
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("http".to_string()),
        url: Some(format!("{origin}/mcp")),
        timeout_ms: Some(30_001),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, None);

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["error_kind"], "budget_exceeded");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_adapter_rejects_schema_rug_pull_before_execution() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["http://127.0.0.1:9"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "array"}
        }"#,
    )
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("http".to_string()),
        url: Some("http://127.0.0.1:9/mcp".to_string()),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, None);

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["error_kind"], "schema_rug_pull");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_http_adapter_rejects_control_characters_in_path() {
    let origin = "http://127.0.0.1:9";
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["{origin}"],
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("http".to_string()),
        url: Some(format!("{origin}/mcp%0d%0aInjected: yes")),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, None);

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["error_kind"], "egress_denied");
    assert_eq!(result["side_effect_executed"], false);
}

#[test]
fn external_mcp_http_adapter_does_not_treat_signed_percent_triplets_as_control_characters() {
    let origin = "http://127.0.0.1:9";
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["{origin}"],
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#
    ))
    .expect("manifest parses");

    for path in ["/mcp%+A", "/mcp%+1"] {
        let request = ExternalMcpAdapterRequest {
            transport: Some("http".to_string()),
            url: Some(format!("{origin}{path}")),
            ..ExternalMcpAdapterRequest::default()
        };

        let result = execute_adapter(&manifest, &request, None);

        assert_eq!(result["decision"], "denied", "{path}: {result}");
        assert_eq!(result["error_kind"], "egress_denied", "{path}: {result}");
        assert_eq!(
            result["reason"], "MCP adapter URL resolved to a private or local address",
            "{path}: {result}"
        );
        assert_eq!(result["side_effect_executed"], false, "{path}: {result}");
    }
}

#[cfg(unix)]
#[test]
fn external_mcp_stdio_requires_exact_allowlisted_command() {
    let dir = tempdir().expect("tempdir");
    let manifest = stdio_manifest(dir.path(), &["sh"]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("/bin/sh".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["error_kind"], "provider_not_allowed");
    assert_eq!(result["side_effect_executed"], false);
}

#[cfg(unix)]
#[test]
fn external_mcp_stdio_rejects_network_capable_manifest_before_spawn() {
    let dir = tempdir().expect("tempdir");
    let working_root = json_path(dir.path());
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network", "process_spawn"],
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network", "process_spawn"],
          "allowed_origins": ["https://example.com"],
          "command_allowlist": ["cat"],
          "working_root": {},
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#,
        working_root
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "denied");
    assert_eq!(result["error_kind"], "egress_denied");
    assert_eq!(result["side_effect_executed"], false);
}

#[cfg(unix)]
#[test]
fn external_mcp_stdio_enforces_timeout_while_waiting() {
    let dir = tempdir().expect("tempdir");
    let script = dir.path().join("sleep-adapter");
    write_executable_script(&script, "#!/bin/sh\ncat >/dev/null & sleep 1\n");
    let command = script.to_string_lossy().into_owned();
    let manifest = stdio_manifest(dir.path(), &[&command]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some(command),
        cwd: Some(dir.path().to_path_buf()),
        timeout_ms: Some(10),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["execution_status"], "failed");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("timed out"),
        "unexpected adapter result: {result}"
    );
    assert_eq!(result["side_effect_executed"], true);
}

#[cfg(unix)]
#[test]
fn external_mcp_stdio_enforces_output_limit_while_reading() {
    let dir = tempdir().expect("tempdir");
    let script = dir.path().join("output-adapter");
    write_executable_script(&script, "#!/bin/sh\ncat >/dev/null\nprintf 1234567890\n");
    let command = script.to_string_lossy().into_owned();
    let manifest = stdio_manifest(dir.path(), &[&command]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some(command),
        cwd: Some(dir.path().to_path_buf()),
        stdout_limit_bytes: Some(4),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["execution_status"], "failed");
    assert!(
        result["reason"]
            .as_str()
            .expect("reason")
            .contains("output limit")
    );
    assert_eq!(result["side_effect_executed"], true);
}

#[cfg(unix)]
#[test]
fn external_mcp_stdio_cleans_process_group_after_success() {
    use std::thread;
    use std::time::{Duration, Instant};

    let dir = tempdir().expect("tempdir");
    let script = dir.path().join("spawn-background-adapter");
    write_executable_script(
        &script,
        "#!/bin/sh\ncat >/dev/null\nsleep 60 >/dev/null 2>/dev/null </dev/null &\necho $!\n",
    );
    let command = script.to_string_lossy().into_owned();
    let manifest = stdio_manifest(dir.path(), &[&command]);
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some(command),
        cwd: Some(dir.path().to_path_buf()),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "allowed");
    assert_eq!(result["execution_status"], "completed");
    let pid = result["stdout"]
        .as_str()
        .expect("stdout string")
        .trim()
        .parse::<i32>()
        .expect("background pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_exists(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!process_exists(pid), "background process {pid} survived");
}

#[cfg(unix)]
fn process_exists(pid: i32) -> bool {
    unsafe { kill(pid, 0) == 0 }
}

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
