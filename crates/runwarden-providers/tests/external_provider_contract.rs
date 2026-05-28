use runwarden_kernel::{ProviderKind, ProviderRisk};
use runwarden_providers::external::{certify_external_provider_manifest, load_provider_manifest};

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
          "transport": "stdio",
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
    assert_eq!(report.side_effect_executed, false);
}

#[test]
fn external_shell_manifest_requires_command_allowlist_and_working_root() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.shell.command",
          "provider_class": "external",
          "kind": "shell",
          "risk": "destructive",
          "side_effects": ["process_spawn", "destructive"],
          "declared_permissions": ["process_spawn"],
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
            .any(|finding| finding == "shell_command_allowlist_required")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "shell_working_root_required")
    );
    assert_eq!(report.side_effect_executed, false);
}
