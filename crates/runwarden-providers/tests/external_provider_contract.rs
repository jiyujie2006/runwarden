use runwarden_kernel::{
    ProviderClass, ProviderKind, ProviderManifest, ProviderRisk, ProviderSchemaPin, SideEffectKind,
};
use runwarden_providers::catalog::default_external_provider_manifest;
use runwarden_providers::external::{certify_external_provider_manifest, load_provider_manifest};

fn base_manifest() -> ProviderManifest {
    let schema = serde_json::json!({"type":"object"});
    ProviderManifest {
        schema_version: "1".to_owned(),
        provider_id: "external.mcp.fixture.call".to_owned(),
        provider_class: ProviderClass::External,
        kind: ProviderKind::Mcp,
        risk: ProviderRisk::High,
        side_effects: vec![SideEffectKind::FileRead, SideEffectKind::ProcessSpawn],
        transport: Some("stdio".to_owned()),
        downstream_identity: Some("fixture-mcp".to_owned()),
        tool_identity: Some("call".to_owned()),
        declared_permissions: vec!["file_read".to_owned(), "process_spawn".to_owned()],
        allowed_origins: Vec::new(),
        command_allowlist: vec!["fixture-mcp".to_owned()],
        working_root: Some(".".to_owned()),
        schema_pin: ProviderSchemaPin::new(schema.clone()),
        observed_schema: schema,
    }
}

#[test]
fn external_mcp_manifest_certifies_identity_permissions_and_schema_pin() {
    let manifest = base_manifest();
    let report = certify_external_provider_manifest(&manifest);

    assert!(report.passed, "{:?}", report.findings);
    assert!(report.findings.is_empty());
    assert_eq!(report.contract.provider.id, manifest.provider_id);
    assert_eq!(
        report.contract.provider.evidence_contract["adapter_manifest"]["transport"],
        "stdio"
    );
    assert!(!report.side_effect_executed);
}

#[test]
fn manifest_loader_rejects_unknown_or_malformed_contract_data() {
    let encoded = serde_json::to_string(&base_manifest()).unwrap();
    let loaded = load_provider_manifest(&encoded).expect("canonical manifest parses");
    assert_eq!(loaded.provider_id, "external.mcp.fixture.call");
    assert!(load_provider_manifest("{not-json").is_err());
}

#[test]
fn checked_in_browser_manifest_matches_catalog_and_documents_fail_closed_egress() {
    let checked_in = load_provider_manifest(include_str!(
        "../../../examples/providers/external.mcp.browser.open_page.json"
    ))
    .unwrap();
    let canonical = default_external_provider_manifest("external.mcp.browser.open_page").unwrap();

    assert_eq!(checked_in, canonical);
    let report = certify_external_provider_manifest(&checked_in);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .contains(&"stdio_egress_controls_unsupported".to_owned())
    );
}

#[test]
fn external_mcp_stdio_manifest_requires_command_allowlist_and_working_root() {
    let mut manifest = base_manifest();
    manifest.command_allowlist.clear();
    manifest.working_root = None;

    let report = certify_external_provider_manifest(&manifest);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .contains(&"stdio_exact_command_required".to_owned())
    );
    assert!(
        report
            .findings
            .contains(&"stdio_working_root_invalid".to_owned())
    );
}

#[test]
fn external_mcp_stdio_manifest_requires_exact_non_shell_identity_and_spawn_declaration() {
    let mut shell = base_manifest();
    shell.command_allowlist = vec!["sh".to_owned()];
    shell.downstream_identity = Some("sh".to_owned());
    let mut multiple = base_manifest();
    multiple.command_allowlist.push("second-mcp".to_owned());
    let mut undeclared = base_manifest();
    undeclared
        .side_effects
        .retain(|effect| *effect != SideEffectKind::ProcessSpawn);
    undeclared
        .declared_permissions
        .retain(|permission| permission != "process_spawn");

    for manifest in [shell, multiple] {
        let report = certify_external_provider_manifest(&manifest);
        assert!(!report.passed);
        assert!(
            report
                .findings
                .contains(&"stdio_exact_command_required".to_owned())
        );
    }
    let report = certify_external_provider_manifest(&undeclared);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .contains(&"stdio_process_spawn_declaration_required".to_owned())
    );
}

#[test]
fn external_mcp_stdio_manifest_rejects_network_or_credential_egress() {
    let mut network = base_manifest();
    network.risk = ProviderRisk::NetworkActive;
    network.side_effects = vec![SideEffectKind::Network];
    network.allowed_origins = vec!["https://example.com".to_owned()];
    network.declared_permissions.push("network".to_owned());
    let mut credential = base_manifest();
    credential.risk = ProviderRisk::CredentialUse;
    credential.side_effects = vec![SideEffectKind::CredentialUse];
    credential
        .declared_permissions
        .push("credential_use".to_owned());

    for manifest in [network, credential] {
        let report = certify_external_provider_manifest(&manifest);
        assert!(!report.passed);
        assert!(
            report
                .findings
                .contains(&"stdio_egress_controls_unsupported".to_owned())
        );
    }
}

#[test]
fn external_mcp_https_transport_is_not_certified_without_a_tls_adapter() {
    let mut manifest = base_manifest();
    manifest.transport = Some("https".to_owned());
    manifest.command_allowlist.clear();
    manifest.working_root = None;
    manifest.allowed_origins = vec!["https://example.com".to_owned()];

    let report = certify_external_provider_manifest(&manifest);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .contains(&"mcp_transport_required".to_owned())
    );
}

#[test]
fn schema_rug_pull_and_pin_tamper_are_certification_failures() {
    let mut observed_changed = base_manifest();
    observed_changed.observed_schema = serde_json::json!({"type":"string"});
    let report = certify_external_provider_manifest(&observed_changed);
    assert!(!report.passed);
    assert!(report.findings.contains(&"schema_rug_pull".to_owned()));

    let mut pin_changed = base_manifest();
    pin_changed.schema_pin.digest = "sha256:00".to_owned();
    let report = certify_external_provider_manifest(&pin_changed);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .contains(&"schema_pin_digest_mismatch".to_owned())
    );
}

#[test]
fn http_and_sse_certification_require_egress_without_process_controls() {
    for transport in ["http", "sse"] {
        let mut manifest = base_manifest();
        manifest.transport = Some(transport.to_owned());
        manifest.side_effects = vec![SideEffectKind::Network];
        manifest.risk = ProviderRisk::NetworkActive;
        manifest.allowed_origins = vec!["http://example.com".to_owned()];
        manifest.command_allowlist.clear();
        manifest.working_root = None;
        let report = certify_external_provider_manifest(&manifest);
        assert!(report.passed, "{transport}: {:?}", report.findings);

        manifest.command_allowlist.push("forbidden".to_owned());
        let report = certify_external_provider_manifest(&manifest);
        assert!(!report.passed);
        assert!(
            report
                .findings
                .contains(&"network_transport_process_controls_forbidden".to_owned())
        );

        manifest.command_allowlist.clear();
        manifest.allowed_origins = vec!["http://127.0.0.1".to_owned()];
        let report = certify_external_provider_manifest(&manifest);
        assert!(!report.passed);
        assert!(
            report
                .findings
                .contains(&"network_transport_origin_invalid".to_owned())
        );
    }
}
