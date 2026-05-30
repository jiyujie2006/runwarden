use runwarden_kernel::{
    ProviderClass, ProviderContract, ProviderKind, ProviderManifest, ProviderRisk,
    ProviderSchemaPin, SideEffectKind,
};
use serde_json::json;

#[test]
fn provider_manifest_models_external_provider_identity_and_schema_pin() {
    let manifest = ProviderManifest {
        schema_version: "1".to_string(),
        provider_id: "external.mcp.browser.open_page".to_string(),
        provider_class: ProviderClass::External,
        kind: ProviderKind::Mcp,
        risk: ProviderRisk::NetworkActive,
        side_effects: vec![SideEffectKind::Network],
        transport: Some("stdio".to_string()),
        downstream_identity: Some("browser-mcp".to_string()),
        tool_identity: Some("open_page".to_string()),
        declared_permissions: vec!["network".to_string()],
        allowed_origins: vec!["https://example.com".to_string()],
        command_allowlist: vec![],
        working_root: None,
        schema_pin: ProviderSchemaPin::new(json!({"type": "object"})),
        observed_schema: json!({"type": "object"}),
    };

    let contract = ProviderContract::from_manifest(&manifest);

    assert_eq!(contract.provider.id, "external.mcp.browser.open_page");
    assert_eq!(contract.provider.class, ProviderClass::External);
    assert_eq!(contract.provider.kind, ProviderKind::Mcp);
    assert_eq!(contract.provider.risk, ProviderRisk::NetworkActive);
    assert_eq!(contract.schema_pin.digest, manifest.schema_pin.digest);
    assert!(!contract.schema_rug_pull_detected);
    assert!(contract.enforcement.requires_kernel_mediation);
    assert!(contract.enforcement.requires_trace);
    assert!(contract.enforcement.requires_redaction);
}

#[test]
fn provider_contract_detects_schema_rug_pull_against_pin() {
    let mut manifest = ProviderManifest {
        schema_version: "1".to_string(),
        provider_id: "external.mcp.browser.open_page".to_string(),
        provider_class: ProviderClass::External,
        kind: ProviderKind::Mcp,
        risk: ProviderRisk::NetworkActive,
        side_effects: vec![SideEffectKind::Network],
        transport: Some("stdio".to_string()),
        downstream_identity: Some("browser-mcp".to_string()),
        tool_identity: Some("open_page".to_string()),
        declared_permissions: vec!["network".to_string()],
        allowed_origins: vec!["https://example.com".to_string()],
        command_allowlist: vec![],
        working_root: None,
        schema_pin: ProviderSchemaPin::new(json!({"type": "object"})),
        observed_schema: json!({"type": "object"}),
    };
    manifest.observed_schema = json!({"type": "object", "properties": {"url": {"type": "string"}}});

    let contract = ProviderContract::from_manifest(&manifest);

    assert!(contract.schema_rug_pull_detected);
    assert_ne!(contract.schema_pin.digest, contract.observed_schema_digest);
}
