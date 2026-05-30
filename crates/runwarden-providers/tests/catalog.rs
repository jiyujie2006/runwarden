use runwarden_kernel::kernel::ProviderRegistry;
use runwarden_kernel::{ProviderClass, ProviderKind, ProviderRisk, SideEffectKind};
use runwarden_providers::catalog::{
    EXTERNAL_PROVIDER_IDS, FIRST_PARTY_PROVIDER_IDS, default_external_providers,
    default_first_party_providers, first_party_registry,
};

#[test]
fn first_party_catalog_contains_core_plan_providers() {
    let ids: Vec<_> = default_first_party_providers()
        .into_iter()
        .map(|provider| provider.id)
        .collect();

    for expected in FIRST_PARTY_PROVIDER_IDS {
        assert!(ids.contains(&expected.to_string()), "missing {expected}");
    }
}

#[test]
fn first_party_catalog_does_not_expose_raw_process_or_destructive_side_effects() {
    for provider in default_first_party_providers() {
        assert_eq!(provider.class, ProviderClass::FirstParty);
        assert!(
            !provider
                .side_effects
                .contains(&SideEffectKind::ProcessSpawn),
            "{} must not spawn raw processes directly",
            provider.id
        );
        assert!(
            !provider.side_effects.contains(&SideEffectKind::Destructive),
            "{} must not expose destructive side effects",
            provider.id
        );
    }
}

#[test]
fn first_party_catalog_populates_kernel_registry() {
    let registry: ProviderRegistry = first_party_registry();

    assert!(registry.contains("runwarden.input.inspect"));
    assert!(registry.contains("runwarden.evidence.inspect"));
    assert!(registry.contains("runwarden.trace.verify"));
    assert!(registry.contains("runwarden.report.lint"));
}

#[test]
fn external_catalog_declares_kernel_managed_external_provider_families() {
    let providers = default_external_providers();
    let ids: Vec<_> = providers
        .iter()
        .map(|provider| provider.id.as_str())
        .collect();

    for expected in EXTERNAL_PROVIDER_IDS {
        assert!(ids.contains(expected), "missing {expected}");
    }
    assert!(providers.iter().any(|provider| {
        provider.id == "external.mcp.browser.open_page"
            && provider.class == ProviderClass::External
            && provider.kind == ProviderKind::Mcp
            && provider.risk == ProviderRisk::NetworkActive
    }));
    assert!(providers.iter().any(|provider| {
        provider.id == "external.shell.command"
            && provider.class == ProviderClass::External
            && provider
                .side_effects
                .contains(&SideEffectKind::ProcessSpawn)
    }));
}

#[test]
fn external_mcp_prefix_is_reserved_for_mcp_kind() {
    for provider in default_external_providers()
        .into_iter()
        .filter(|provider| provider.id.starts_with("external.mcp."))
    {
        assert_eq!(
            provider.kind,
            ProviderKind::Mcp,
            "{} uses the external.mcp prefix but is {:?}",
            provider.id,
            provider.kind
        );
    }
}
