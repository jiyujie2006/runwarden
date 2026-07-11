//! Crate-private external MCP transports reachable only from the native executor.

mod http;
mod sse;
mod stdio;

use std::path::Path;

use runwarden_kernel::{
    KernelProvider, ProviderClass, ProviderContract, ProviderKind, ProviderManifest,
};
use time::OffsetDateTime;

use crate::executor::{
    ExecutionPermit, PermitVerifier, ProviderExecutionRequest, ProviderExecutionResult,
};

pub(crate) struct ExternalMcpRuntime<'a> {
    pub(crate) permit_verifier: &'a PermitVerifier,
    pub(crate) canonical_provider: &'a KernelProvider,
    pub(crate) trusted_runtime_root: &'a Path,
    pub(crate) now: OffsetDateTime,
}

pub(crate) fn validate_registration(
    manifest: &ProviderManifest,
    canonical_provider: &KernelProvider,
    trusted_runtime_root: &Path,
) -> Result<(), &'static str> {
    if manifest.provider_class != ProviderClass::External || manifest.kind != ProviderKind::Mcp {
        return Err("external_mcp_manifest_required");
    }
    let contract = ProviderContract::from_manifest(manifest);
    if contract.schema_rug_pull_detected
        || manifest.schema_pin.algorithm != "sha256"
        || manifest.schema_pin.digest
            != runwarden_kernel::schema_digest(&manifest.schema_pin.schema)
    {
        return Err("schema_pin_invalid");
    }
    if &contract.provider != canonical_provider {
        return Err("provider_contract_mismatch");
    }
    match manifest.transport.as_deref() {
        Some("stdio") => stdio::validate_registration(manifest, trusted_runtime_root),
        Some("http") => http::validate_registration(manifest),
        Some("sse") => sse::validate_registration(manifest),
        _ => Err("adapter_transport_unsupported"),
    }
}

pub(crate) fn execute_mediated_external_mcp_adapter(
    manifest: &ProviderManifest,
    permit: &ExecutionPermit,
    request: &ProviderExecutionRequest,
    runtime: &ExternalMcpRuntime<'_>,
) -> ProviderExecutionResult {
    // The capability check deliberately precedes every read of the manifest or
    // every filesystem, DNS, socket, and process operation in transport code.
    if runtime
        .permit_verifier
        .validate(permit, request, runtime.canonical_provider, runtime.now)
        .is_err()
    {
        return ProviderExecutionResult::blocked(
            "execution_permit_invalid",
            "permit_validation_failed",
        );
    }
    if validate_registration(
        manifest,
        runtime.canonical_provider,
        runtime.trusted_runtime_root,
    )
    .is_err()
    {
        return ProviderExecutionResult::blocked(
            "provider_contract_invalid",
            "adapter_registration_invalid",
        );
    }

    let result = match manifest.transport.as_deref() {
        Some("stdio") => stdio::execute(manifest, request, runtime),
        Some("http") => http::execute(manifest, request, runtime),
        Some("sse") => sse::execute(manifest, request, runtime),
        _ => ProviderExecutionResult::blocked(
            "provider_transport_invalid",
            "adapter_transport_unsupported",
        ),
    };
    if result.validate_against(request.budget_charge).is_ok() {
        result
    } else {
        ProviderExecutionResult::outcome_unknown(
            "provider_result_invalid",
            "adapter_result_invalid",
            request.budget_charge,
        )
        .unwrap_or_else(|_| {
            ProviderExecutionResult::blocked("provider_result_invalid", "adapter_result_invalid")
        })
    }
}

fn manifest_has_network_or_credentials(manifest: &ProviderManifest) -> bool {
    use runwarden_kernel::{ProviderRisk, SideEffectKind};

    matches!(
        manifest.risk,
        ProviderRisk::NetworkActive | ProviderRisk::CredentialUse
    ) || manifest.side_effects.iter().any(|effect| {
        matches!(
            effect,
            SideEffectKind::Network | SideEffectKind::CredentialUse
        )
    }) || !manifest.allowed_origins.is_empty()
}
