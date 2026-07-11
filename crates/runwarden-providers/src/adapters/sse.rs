use super::ExternalMcpRuntime;
use crate::executor::{ProviderExecutionRequest, ProviderExecutionResult};
use crate::external::is_canonical_public_plain_http_origin;
use runwarden_kernel::ProviderManifest;

/// Legacy SSE requires a stateful endpoint negotiation and message channel.
/// Keep it explicitly unavailable rather than treating an arbitrary `data:`
/// line as proof that a tool call completed.
pub(super) fn validate_registration(manifest: &ProviderManifest) -> Result<(), &'static str> {
    if manifest.allowed_origins.is_empty()
        || !manifest.command_allowlist.is_empty()
        || manifest.working_root.is_some()
        || manifest
            .allowed_origins
            .iter()
            .any(|origin| !is_canonical_public_plain_http_origin(origin))
    {
        return Err("sse_registration_invalid");
    }
    Err("network_adapter_not_enabled")
}

pub(super) fn execute(
    _manifest: &ProviderManifest,
    _request: &ProviderExecutionRequest,
    _runtime: &ExternalMcpRuntime<'_>,
) -> ProviderExecutionResult {
    ProviderExecutionResult::blocked(
        "provider_transport_unavailable",
        "network_adapter_not_enabled",
    )
}
