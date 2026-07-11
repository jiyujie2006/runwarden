use runwarden_kernel::ProviderManifest;

use super::ExternalMcpRuntime;
use crate::executor::{ProviderExecutionRequest, ProviderExecutionResult};
use crate::external::is_canonical_public_plain_http_origin;

/// Validate the frozen shape, then keep the transport unavailable until a
/// complete Streamable HTTP client binds a server-owned endpoint and one
/// absolute DNS/connect/read deadline. This prevents a catalog addition from
/// accidentally activating the quarantined transport.
pub(super) fn validate_registration(manifest: &ProviderManifest) -> Result<(), &'static str> {
    if manifest.allowed_origins.is_empty()
        || !manifest.command_allowlist.is_empty()
        || manifest.working_root.is_some()
        || manifest
            .allowed_origins
            .iter()
            .any(|origin| !is_canonical_public_plain_http_origin(origin))
    {
        return Err("http_registration_invalid");
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
