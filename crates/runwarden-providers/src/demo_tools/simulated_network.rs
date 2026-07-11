use runwarden_kernel::operation::SafeProviderOutput;
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use serde_json::{Value, json};

use super::{ToolError, ToolExecution};
use crate::resource_claims::{canonicalize_http_method, canonicalize_http_origin};

pub(crate) fn simulate_api_request(
    arguments: &Value,
    claim: &ResourceClaim,
) -> Result<ToolExecution, ToolError> {
    let ResourceClaim::Network { method, origin, .. } = claim else {
        return Err(ToolError::ClaimMismatch);
    };
    let argument_method = arguments
        .get("method")
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    let argument_url = arguments
        .get("url")
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    let canonical_method =
        canonicalize_http_method(argument_method).map_err(|_| ToolError::InvalidRequest)?;
    let canonical_origin =
        canonicalize_http_origin(argument_url).map_err(|_| ToolError::InvalidRequest)?;
    if &canonical_method != method || &canonical_origin != origin {
        return Err(ToolError::ClaimMismatch);
    }
    simulated_output("api_request_simulated", method, origin)
}

pub(crate) fn simulate_browser_open(
    arguments: &Value,
    claim: &ResourceClaim,
) -> Result<ToolExecution, ToolError> {
    let ResourceClaim::Network { method, origin, .. } = claim else {
        return Err(ToolError::ClaimMismatch);
    };
    let argument_url = arguments
        .get("url")
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    let canonical_origin =
        canonicalize_http_origin(argument_url).map_err(|_| ToolError::InvalidRequest)?;
    if method != "GET" || &canonical_origin != origin {
        return Err(ToolError::ClaimMismatch);
    }
    simulated_output("browser_open_simulated", method, origin)
}

fn simulated_output(
    effect_kind: &'static str,
    method: &str,
    origin: &str,
) -> Result<ToolExecution, ToolError> {
    // This payload is evidence about a counterfactual effect. This module has
    // no socket, DNS, HTTP, process, or browser dependency.
    let payload = json!({
        "effect_kind": effect_kind,
        "method": method,
        "origin": origin,
        "network_opened": false,
    });
    let bytes = canonical_json_v1(&payload);
    let length = u64::try_from(bytes.len()).map_err(|_| ToolError::LimitExceeded)?;
    Ok(ToolExecution::simulated(SafeProviderOutput::Network {
        status_code: 0,
        response_hash: Sha256Digest::from_bytes(&bytes),
        bytes: length,
    }))
}
