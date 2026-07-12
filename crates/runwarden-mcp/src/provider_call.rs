use runwarden_providers::catalog::canonical_runtime_provider_action;
use runwarden_runtime::{McpRuntime, RuntimeError, RuntimeRequest, RuntimeResponse};
use serde_json::Value;

use crate::server::{InvocationKeyDeriver, JsonRpcRequestId};

pub(crate) const PROVIDER_CALL_ALLOWED_ARGUMENT_KEYS: &[&str] = &[
    "provider",
    "input_text",
    "url",
    "method",
    "body",
    "path",
    "content",
    "to",
    "subject",
    "key",
    "value",
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProviderCallError {
    #[error("provider call arguments must be an object")]
    ArgumentsNotObject,
    #[error("provider call argument is not allowed: {0}")]
    UnknownArgument(String),
    #[error("provider call requires a bounded arguments.provider string")]
    ProviderMissing,
    #[error("provider does not have a canonical MCP action")]
    UnsupportedProvider,
    #[error("trusted invocation key derivation failed")]
    InvocationKey,
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
}

pub(crate) fn invoke_provider<R: McpRuntime>(
    runtime: &R,
    invocation_keys: &InvocationKeyDeriver,
    request_id: &JsonRpcRequestId,
    arguments: &Value,
) -> Result<RuntimeResponse, ProviderCallError> {
    let object = arguments
        .as_object()
        .ok_or(ProviderCallError::ArgumentsNotObject)?;
    if let Some(key) = object
        .keys()
        .find(|key| !PROVIDER_CALL_ALLOWED_ARGUMENT_KEYS.contains(&key.as_str()))
    {
        return Err(ProviderCallError::UnknownArgument(key.clone()));
    }
    let provider = object
        .get("provider")
        .and_then(Value::as_str)
        .filter(|provider| {
            !provider.is_empty()
                && provider.len() <= 128
                && provider.is_ascii()
                && !provider.bytes().any(|byte| byte.is_ascii_control())
        })
        .ok_or(ProviderCallError::ProviderMissing)?;
    let action = canonical_runtime_provider_action(provider)
        .ok_or(ProviderCallError::UnsupportedProvider)?
        .to_owned();
    let mut provider_arguments = object.clone();
    provider_arguments.remove("provider");
    let invocation_key = invocation_keys
        .derive(request_id, "runwarden.provider.call")
        .map_err(|_| ProviderCallError::InvocationKey)?;
    runtime
        .invoke(RuntimeRequest {
            invocation_key,
            provider: provider.to_owned(),
            action,
            arguments: Value::Object(provider_arguments),
            parent_model_call_id: None,
            proposed_tool_call_id: None,
        })
        .map_err(ProviderCallError::Runtime)
}
