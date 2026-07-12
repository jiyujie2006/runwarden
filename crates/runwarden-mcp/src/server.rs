use std::sync::Arc;

use hmac::Mac as _;
use runwarden_kernel::story::InvocationKey;
use runwarden_runtime::McpRuntime;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::tools;

const MAX_JSONRPC_REQUEST_BYTES: usize = 1_048_576;
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

pub trait JsonRpcHandler {
    fn handle_jsonrpc(&self, body: &str) -> anyhow::Result<Option<Value>>;
}

pub struct McpServer<R> {
    runtime: Arc<R>,
    max_request_bytes: usize,
    invocation_keys: InvocationKeyDeriver,
}

impl<R: McpRuntime> McpServer<R> {
    pub fn new(
        runtime: Arc<R>,
        max_request_bytes: usize,
        invocation_keys: InvocationKeyDeriver,
    ) -> Self {
        Self {
            runtime,
            max_request_bytes: max_request_bytes.min(MAX_JSONRPC_REQUEST_BYTES),
            invocation_keys,
        }
    }

    pub fn handle_jsonrpc(&self, body: &str) -> anyhow::Result<Option<Value>> {
        handle_jsonrpc_impl(
            self.runtime.as_ref(),
            &self.invocation_keys,
            self.max_request_bytes,
            body,
        )
    }
}

impl<R: McpRuntime> JsonRpcHandler for McpServer<R> {
    fn handle_jsonrpc(&self, body: &str) -> anyhow::Result<Option<Value>> {
        McpServer::handle_jsonrpc(self, body)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum JsonRpcRequestId {
    String(String),
    Integer(i64),
}

impl JsonRpcRequestId {
    pub(crate) fn response_value(&self) -> Value {
        match self {
            Self::String(value) => Value::String(value.clone()),
            Self::Integer(value) => json!(value),
        }
    }
}

impl<'de> Deserialize<'de> for JsonRpcRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::try_from(&value).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&Value> for JsonRpcRequestId {
    type Error = InvocationKeyError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        match value {
            Value::String(value) if value.len() <= 1_024 => Ok(Self::String(value.clone())),
            Value::Number(value) => value
                .as_i64()
                .filter(|value| value.unsigned_abs() <= MAX_SAFE_JSON_INTEGER as u64)
                .map(Self::Integer)
                .ok_or(InvocationKeyError::InvalidRequestId),
            _ => Err(InvocationKeyError::InvalidRequestId),
        }
    }
}

pub struct InvocationKeyDeriver {
    active_instance_id: String,
    instance_token: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvocationKeyError {
    #[error("trusted instance binding is empty or invalid")]
    EmptyTrustedBinding,
    #[error("JSON-RPC request id is invalid")]
    InvalidRequestId,
    #[error("tool name is invalid")]
    InvalidToolName,
    #[error("invocation key material could not be serialized")]
    Serialization,
}

impl InvocationKeyDeriver {
    pub fn from_trusted_instance(
        active_instance_id: String,
        instance_token: Zeroizing<Vec<u8>>,
    ) -> Result<Self, InvocationKeyError> {
        if active_instance_id.is_empty()
            || active_instance_id.len() > 256
            || active_instance_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || instance_token.is_empty()
            || instance_token.len() > 4_096
        {
            return Err(InvocationKeyError::EmptyTrustedBinding);
        }
        Ok(Self {
            active_instance_id,
            instance_token,
        })
    }

    pub fn derive(
        &self,
        request_id: &JsonRpcRequestId,
        tool_name: &str,
    ) -> Result<InvocationKey, InvocationKeyError> {
        if tool_name.is_empty()
            || tool_name.len() > 128
            || !tool_name.is_ascii()
            || tool_name.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(InvocationKeyError::InvalidToolName);
        }
        let material = json!({
            "schema_version": "1.0.0",
            "active_instance_id": self.active_instance_id.as_str(),
            "request_id": request_id,
            "tool_name": tool_name,
        });
        let canonical = runwarden_kernel::trace::canonical_json_v1(&material);
        let mut mac =
            <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(self.instance_token.as_slice())
                .map_err(|_| InvocationKeyError::Serialization)?;
        mac.update(&canonical);
        let tag = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&tag);
        Ok(InvocationKey::from_hmac_bytes(bytes))
    }
}

pub(crate) fn handle_jsonrpc_impl<R: McpRuntime>(
    runtime: &R,
    invocation_keys: &InvocationKeyDeriver,
    max_request_bytes: usize,
    body: &str,
) -> anyhow::Result<Option<Value>> {
    if max_request_bytes == 0 || body.len() > max_request_bytes {
        anyhow::bail!("MCP JSON-RPC request exceeds maximum size");
    }
    let request: Value = match serde_json::from_str(body) {
        Ok(request) => request,
        Err(_) => {
            return Ok(Some(jsonrpc_error(
                Value::Null,
                -32700,
                "JSON-RPC request is not valid JSON",
                json!({"side_effect_executed": false}),
            )));
        }
    };
    let Some(object) = request.as_object() else {
        return Ok(Some(jsonrpc_error(
            Value::Null,
            -32600,
            "JSON-RPC request must be an object",
            json!({"side_effect_executed": false}),
        )));
    };
    let raw_id = object.get("id");
    let response_id = raw_id
        .and_then(|id| JsonRpcRequestId::try_from(id).ok())
        .map(|id| id.response_value())
        .unwrap_or(Value::Null);
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Ok(Some(jsonrpc_error(
            response_id,
            -32600,
            "JSON-RPC request is missing method",
            json!({"side_effect_executed": false}),
        )));
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Ok(Some(jsonrpc_error(
            response_id,
            -32600,
            "JSON-RPC version must be 2.0",
            json!({"side_effect_executed": false}),
        )));
    }

    // A notification has no response and, critically, cannot invoke any tool.
    let Some(raw_id) = raw_id else {
        return Ok(None);
    };
    let request_id = match JsonRpcRequestId::try_from(raw_id) {
        Ok(request_id) => request_id,
        Err(_) => {
            return Ok(Some(jsonrpc_error(
                Value::Null,
                -32600,
                "JSON-RPC id must be a bounded string or interoperable integer",
                json!({"side_effect_executed": false}),
            )));
        }
    };
    let id = request_id.response_value();

    match method {
        "initialize" => {
            let protocol_version = object
                .get("params")
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("2025-03-26");
            Ok(Some(jsonrpc_ok(
                id,
                json!({
                    "protocolVersion": protocol_version,
                    "serverInfo": {
                        "name": "runwarden-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {"tools": {"listChanged": false}}
                }),
            )))
        }
        "tools/list" => Ok(Some(jsonrpc_ok(
            id,
            json!({"tools": tools::tool_descriptors()}),
        ))),
        "tools/call" => Ok(Some(tools::handle_tools_call(
            runtime,
            invocation_keys,
            &request_id,
            id,
            object.get("params"),
        ))),
        _ => Ok(Some(jsonrpc_error(
            id,
            -32601,
            "method is not supported by Runwarden MCP",
            json!({"method": method, "side_effect_executed": false}),
        ))),
    }
}

pub(crate) fn jsonrpc_ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub(crate) fn jsonrpc_error(id: Value, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message, "data": data}
    })
}
