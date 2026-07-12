//! The only MCP boundary exposed to agents.
//!
//! Security decisions remain in the Rust kernel/runtime/state/provider crates;
//! this crate validates JSON-RPC, derives trusted invocation identities, and
//! presents display-safe results.

mod approval_wait;
mod config;
mod provider_call;
mod server;
mod tools;

use anyhow::{Context as _, bail};
use serde_json::Value;

pub use config::{
    AgentConfigValidation, ProductionRuntime, production_server_from_env,
    validate_runwarden_only_agent_config,
};
pub use server::{
    InvocationKeyDeriver, InvocationKeyError, JsonRpcHandler, JsonRpcRequestId, McpServer,
};

const MAX_STDIO_FRAME_BYTES: usize = 1_048_576;

/// Compatibility helper for protocol tests. Every call constructs a throwaway
/// native story, session, journal, and executor under an isolated temporary
/// directory. Production code must use [`production_server_from_env`] instead.
pub fn handle_jsonrpc_message(body: &str) -> anyhow::Result<Option<Value>> {
    config::handle_compatibility_jsonrpc(body)
}

pub fn handle_jsonrpc_body(body: &str) -> anyhow::Result<Value> {
    Ok(handle_jsonrpc_message(body)?.unwrap_or(Value::Null))
}

pub fn handle_stdio_payload(payload: &str) -> anyhow::Result<String> {
    let body = decode_stdio_body(payload)?;
    let Some(response) = handle_jsonrpc_message(body)? else {
        return Ok(String::new());
    };
    let response_body = serde_json::to_string(&response).context("serialize JSON-RPC response")?;
    Ok(format!(
        "Content-Length: {}\r\n\r\n{}",
        response_body.len(),
        response_body
    ))
}

fn decode_stdio_body(payload: &str) -> anyhow::Result<&str> {
    if payload.len() > MAX_STDIO_FRAME_BYTES + 64 * 1_024 {
        bail!("MCP frame exceeds maximum size");
    }
    if !payload.starts_with("Content-Length:") {
        if payload.len() > MAX_STDIO_FRAME_BYTES {
            bail!("MCP raw payload exceeds maximum size");
        }
        return Ok(payload.trim());
    }
    let Some((headers, body)) = payload.split_once("\r\n\r\n") else {
        bail!("MCP frame is missing header terminator");
    };
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length:"))
        .context("MCP frame is missing Content-Length")?
        .trim()
        .parse::<usize>()
        .context("parse Content-Length")?;
    if length > MAX_STDIO_FRAME_BYTES {
        bail!("MCP frame Content-Length exceeds maximum size");
    }
    let bytes = body.as_bytes();
    if bytes.len() < length {
        bail!("MCP frame body is shorter than Content-Length");
    }
    std::str::from_utf8(&bytes[..length]).context("MCP frame body is not UTF-8")
}
