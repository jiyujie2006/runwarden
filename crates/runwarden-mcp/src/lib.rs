use anyhow::{Context, bail};
use runwarden_anomaly::{AnomalyMonitor, BehaviorProfile};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report,
};
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery, hex_sha256};
use runwarden_kernel::kernel::{
    KernelEnforcer, KernelPolicy, ProviderRegistry, ScopedRoot, provider_requires_approval,
};
use runwarden_kernel::{ErrorKind, KernelProvider, PolicyDecision, ProviderCall, ProviderOutcome};
use runwarden_providers::catalog::{
    default_external_provider_manifests, default_external_providers, default_first_party_providers,
    full_provider_registry,
};
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use runwarden_providers::tools;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use url::Url;

const RUNWARDEN_TOOLS: &[(&str, &str)] = &[
    (
        "runwarden.agent.bootstrap",
        "Return the agent-facing Runwarden-only security boundary.",
    ),
    (
        "runwarden.provider.call",
        "Submit a provider call to the Runwarden kernel mediation path.",
    ),
    (
        "runwarden.provider.list",
        "Return kernel-managed providers available to the current session.",
    ),
    (
        "runwarden.provider.status",
        "Return provider availability, risk, side effects, and approval requirements.",
    ),
    (
        "runwarden.trace.verify",
        "Verify the Runwarden trace hash chain before export or report use.",
    ),
    (
        "runwarden.trace.export",
        "Export verified trace evidence through the Runwarden artifact boundary.",
    ),
    (
        "runwarden.report.lint",
        "Lint report claims against obs_* trace references.",
    ),
    (
        "runwarden.report.render",
        "Render a cited report through the citation enforcement boundary.",
    ),
];
const MAX_STDIO_FRAME_BYTES: usize = 1_048_576;
const MCP_INLINE_MAX_ARGUMENT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfigValidation {
    pub ok: bool,
    pub errors: Vec<String>,
    pub side_effect_executed: bool,
}

pub fn validate_runwarden_only_agent_config(config: &Value) -> AgentConfigValidation {
    let mut errors = Vec::new();
    let has_claude_shape = config.get("mcpServers").is_some();
    let has_opencode_shape = config.get("mcp").is_some();

    match (has_claude_shape, has_opencode_shape) {
        (true, false) => validate_claude_mcp_config(config, &mut errors),
        (false, true) => validate_opencode_mcp_config(config, &mut errors),
        (true, true) => {
            errors.push("agent config must not define both mcpServers and mcp".to_string())
        }
        (false, false) => {
            errors.push("agent config must define exactly one Runwarden MCP server".to_string())
        }
    }

    AgentConfigValidation {
        ok: errors.is_empty(),
        errors,
        side_effect_executed: false,
    }
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

pub fn handle_jsonrpc_body(body: &str) -> anyhow::Result<Value> {
    Ok(handle_jsonrpc_message(body)?.unwrap_or(Value::Null))
}

pub fn handle_jsonrpc_message(body: &str) -> anyhow::Result<Option<Value>> {
    let request: Value = serde_json::from_str(body).context("parse JSON-RPC request")?;
    let Some(id) = request.get("id").cloned() else {
        return Ok(None);
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Ok(Some(jsonrpc_error(
            id,
            -32600,
            "JSON-RPC request is missing method",
            json!({"side_effect_executed": false}),
        )));
    };

    match method {
        "initialize" => {
            // Echo the client's offered protocol version so newer clients
            // (e.g. opencode, which sends "2025-11-25") don't reject the
            // server for advertising an older version than they support.
            let protocol_version = request
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
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    }
                }),
            )))
        }
        "tools/list" => Ok(Some(jsonrpc_ok(id, json!({ "tools": tool_descriptors() })))),
        "tools/call" => Ok(Some(handle_tools_call(id, request.get("params")))),
        _ => Ok(Some(jsonrpc_error(
            id,
            -32601,
            "method is not supported by Runwarden MCP",
            json!({"method": method, "side_effect_executed": false}),
        ))),
    }
}

fn decode_stdio_body(payload: &str) -> anyhow::Result<&str> {
    if payload.len() > MAX_STDIO_FRAME_BYTES + 64 * 1024 {
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

    if body.len() < length {
        bail!("MCP frame body is shorter than Content-Length");
    }

    Ok(&body[..length])
}

fn tool_descriptors() -> Vec<Value> {
    RUNWARDEN_TOOLS
        .iter()
        .map(|(name, description)| {
            json!({
                "name": name,
                "description": description,
                "inputSchema": tool_input_schema(name),
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": true
                }
            })
        })
        .collect()
}

fn tool_input_schema(name: &str) -> Value {
    match name {
        "runwarden.provider.call" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["provider"],
            "properties": provider_call_schema_properties()
        }),
        "runwarden.provider.list" => json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }),
        "runwarden.provider.status" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["provider"],
            "properties": {
                "provider": { "type": "string" }
            }
        }),
        _ => json!({
            "type": "object",
            "additionalProperties": true
        }),
    }
}

fn provider_call_schema_properties() -> Value {
    json!({
        "provider": { "type": "string" },
        "action": { "type": "string" },
        "input_text": { "type": "string" },
        "input_path": { "type": "string" },
        "input_source": { "type": "string" },
        "trace_path": { "type": "string" },
        "report_path": { "type": "string" },
        "format": { "type": "string" },
        "url": { "type": "string" },
        "method": { "type": "string" },
        "body": {},
        "path": { "type": "string" },
        "to": { "type": "string" },
        "subject": { "type": "string" },
        "content": { "type": "string" },
        "key": { "type": "string" },
        "value": {},
        "query": {},
        "payload": {},
        "trace_events": { "type": "array" },
        "report": { "type": "object" }
    })
}

fn handle_tools_call(id: Value, params: Option<&Value>) -> Value {
    let Some(tool_name) = params
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
    else {
        return jsonrpc_error(
            id,
            -32602,
            "tools/call params.name is required",
            json!({"side_effect_executed": false}),
        );
    };

    if let Err(message) = validate_no_policy_envelope_arguments(tool_arguments(params), tool_name) {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }

    match tool_name {
        "runwarden.agent.bootstrap" => tool_result(
            id,
            json!({
                "architecture": "agent_native_security_kernel",
                "agent_only_sees_runwarden": true,
                "all_tools_are_kernel_managed_providers": true,
                "raw_side_effect_tools_allowed": false
            }),
        ),
        "runwarden.provider.call" => handle_provider_call(id, params),
        "runwarden.provider.list" => handle_provider_list(id, params),
        "runwarden.provider.status" => handle_provider_status(id, params),
        "runwarden.trace.verify" => handle_trace_verify(id, tool_arguments(params)),
        "runwarden.trace.export" => handle_trace_export(id, tool_arguments(params)),
        "runwarden.report.lint" => handle_report_lint(id, params),
        "runwarden.report.render" => handle_report_render(id, params),
        _ => jsonrpc_error(
            id,
            -32602,
            "tool is not exposed by Runwarden MCP boundary",
            json!({
                "tool": tool_name,
                "side_effect_executed": false
            }),
        ),
    }
}

fn handle_provider_call(id: Value, params: Option<&Value>) -> Value {
    let empty_arguments = json!({});
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&empty_arguments);
    let sandbox_root = tools::sandbox_root_from();
    if let Err(message) = validate_argument_object(
        arguments,
        PROVIDER_CALL_ALLOWED_ARGUMENT_KEYS,
        "provider call",
    ) {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
    let Some(provider) = arguments.get("provider").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            -32602,
            "provider call requires arguments.provider",
            json!({"side_effect_executed": false}),
        );
    };

    let mut call = provider_call_from_arguments(provider, arguments);
    let approvals = read_all_approvals_mcp().unwrap_or_default();
    attach_matching_approval_mcp(&mut call, &approvals);
    let mut enforcer = KernelEnforcer::new(full_provider_registry(), mcp_kernel_policy());
    for approval in approvals {
        enforcer.add_approval(approval);
    }
    let outcome = enforcer.evaluate_call(&call);
    if outcome.decision != PolicyDecision::Allowed {
        persist_pending_approval_mcp(&call, &outcome).ok();
        let payload = provider_outcome_payload(&outcome, Some(arguments));
        let payload = append_mcp_provider_event(&outcome, &payload).unwrap_or(payload);
        return tool_error_result(id, payload);
    }

    let payload = match provider {
        "runwarden.input.inspect" => {
            let input_text = arguments
                .get("input_text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let input_source =
                parse_input_source(arguments.get("input_source").and_then(Value::as_str));
            let inspection = inspect_input(
                input_source,
                input_text.as_bytes(),
                InputInspectPolicy::default(),
            );
            json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "obs_ref": &outcome.observation_id,
                "trace_event": trace_event_for_provider_result(
                    &outcome,
                    "provider_completed",
                    "completed",
                    false,
                    false,
                    None
                ),
                "output": inspection
            })
        }
        other if provider_is_external(other) => {
            external_provider_result(&outcome, arguments, &sandbox_root)
        }
        other => {
            return tool_error_result(
                id,
                json!({
                "error_kind": ErrorKind::ProviderUnknown,
                "message": "provider is not implemented by the MCP inline call path",
                "provider": other,
                "side_effect_executed": false
                }),
            );
        }
    };

    if let Some(approval_id) = call.approval_id.as_deref()
        && enforcer.approval_state(approval_id) == Some(ApprovalState::Consumed)
    {
        persist_consumed_approval_mcp(&call, &enforcer.approval_binding_for_call(&call)).ok();
    }
    let payload = append_mcp_provider_event(&outcome, &payload).unwrap_or(payload);
    tool_result(id, payload)
}

/// Map a caller-supplied `input_source` string to an `InputSource` so the
/// inspect tool no longer hardcodes `ToolInput` — callers (e.g. the LLM proxy
/// or a red-team harness) can declare whether the text is a user prompt, an
/// assistant message, a tool output, etc. Unknown values default to
/// `ToolInput` to preserve the prior behaviour.
fn parse_input_source(value: Option<&str>) -> InputSource {
    match value {
        Some("system_prompt") => InputSource::SystemPrompt,
        Some("user_prompt") => InputSource::UserPrompt,
        Some("assistant_message") => InputSource::AssistantMessage,
        Some("retrieved_knowledge") => InputSource::RetrievedKnowledge,
        Some("memory_entry") => InputSource::MemoryEntry,
        Some("tool_input") => InputSource::ToolInput,
        Some("tool_output") => InputSource::ToolOutput,
        _ => InputSource::ToolInput,
    }
}

const PROVIDER_CALL_ALLOWED_ARGUMENT_KEYS: &[&str] = &[
    "provider",
    "action",
    "input_text",
    "input_path",
    "input_source",
    "trace_path",
    "report_path",
    "format",
    "url",
    "method",
    "body",
    "path",
    "to",
    "subject",
    "content",
    "key",
    "value",
    "query",
    "payload",
    "trace_events",
    "report",
];

const PROVIDER_LIST_ALLOWED_ARGUMENT_KEYS: &[&str] = &[];
const PROVIDER_STATUS_ALLOWED_ARGUMENT_KEYS: &[&str] = &["provider"];
const POLICY_ENVELOPE_ARGUMENT_KEYS: &[&str] = &[
    "session_id",
    "actor_id",
    "authz_id",
    "approval_id",
    "active_assessment",
    "session_allowed_providers",
    "session_roots",
    "authz_grants",
    "budget",
    "budgets",
    "root",
    "root_path",
    "sandbox_root",
    "simulated_approval",
];

fn validate_no_policy_envelope_arguments(arguments: &Value, label: &str) -> Result<(), String> {
    let Some(object) = arguments.as_object() else {
        return Ok(());
    };
    for key in object.keys() {
        if POLICY_ENVELOPE_ARGUMENT_KEYS.contains(&key.as_str()) {
            return Err(format!("{label} argument is not allowed: {key}"));
        }
    }
    Ok(())
}

fn validate_argument_object(
    arguments: &Value,
    allowed_keys: &[&str],
    label: &str,
) -> Result<(), String> {
    let Some(object) = arguments.as_object() else {
        return Err(format!("{label} arguments must be an object"));
    };
    for key in object.keys() {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(format!("{label} argument is not allowed: {key}"));
        }
    }
    Ok(())
}

fn validate_claude_mcp_config(config: &Value, errors: &mut Vec<String>) {
    let Some(servers) = config.get("mcpServers").and_then(Value::as_object) else {
        errors.push("mcpServers must be an object".to_string());
        return;
    };
    validate_single_runwarden_server(servers, "mcpServers", errors);
    let Some(server) = servers.get("runwarden") else {
        return;
    };
    validate_common_runwarden_server_fields(server, "mcpServers.runwarden", errors);
    if server.get("command").and_then(Value::as_str) != Some("runwarden-mcp") {
        errors.push("mcpServers.runwarden.command must be exactly runwarden-mcp".to_string());
    }
}

fn validate_opencode_mcp_config(config: &Value, errors: &mut Vec<String>) {
    let Some(servers) = config.get("mcp").and_then(Value::as_object) else {
        errors.push("mcp must be an object".to_string());
        return;
    };
    validate_single_runwarden_server(servers, "mcp", errors);
    let Some(server) = servers.get("runwarden") else {
        return;
    };
    validate_common_runwarden_server_fields(server, "mcp.runwarden", errors);
    if server.get("type").and_then(Value::as_str) != Some("local") {
        errors.push("mcp.runwarden.type must be local".to_string());
    }
    if server.get("enabled").and_then(Value::as_bool) == Some(false) {
        errors.push("mcp.runwarden.enabled must not be false".to_string());
    }
    let command_ok = server
        .get("command")
        .and_then(Value::as_array)
        .is_some_and(|items| items.len() == 1 && items[0].as_str() == Some("runwarden-mcp"));
    if !command_ok {
        errors.push("mcp.runwarden.command must be exactly [\"runwarden-mcp\"]".to_string());
    }

    let Some(tools) = config.get("tools").and_then(Value::as_object) else {
        errors.push("OpenCode config must disable built-in tools".to_string());
        return;
    };
    for (name, value) in tools {
        if value.as_bool() != Some(false) {
            errors.push(format!("OpenCode built-in tool must be disabled: {name}"));
        }
    }
}

fn validate_single_runwarden_server(
    servers: &serde_json::Map<String, Value>,
    label: &str,
    errors: &mut Vec<String>,
) {
    if servers.len() != 1 || !servers.contains_key("runwarden") {
        errors.push(format!(
            "{label} must contain exactly one server named runwarden"
        ));
    }
}

fn validate_common_runwarden_server_fields(server: &Value, label: &str, errors: &mut Vec<String>) {
    let Some(server_object) = server.as_object() else {
        errors.push(format!("{label} must be an object"));
        return;
    };
    for field in ["env", "environment", "cwd", "url", "transport"] {
        if server_object.contains_key(field) {
            errors.push(format!("{label}.{field} must not be set"));
        }
    }
    if let Some(args) = server_object.get("args")
        && !args.as_array().is_some_and(Vec::is_empty)
    {
        errors.push(format!("{label}.args must be an empty array when present"));
    }
}

fn provider_call_from_arguments(provider: &str, arguments: &Value) -> ProviderCall {
    ProviderCall {
        session_id: "mcp-inline".to_string(),
        provider: provider.to_string(),
        action: arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("call")
            .to_string(),
        arguments: arguments.clone(),
        actor_id: Some("mcp-agent".to_string()),
        authz_id: None,
        approval_id: None,
    }
}

fn state_dir_mcp() -> PathBuf {
    std::env::var("RUNWARDEN_STATE_DIR")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".runwarden"))
}

fn approvals_dir_mcp() -> PathBuf {
    state_dir_mcp().join("approvals")
}

fn read_all_approvals_mcp() -> anyhow::Result<Vec<ApprovalRecord>> {
    let dir = approvals_dir_mcp();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut approvals = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let body = std::fs::read_to_string(entry.path())?;
        if let Ok(approval) = serde_json::from_str::<ApprovalRecord>(&body) {
            approvals.push(approval);
        }
    }
    Ok(approvals)
}

fn approval_binding_for_mcp_call(call: &ProviderCall) -> ApprovalBinding {
    ApprovalBinding {
        session_id: call.session_id.clone(),
        provider: call.provider.clone(),
        action: call.action.clone(),
        argument_hash: hex_sha256(&serde_json::to_vec(&call.arguments).unwrap_or_default()),
        authz_id: call.authz_id.clone(),
        actor_id: call.actor_id.clone(),
    }
}

fn attach_matching_approval_mcp(call: &mut ProviderCall, approvals: &[ApprovalRecord]) {
    let binding = approval_binding_for_mcp_call(call);
    if let Some(approval) = approvals.iter().find(|approval| {
        approval.binding == binding
            && approval.state == ApprovalState::Approved
            && approval
                .expires_at
                .is_none_or(|expires_at| expires_at > time::OffsetDateTime::now_utc())
    }) {
        call.approval_id = Some(approval.approval_id.clone());
    }
}

fn persist_pending_approval_mcp(
    call: &ProviderCall,
    outcome: &ProviderOutcome,
) -> anyhow::Result<()> {
    if outcome.decision != PolicyDecision::RequiresReview {
        return Ok(());
    }
    let approval_id = format!("webui-{}", outcome.observation_id);
    let path = approvals_dir_mcp().join(format!("{approval_id}.json"));
    if path.exists() {
        return Ok(());
    }
    let approval = ApprovalRecord::new(approval_id, approval_binding_for_mcp_call(call));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&approval)?)?;
    Ok(())
}

fn persist_consumed_approval_mcp(
    call: &ProviderCall,
    binding: &ApprovalBinding,
) -> anyhow::Result<()> {
    let Some(approval_id) = call.approval_id.as_deref() else {
        return Ok(());
    };
    let path = approvals_dir_mcp().join(format!("{approval_id}.json"));
    let body = std::fs::read_to_string(&path)?;
    let mut approval = serde_json::from_str::<ApprovalRecord>(&body)?;
    if approval.state == ApprovalState::Approved {
        approval.consume_once(binding)?;
        std::fs::write(path, serde_json::to_string_pretty(&approval)?)?;
    }
    Ok(())
}

fn append_mcp_provider_event(outcome: &ProviderOutcome, payload: &Value) -> anyhow::Result<Value> {
    let path = state_dir_mcp().join("events.jsonl");
    append_mcp_provider_event_to_path(&path, outcome, payload)
}

fn append_mcp_provider_event_to_path(
    path: &Path,
    outcome: &ProviderOutcome,
    payload: &Value,
) -> anyhow::Result<Value> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut payload = payload.clone();
    if let Some(trace_event) = payload
        .get("trace_event")
        .and_then(|value| serde_json::from_value::<TraceEvent>(value.clone()).ok())
    {
        let trace_event = TraceEvent::sealed(
            trace_event.obs_id,
            trace_event.event_type,
            trace_event.provider,
            trace_event.payload,
            last_mcp_provider_event_hash(path)?,
        );
        payload["trace_event"] = serde_json::to_value(trace_event)?;
    }
    let event = json!({
        "kind": "provider_call",
        "provider": &outcome.envelope.provider,
        "action": &outcome.envelope.action,
        "decision": &outcome.decision,
        "error_kind": &outcome.envelope.error_kind,
        "reason": &outcome.envelope.reason,
        "obs_ref": &outcome.observation_id,
        "approval_id": if outcome.decision == PolicyDecision::RequiresReview {
            json!(format!("webui-{}", outcome.observation_id))
        } else {
            Value::Null
        },
        "side_effect_executed": payload
            .get("side_effect_executed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "data": payload
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    Ok(payload)
}

fn last_mcp_provider_event_hash(path: &Path) -> anyhow::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    Ok(content.lines().rev().find_map(|line| {
        let event: Value = serde_json::from_str(line).ok()?;
        let trace_event: TraceEvent =
            serde_json::from_value(event.get("data")?.get("trace_event")?.clone()).ok()?;
        Some(trace_event.event_hash)
    }))
}

fn first_party_provider_registry() -> ProviderRegistry {
    let mut registry = ProviderRegistry::default();
    for provider in default_first_party_providers() {
        registry.register(provider);
    }
    registry
}

fn all_kernel_managed_providers() -> Vec<KernelProvider> {
    default_first_party_providers()
        .into_iter()
        .chain(default_external_providers())
        .collect()
}

fn mcp_kernel_policy() -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.active_assessment = true;
    policy.max_argument_bytes = Some(MCP_INLINE_MAX_ARGUMENT_BYTES);
    policy.add_scoped_root(ScopedRoot::new(
        "mcp-inline-sandbox",
        tools::sandbox_root_from(),
    ));
    for provider in all_kernel_managed_providers() {
        policy.allow_provider(provider.id);
    }
    for manifest in default_external_provider_manifests() {
        for origin in manifest.allowed_origins {
            if let Some(host) = public_host_from_origin(&origin) {
                policy.allow_egress_host(host);
            }
        }
    }
    policy
}

fn mcp_single_provider_policy(provider: &str) -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.active_assessment = true;
    policy.max_argument_bytes = Some(MCP_INLINE_MAX_ARGUMENT_BYTES);
    policy.allow_provider(provider);
    policy
}

fn public_host_from_origin(origin: &str) -> Option<String> {
    let url = Url::parse(origin).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str().map(normalize_host)?;
    (!is_private_or_local_host(&host)).then_some(host)
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_private_or_local_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }

    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };

    match ip {
        IpAddr::V4(addr) => is_private_or_local_ipv4(addr),
        IpAddr::V6(addr) => {
            if let Some(mapped) = addr.to_ipv4_mapped() {
                return is_private_or_local_ipv4(mapped);
            }
            addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_unique_local()
                || addr.is_unicast_link_local()
        }
    }
}

fn is_private_or_local_ipv4(addr: Ipv4Addr) -> bool {
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_unspecified()
        || is_carrier_grade_nat(addr)
}

fn is_carrier_grade_nat(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn tool_arguments(params: Option<&Value>) -> &Value {
    params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null)
}

fn provider_outcome_payload(outcome: &ProviderOutcome, arguments: Option<&Value>) -> Value {
    let anomaly = if provider_is_external(&outcome.envelope.provider) {
        arguments.map(|arguments| analyze_anomaly(outcome, arguments))
    } else {
        None
    };
    let mut payload = serde_json::to_value(outcome).expect("provider outcome serializes");
    payload["provider"] = json!(&outcome.envelope.provider);
    payload["action"] = json!(&outcome.envelope.action);
    payload["error_kind"] = json!(&outcome.envelope.error_kind);
    payload["reason"] = json!(&outcome.envelope.reason);
    payload["side_effect_executed"] = json!(outcome.envelope.side_effect_executed);
    payload["obs_ref"] = json!(&outcome.observation_id);
    payload["trace_event"] = trace_event_for_outcome(outcome, anomaly.as_ref());
    if let Some(anomaly) = anomaly {
        payload["anomaly"] = anomaly;
    }
    payload
}

fn trace_event_for_outcome(outcome: &ProviderOutcome, anomaly: Option<&Value>) -> Value {
    let event_type = match outcome.decision {
        PolicyDecision::Allowed => "provider_policy_evaluated",
        PolicyDecision::Denied => "provider_denied",
        PolicyDecision::RequiresReview => "provider_approval_pending",
    };
    trace_event_for_provider_result(
        outcome,
        event_type,
        serde_json::to_value(&outcome.execution_status)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .as_deref()
            .unwrap_or("not_executed"),
        false,
        outcome.envelope.side_effect_executed,
        anomaly,
    )
}

fn trace_event_for_provider_result(
    outcome: &ProviderOutcome,
    event_type: &str,
    execution_status: &str,
    simulated: bool,
    side_effect_executed: bool,
    anomaly: Option<&Value>,
) -> Value {
    let mut payload = json!({
        "provider": &outcome.envelope.provider,
        "action": &outcome.envelope.action,
        "decision": &outcome.decision,
        "execution_status": execution_status,
        "gate_id": &outcome.envelope.gate_id,
        "reason": &outcome.envelope.reason,
        "error_kind": &outcome.envelope.error_kind,
        "side_effect_executed": side_effect_executed,
        "simulated": simulated
    });
    if let Some(anomaly) = anomaly {
        payload["anomaly"] = anomaly.clone();
    }
    let event = TraceEvent::sealed(
        outcome.observation_id.clone(),
        event_type.to_string(),
        Some(outcome.envelope.provider.clone()),
        payload,
        None,
    );
    serde_json::to_value(event).expect("trace event serializes")
}

fn anomaly_monitors() -> &'static Mutex<HashMap<String, AnomalyMonitor>> {
    static STORE: OnceLock<Mutex<HashMap<String, AnomalyMonitor>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(normalize_host))
}

/// Run the behavior-anomaly monitor for an allowed external provider call and
/// return its report as a JSON value. Per-session so the monitor can track the
/// provider sequence across calls within a session.
fn analyze_anomaly(outcome: &ProviderOutcome, arguments: &Value) -> Value {
    let session_id = "mcp-inline".to_string();
    let provider = &outcome.envelope.provider;
    let arg_bytes = serde_json::to_vec(arguments).map(|v| v.len()).unwrap_or(0);
    let egress_host = arguments
        .get("url")
        .and_then(Value::as_str)
        .and_then(host_of);
    let report = match anomaly_monitors().lock() {
        Ok(mut store) => {
            let monitor = store
                .entry(session_id)
                .or_insert_with(|| AnomalyMonitor::new(BehaviorProfile::default_benign()));
            monitor.analyze(provider, arg_bytes, egress_host.as_deref())
        }
        Err(_) => runwarden_anomaly::AnomalyReport {
            score: 0,
            is_anomalous: false,
            reasons: vec!["anomaly monitor lock poisoned".to_string()],
        },
    };
    serde_json::to_value(&report)
        .unwrap_or(json!({"is_anomalous": false, "score": 0, "reasons": []}))
}

fn external_provider_result(
    outcome: &ProviderOutcome,
    arguments: &Value,
    sandbox_root: &Path,
) -> Value {
    let executed = tools::execute_external_tool(
        &outcome.envelope.provider,
        &outcome.envelope.action,
        arguments,
        sandbox_root,
    );
    let execution_status = executed
        .get("execution_status")
        .and_then(Value::as_str)
        .unwrap_or("simulated");
    let simulated = executed
        .get("simulated")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let side_effect_executed = executed
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let event_type = if simulated {
        "provider_simulated_replay"
    } else {
        "provider_completed"
    };
    let anomaly = analyze_anomaly(outcome, arguments);
    json!({
        "provider": &outcome.envelope.provider,
        "action": &outcome.envelope.action,
        "decision": "allowed",
        "execution_status": execution_status,
        "simulated": simulated,
        "side_effect_executed": side_effect_executed,
        "obs_ref": &outcome.observation_id,
        "trace_event": trace_event_for_provider_result(
            outcome,
            event_type,
            execution_status,
            simulated,
            side_effect_executed,
            Some(&anomaly)
        ),
        "output": executed.get("output").cloned().unwrap_or(Value::Null),
        "anomaly": anomaly
    })
}

fn provider_is_external(provider_id: &str) -> bool {
    default_external_providers()
        .into_iter()
        .any(|provider| provider.id == provider_id)
}

fn inline_trace_events(arguments: &Value) -> Vec<TraceEvent> {
    serde_json::from_value(
        arguments
            .get("trace_events")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .unwrap_or_default()
}

fn handle_trace_verify(id: Value, arguments: &Value) -> Value {
    let trace_events = inline_trace_events(arguments);
    let verification = verify_inline_trace(&trace_events);
    tool_result(
        id,
        json!({
            "verified": verification["verified"],
            "event_count": verification["event_count"],
            "error": verification.get("error"),
            "side_effect_executed": false
        }),
    )
}

fn handle_trace_export(id: Value, arguments: &Value) -> Value {
    let trace_events = inline_trace_events(arguments);
    let verification = verify_inline_trace(&trace_events);
    if verification["verified"].as_bool() != Some(true) {
        return tool_error_result(
            id,
            json!({
                "exported": false,
                "verified": false,
                "verification": verification,
                "side_effect_executed": false
            }),
        );
    }

    let call = provider_call_from_arguments("runwarden.trace.export", arguments);
    let mut enforcer = KernelEnforcer::new(
        first_party_provider_registry(),
        mcp_single_provider_policy("runwarden.trace.export"),
    );
    let outcome = enforcer.evaluate_call(&call);
    if outcome.decision != PolicyDecision::Allowed {
        return tool_error_result(id, provider_outcome_payload(&outcome, None));
    }

    let mut store = InMemoryTraceStore::default();
    for event in trace_events {
        store.append(event);
    }
    let query = trace_query_from_args(arguments);
    let compact_refs = arguments
        .get("compact_refs")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let page = store.query(query);
    let refs: Vec<_> = page
        .events
        .iter()
        .map(|event| event.obs_id.clone())
        .collect();

    tool_result(
        id,
        json!({
            "exported": true,
            "verified": true,
            "page": page,
            "compact_refs": if compact_refs { json!(refs) } else { Value::Null },
            "side_effect_executed": false
        }),
    )
}

fn verify_inline_trace(trace_events: &[TraceEvent]) -> Value {
    let mut store = InMemoryTraceStore::default();
    for event in trace_events {
        store.append(event.clone());
    }
    match store.verify_hash_chain() {
        Ok(()) => json!({
            "verified": true,
            "event_count": trace_events.len()
        }),
        Err(err) => json!({
            "verified": false,
            "event_count": trace_events.len(),
            "error": {
                "kind": "trace_tampered",
                "offset": err.offset,
                "obs_id": err.obs_id,
                "message": err.reason
            }
        }),
    }
}

fn trace_query_from_args(arguments: &Value) -> TraceQuery {
    TraceQuery {
        offset: arguments
            .get("offset")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or(0),
        limit: arguments
            .get("limit")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or(100),
        provider: arguments
            .get("provider")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        event_type: arguments
            .get("event_type")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        obs_prefix: arguments
            .get("obs_prefix")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        max_bytes: arguments
            .get("max_bytes")
            .and_then(Value::as_u64)
            .map(|value| value as usize),
    }
}

fn handle_provider_list(id: Value, params: Option<&Value>) -> Value {
    let empty_arguments = json!({});
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&empty_arguments);
    if let Err(message) = validate_argument_object(
        arguments,
        PROVIDER_LIST_ALLOWED_ARGUMENT_KEYS,
        "provider list",
    ) {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
    let providers = all_kernel_managed_providers();

    tool_result(
        id,
        json!({
            "providers": providers,
            "side_effect_executed": false
        }),
    )
}

fn handle_provider_status(id: Value, params: Option<&Value>) -> Value {
    let empty_arguments = json!({});
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&empty_arguments);
    if let Err(message) = validate_argument_object(
        arguments,
        PROVIDER_STATUS_ALLOWED_ARGUMENT_KEYS,
        "provider status",
    ) {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
    let Some(provider_id) = arguments.get("provider").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            -32602,
            "provider status requires arguments.provider",
            json!({"side_effect_executed": false}),
        );
    };

    let Some(provider) = find_kernel_managed_provider(provider_id) else {
        return tool_error_result(
            id,
            json!({
                "error_kind": ErrorKind::ProviderUnknown,
                "provider": provider_id,
                "available": false,
                "side_effect_executed": false
            }),
        );
    };

    tool_result(
        id,
        json!({
            "provider": provider.id,
            "available": true,
            "kind": provider.kind,
            "risk": provider.risk,
            "side_effects": provider.side_effects,
            "approval_required": provider_requires_approval(&provider),
            "side_effect_executed": false
        }),
    )
}

fn handle_report_lint(id: Value, params: Option<&Value>) -> Value {
    let Some(report) = report_arg(params) else {
        return jsonrpc_error(
            id,
            -32602,
            "report lint requires arguments.report",
            json!({"side_effect_executed": false}),
        );
    };

    let trace_events = match read_mcp_provider_trace_events() {
        Ok(trace_events) => trace_events,
        Err(err) => {
            return tool_error_result(
                id,
                json!({
                    "ok": false,
                    "errors": [{
                        "kind": "trace_store_unreadable",
                        "message": err.to_string()
                    }],
                    "trace_source": "mcp_provider_event_store",
                    "side_effect_executed": false
                }),
            );
        }
    };
    let result = lint_report_against_trace(&report, &trace_events);
    let payload = json!({
        "ok": result.ok,
        "errors": result.errors,
        "trace_source": "mcp_provider_event_store",
        "trace_event_count": trace_events.len(),
        "side_effect_executed": false
    });

    if result.ok {
        tool_result(id, payload)
    } else {
        tool_error_result(id, payload)
    }
}

fn handle_report_render(id: Value, params: Option<&Value>) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let call = provider_call_from_arguments("runwarden.report.render", arguments);
    let mut enforcer = KernelEnforcer::new(
        first_party_provider_registry(),
        mcp_single_provider_policy("runwarden.report.render"),
    );
    let outcome = enforcer.evaluate_call(&call);
    if outcome.decision != PolicyDecision::Allowed {
        return tool_error_result(id, provider_outcome_payload(&outcome, None));
    }

    let Some(report) = report_arg(params) else {
        return jsonrpc_error(
            id,
            -32602,
            "report render requires arguments.report",
            json!({"side_effect_executed": false}),
        );
    };
    let trace_events = match read_mcp_provider_trace_events() {
        Ok(trace_events) => trace_events,
        Err(err) => {
            return tool_error_result(
                id,
                json!({
                    "error_kind": ErrorKind::ReportCitationInvalid,
                    "message": format!("failed to read MCP provider trace store: {err}"),
                    "side_effect_executed": false
                }),
            );
        }
    };
    let format = arguments
        .get("format")
        .and_then(Value::as_str)
        .and_then(parse_render_format)
        .unwrap_or(RenderFormat::Markdown);

    match render_report(&report, &trace_events, format) {
        Ok(rendered) => tool_result(id, json!(rendered)),
        Err(err) => tool_error_result(
            id,
            json!({
                "error_kind": ErrorKind::ReportCitationInvalid,
                "message": err.message,
                "side_effect_executed": err.side_effect_executed
            }),
        ),
    }
}

fn report_arg(params: Option<&Value>) -> Option<ReportDraft> {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    serde_json::from_value(arguments.get("report")?.clone()).ok()
}

fn read_mcp_provider_trace_events() -> anyhow::Result<Vec<TraceEvent>> {
    let path = state_dir_mcp().join("events.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read MCP provider events from {}", path.display()))?;
    let mut trace_events = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(line)
            .with_context(|| format!("parse MCP provider event line {}", index + 1))?;
        let trace_event = event
            .get("data")
            .and_then(|data| data.get("trace_event"))
            .cloned()
            .with_context(|| {
                format!(
                    "MCP provider event line {} is missing data.trace_event",
                    index + 1
                )
            })?;
        trace_events.push(serde_json::from_value(trace_event).with_context(|| {
            format!("parse trace_event on MCP provider event line {}", index + 1)
        })?);
    }
    Ok(trace_events)
}

fn find_kernel_managed_provider(provider_id: &str) -> Option<KernelProvider> {
    all_kernel_managed_providers()
        .into_iter()
        .find(|provider| provider.id == provider_id)
}

fn parse_render_format(format: &str) -> Option<RenderFormat> {
    match format {
        "markdown" | "md" => Some(RenderFormat::Markdown),
        "json" => Some(RenderFormat::Json),
        "html" => Some(RenderFormat::Html),
        "sarif" | "sarif.json" => Some(RenderFormat::Sarif),
        _ => None,
    }
}

fn tool_result(id: Value, payload: Value) -> Value {
    jsonrpc_ok(
        id,
        json!({
            "structuredContent": payload,
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&payload).expect("tool payload serializes")
                }
            ],
            "isError": false
        }),
    )
}

fn tool_error_result(id: Value, payload: Value) -> Value {
    jsonrpc_ok(
        id,
        json!({
            "structuredContent": payload,
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&payload).expect("tool payload serializes")
                }
            ],
            "isError": true
        }),
    )
}

fn jsonrpc_ok(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn jsonrpc_error(id: Value, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
            "data": data
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn external_provider_result_propagates_real_sandbox_side_effect_to_trace() {
        let sandbox = std::env::temp_dir().join(format!(
            "runwarden-mcp-side-effect-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir_all(&sandbox).expect("sandbox");
        let arguments = json!({"path": "notes.txt", "content": "hello"});
        let call = ProviderCall {
            session_id: "mcp-inline".to_string(),
            provider: "external.mcp.filesystem.write_file".to_string(),
            action: "write_file".to_string(),
            arguments: arguments.clone(),
            actor_id: None,
            authz_id: None,
            approval_id: None,
        };
        let outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::Allowed,
            &call,
            "policy_allowed",
            "allowed for test",
            None,
        );

        let payload = external_provider_result(&outcome, &arguments, &sandbox);

        assert_eq!(payload["execution_status"], "completed");
        assert_eq!(payload["simulated"], false);
        assert_eq!(payload["side_effect_executed"], true);
        assert_eq!(payload["trace_event"]["event_type"], "provider_completed");
        assert_eq!(
            payload["trace_event"]["payload"]["side_effect_executed"],
            true
        );
        assert_eq!(payload["trace_event"]["payload"]["simulated"], false);
        assert_eq!(
            fs::read_to_string(sandbox.join("notes.txt")).expect("written file"),
            "hello"
        );

        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn provider_outcome_payload_adds_anomaly_for_review_blocked_external_call() {
        let call = ProviderCall {
            session_id: "mcp-inline".to_string(),
            provider: "external.api.request".to_string(),
            action: "request".to_string(),
            arguments: json!({
                "method": "POST",
                "url": "https://api.example.com/callback",
                "body": {"source": "memory"}
            }),
            actor_id: None,
            authz_id: None,
            approval_id: None,
        };
        let outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::RequiresReview,
            &call,
            "approval",
            "approval required for test",
            Some(ErrorKind::ApprovalInvalid),
        );

        let payload = provider_outcome_payload(&outcome, Some(&call.arguments));

        assert_eq!(payload["decision"], "requires_review");
        assert_eq!(payload["side_effect_executed"], false);
        assert!(payload["anomaly"]["score"].is_number());
        assert!(payload["anomaly"]["is_anomalous"].is_boolean());
        assert!(payload["anomaly"]["reasons"].is_array());
        assert!(payload["trace_event"]["payload"]["anomaly"]["score"].is_number());
        assert_eq!(
            payload["trace_event"]["payload"]["side_effect_executed"],
            false
        );
    }

    #[test]
    fn append_mcp_provider_event_stores_verifiable_trace_chain() {
        let dir = std::env::temp_dir().join(format!(
            "runwarden-mcp-event-chain-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let path = dir.join("events.jsonl");

        let first_call = ProviderCall {
            session_id: "mcp-inline".to_string(),
            provider: "external.api.request".to_string(),
            action: "call".to_string(),
            arguments: json!({"url": "http://127.0.0.1/latest/meta-data"}),
            actor_id: None,
            authz_id: None,
            approval_id: None,
        };
        let first_outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::Denied,
            &first_call,
            "egress",
            "denied for test",
            Some(ErrorKind::EgressDenied),
        );
        let first_payload = append_mcp_provider_event_to_path(
            &path,
            &first_outcome,
            &provider_outcome_payload(&first_outcome, None),
        )
        .expect("first event");

        let second_call = ProviderCall {
            session_id: "mcp-inline".to_string(),
            provider: "external.email.send".to_string(),
            action: "call".to_string(),
            arguments: json!({"to": "ops@example.com"}),
            actor_id: None,
            authz_id: None,
            approval_id: None,
        };
        let second_outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::RequiresReview,
            &second_call,
            "approval",
            "approval required for test",
            Some(ErrorKind::ApprovalInvalid),
        );
        let second_payload = append_mcp_provider_event_to_path(
            &path,
            &second_outcome,
            &provider_outcome_payload(&second_outcome, None),
        )
        .expect("second event");

        let first_trace: TraceEvent =
            serde_json::from_value(first_payload["trace_event"].clone()).expect("first trace");
        let second_trace: TraceEvent =
            serde_json::from_value(second_payload["trace_event"].clone()).expect("second trace");
        assert_eq!(
            second_trace.previous_hash.as_deref(),
            Some(first_trace.event_hash.as_str())
        );

        let content = fs::read_to_string(&path).expect("events jsonl");
        let mut store = InMemoryTraceStore::default();
        for line in content.lines() {
            let event: Value = serde_json::from_str(line).expect("event json");
            let trace: TraceEvent =
                serde_json::from_value(event["data"]["trace_event"].clone()).expect("trace event");
            store.append(trace);
        }
        store.verify_hash_chain().expect("provider trace verifies");

        let _ = fs::remove_dir_all(&dir);
    }
}
