use anyhow::{Context, bail};
use runwarden_anomaly::{
    AnomalyMonitor, AnomalyReport, BehaviorObservation, BehaviorProfile, RecommendedAction,
    RiskLevel,
};
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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{
    Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
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
const ANOMALY_PROFILE_VERSION: &str = "default_benign.v1";
const ANOMALY_CHALLENGE_SCHEMA: &str = "runwarden.anomaly-challenge.v1";
const PROVIDER_EVENT_BINDING_SCHEMA: &str = "runwarden.provider-event-binding.v1";
const ANOMALY_CHALLENGE_TTL_SECONDS: i64 = 300;
const SINGLE_SESSION_COMPATIBILITY_ID: &str = "mcp-inline";
const DEFAULT_MCP_ACTOR_ID: &str = "mcp-agent";
const MAX_SERVER_IDENTITY_BYTES: usize = 128;

/// Logical identity owned by the MCP launcher, never by model-supplied tool arguments.
///
/// Launchers should set `RUNWARDEN_SESSION_ID` (and optionally
/// `RUNWARDEN_ACTOR_ID`) once when starting the MCP process. If the session
/// variable is absent, Runwarden generates a process-unique, process-stable
/// epoch. Legacy single-session behavior requires explicitly setting
/// `RUNWARDEN_SESSION_ID=mcp-inline`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerIdentity {
    session_id: String,
    actor_id: String,
    mode: ServerIdentityMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerIdentityMode {
    GeneratedProcessEpoch,
    SingleSessionCompatibility,
    LauncherScoped,
}

impl ServerIdentity {
    pub fn from_process_env() -> anyhow::Result<Self> {
        let session_id = std::env::var("RUNWARDEN_SESSION_ID")
            .map(Some)
            .or_else(|error| match error {
                std::env::VarError::NotPresent => Ok(None),
                std::env::VarError::NotUnicode(_) => {
                    Err(anyhow::anyhow!("RUNWARDEN_SESSION_ID must be valid UTF-8"))
                }
            })?;
        let actor_id =
            std::env::var("RUNWARDEN_ACTOR_ID")
                .map(Some)
                .or_else(|error| match error {
                    std::env::VarError::NotPresent => Ok(None),
                    std::env::VarError::NotUnicode(_) => {
                        Err(anyhow::anyhow!("RUNWARDEN_ACTOR_ID must be valid UTF-8"))
                    }
                })?;
        Self::from_environment_values(session_id.as_deref(), actor_id.as_deref())
    }

    pub fn single_session_compatibility() -> Self {
        Self {
            session_id: SINGLE_SESSION_COMPATIBILITY_ID.to_string(),
            actor_id: DEFAULT_MCP_ACTOR_ID.to_string(),
            mode: ServerIdentityMode::SingleSessionCompatibility,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    fn from_environment_values(
        session_id: Option<&str>,
        actor_id: Option<&str>,
    ) -> anyhow::Result<Self> {
        let (session_id, mode) = match session_id {
            Some(SINGLE_SESSION_COMPATIBILITY_ID) => (
                SINGLE_SESSION_COMPATIBILITY_ID,
                ServerIdentityMode::SingleSessionCompatibility,
            ),
            Some(session_id) => (session_id, ServerIdentityMode::LauncherScoped),
            None => (
                generated_process_session_id(),
                ServerIdentityMode::GeneratedProcessEpoch,
            ),
        };
        let actor_id = actor_id.unwrap_or(DEFAULT_MCP_ACTOR_ID);
        validate_server_identity_component("RUNWARDEN_SESSION_ID", session_id)?;
        validate_server_identity_component("RUNWARDEN_ACTOR_ID", actor_id)?;
        Ok(Self {
            session_id: session_id.to_string(),
            actor_id: actor_id.to_string(),
            mode,
        })
    }

    pub fn mode(&self) -> &'static str {
        match self.mode {
            ServerIdentityMode::GeneratedProcessEpoch => "generated_process_epoch",
            ServerIdentityMode::SingleSessionCompatibility => "single_session_compatibility",
            ServerIdentityMode::LauncherScoped => "launcher_scoped",
        }
    }
}

fn generated_process_session_id() -> &'static str {
    static SESSION_ID: OnceLock<String> = OnceLock::new();
    SESSION_ID.get_or_init(|| {
        let epoch_material = format!(
            "runwarden-mcp:{}:{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        format!("mcp-epoch-{}", &hex_sha256(epoch_material.as_bytes())[..32])
    })
}

fn validate_server_identity_component(label: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        bail!("{label} must not be empty when set");
    }
    if value.len() > MAX_SERVER_IDENTITY_BYTES {
        bail!("{label} exceeds {MAX_SERVER_IDENTITY_BYTES} bytes");
    }
    if !value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        bail!("{label} must start and end with an ASCII letter or digit");
    }
    if !value.as_bytes().iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
    }) {
        bail!(
            "{label} may contain only ASCII letters, digits, hyphen, underscore, dot, colon, or @"
        );
    }
    Ok(())
}

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
        (true, false) => {
            validate_claude_mcp_config(config, &mut errors);
            errors.push(
                "Claude MCP configuration is only an MCP fragment and cannot prove that built-in Bash/Read/Edit tools are disabled"
                    .to_string(),
            );
        }
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
    let identity = ServerIdentity::from_process_env()?;
    let Some(response) = handle_jsonrpc_message_for_identity(body, &identity)? else {
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
    let identity = ServerIdentity::from_process_env()?;
    handle_jsonrpc_message_for_identity(body, &identity)
}

pub fn handle_jsonrpc_message_for_identity(
    body: &str,
    identity: &ServerIdentity,
) -> anyhow::Result<Option<Value>> {
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
        "tools/call" => Ok(Some(handle_tools_call(id, request.get("params"), identity))),
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
        "language": { "type": "string", "enum": ["runwarden-expression-v1"] },
        "program": { "type": "object" },
        "trace_events": { "type": "array" },
        "report": { "type": "object" }
    })
}

fn handle_tools_call(id: Value, params: Option<&Value>, identity: &ServerIdentity) -> Value {
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
                "raw_side_effect_tools_allowed": false,
                "server_identity_mode": identity.mode(),
                "server_session_sha256": hex_sha256(identity.session_id().as_bytes())
            }),
        ),
        "runwarden.provider.call" => handle_provider_call(id, params, identity),
        "runwarden.provider.list" => handle_provider_list(id, params),
        "runwarden.provider.status" => handle_provider_status(id, params),
        "runwarden.trace.verify" => handle_trace_verify(id, tool_arguments(params)),
        "runwarden.trace.export" => handle_trace_export(id, tool_arguments(params), identity),
        "runwarden.report.lint" => handle_report_lint(id, params),
        "runwarden.report.render" => handle_report_render(id, params, identity),
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

fn handle_provider_call(id: Value, params: Option<&Value>, identity: &ServerIdentity) -> Value {
    handle_provider_call_for_identity(id, params, identity)
}

#[cfg(test)]
fn handle_provider_call_for_session(id: Value, params: Option<&Value>, session_id: &str) -> Value {
    let identity = ServerIdentity {
        session_id: session_id.to_string(),
        actor_id: DEFAULT_MCP_ACTOR_ID.to_string(),
        mode: if session_id == SINGLE_SESSION_COMPATIBILITY_ID {
            ServerIdentityMode::SingleSessionCompatibility
        } else {
            ServerIdentityMode::LauncherScoped
        },
    };
    handle_provider_call_for_identity(id, params, &identity)
}

fn handle_provider_call_for_identity(
    id: Value,
    params: Option<&Value>,
    identity: &ServerIdentity,
) -> Value {
    let _call_guard = provider_call_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let empty_arguments = json!({});
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&empty_arguments);
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
    let action = match resolve_provider_action(provider, arguments) {
        Ok(action) => action,
        Err(message) => {
            return jsonrpc_error(
                id,
                -32602,
                &message,
                json!({
                    "provider": provider,
                    "side_effect_executed": false
                }),
            );
        }
    };
    let sandbox_root = tools::sandbox_root_from();

    let mut call = provider_call_from_arguments_with_action(provider, arguments, &action, identity);
    let _history_lock = match acquire_anomaly_history_lock(&call) {
        Ok(lock) => lock,
        Err(error) => {
            return fail_closed_before_external_effect(
                id,
                &call,
                arguments,
                "behavior_history_lock",
                ErrorKind::TraceWriteFailed,
                format!("failed to acquire durable behavior-history lock: {error}"),
                None,
            );
        }
    };
    let approvals = read_all_approvals_mcp().unwrap_or_default();
    let mut enforcer = KernelEnforcer::new(full_provider_registry(), mcp_kernel_policy());
    for approval in approvals.iter().cloned() {
        enforcer.add_approval(approval);
    }
    // Establish the server-owned policy result before considering any approval.
    // This prevents an approval record from hiding a hard kernel denial.
    let unapproved_outcome = enforcer.evaluate_call(&call);
    let is_external = provider_is_external(provider);
    let anomaly_report = if provider == "runwarden.input.inspect"
        || (is_external && unapproved_outcome.decision != PolicyDecision::Denied)
    {
        match preview_anomaly_report_checked(&call) {
            Ok(report) => Some(report),
            Err(error) => {
                return fail_closed_before_external_effect(
                    id,
                    &call,
                    arguments,
                    "behavior_history_read",
                    ErrorKind::TraceWriteFailed,
                    format!("failed to read durable behavior history: {error}"),
                    None,
                );
            }
        }
    } else {
        None
    };
    let anomaly_context = match anomaly_report.as_ref() {
        Some(report) => match anomaly_context_for_call(&call, report) {
            Ok(context) => Some(context),
            Err(error) => {
                return fail_closed_before_external_effect(
                    id,
                    &call,
                    arguments,
                    "behavior_context",
                    ErrorKind::TraceWriteFailed,
                    format!("failed to bind current behavior context: {error}"),
                    None,
                );
            }
        },
        None => None,
    };
    let anomaly = anomaly_report
        .as_ref()
        .map(|report| serde_json::to_value(report).expect("anomaly report serializes"));

    if is_external
        && let Some(report) = anomaly_report.as_ref()
        && anomaly_requires_denial(report)
    {
        let denied = anomaly_policy_outcome(&call, report, PolicyDecision::Denied);
        return finish_blocked_provider_call(
            id,
            &call,
            arguments,
            &denied,
            anomaly.as_ref(),
            None,
            None,
        );
    }

    let attached_approval = if unapproved_outcome.decision == PolicyDecision::Denied {
        None
    } else {
        attach_matching_approval_mcp(&mut call, &approvals, anomaly_context.as_ref())
    };
    let outcome = enforcer.evaluate_call(&call);

    if outcome.decision != PolicyDecision::Allowed {
        let dynamic_review =
            is_external && anomaly_report.as_ref().is_some_and(anomaly_requires_review);
        let effective_outcome = if dynamic_review {
            anomaly_policy_outcome(
                &call,
                anomaly_report.as_ref().expect("dynamic anomaly report"),
                PolicyDecision::RequiresReview,
            )
        } else {
            outcome
        };
        let pending_kind = (effective_outcome.decision == PolicyDecision::RequiresReview)
            .then_some(if dynamic_review {
                PendingApprovalKind::DynamicAnomaly
            } else {
                PendingApprovalKind::Kernel
            });
        let dynamic_context = if dynamic_review {
            Some(
                anomaly_context
                    .as_ref()
                    .expect("dynamic anomaly context must exist"),
            )
        } else {
            None
        };
        return finish_blocked_provider_call(
            id,
            &call,
            arguments,
            &effective_outcome,
            anomaly.as_ref(),
            pending_kind,
            dynamic_context,
        );
    }

    if is_external
        && anomaly_report.as_ref().is_some_and(anomaly_requires_review)
        && attached_approval != Some(AttachedApprovalKind::DynamicAnomaly)
    {
        let review = anomaly_policy_outcome(
            &call,
            anomaly_report.as_ref().expect("dynamic anomaly report"),
            PolicyDecision::RequiresReview,
        );
        return finish_blocked_provider_call(
            id,
            &call,
            arguments,
            &review,
            anomaly.as_ref(),
            Some(PendingApprovalKind::DynamicAnomaly),
            anomaly_context.as_ref(),
        );
    }

    let provider_is_approval_gated = find_kernel_managed_provider(provider)
        .as_ref()
        .is_some_and(provider_requires_approval);
    if is_external && (provider_is_approval_gated || call.approval_id.is_some()) {
        let binding = enforcer.approval_binding_for_call(&call);
        if attached_approval == Some(AttachedApprovalKind::DynamicAnomaly)
            && let Err(error) = verify_dynamic_anomaly_challenge_mcp(
                call.approval_id.as_deref().unwrap_or_default(),
                anomaly_context
                    .as_ref()
                    .expect("attached anomaly approval requires anomaly context"),
            )
        {
            return fail_closed_before_external_effect(
                id,
                &call,
                arguments,
                "anomaly_challenge",
                ErrorKind::ApprovalInvalid,
                format!("dynamic anomaly challenge changed before claim: {error}"),
                anomaly.as_ref(),
            );
        }
        if let Err(error) = claim_and_consume_approval_mcp(&call, &binding) {
            return fail_closed_before_external_effect(
                id,
                &call,
                arguments,
                "approval_claim",
                ErrorKind::ApprovalInvalid,
                format!("failed to atomically claim and persist approval: {error}"),
                anomaly.as_ref(),
            );
        }
    }

    let execution_reservation_id = if is_external {
        match persist_execution_reservation_mcp(&call, &outcome) {
            Ok(reservation_id) => Some(reservation_id),
            Err(error) => {
                return fail_closed_before_external_effect(
                    id,
                    &call,
                    arguments,
                    "execution_reservation",
                    ErrorKind::TraceWriteFailed,
                    format!("failed to persist execution reservation: {error}"),
                    anomaly.as_ref(),
                );
            }
        }
    } else {
        None
    };

    let mut payload = match provider {
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
                "output": inspection,
                "anomaly": anomaly.as_ref().expect("input inspection anomaly report")
            })
        }
        other if provider_is_external(other) => external_provider_result(
            &outcome,
            arguments,
            &sandbox_root,
            anomaly.as_ref().expect("external anomaly report"),
        ),
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

    let reservation_finalization_error =
        execution_reservation_id.as_deref().and_then(
            |id| match finalize_execution_reservation_mcp(id, &payload) {
                Ok(binding) => {
                    payload["reservation_state"] = json!(binding.state);
                    payload["reservation_digest"] = json!(binding.record_sha256);
                    None
                }
                Err(error) => {
                    payload["reservation_state"] = json!("indeterminate");
                    payload["reservation_digest"] = Value::Null;
                    Some(error)
                }
            },
        );

    let behavior_history_commit = if payload
        .get("execution_status")
        .and_then(Value::as_str)
        .is_some_and(|status| status != "failed")
    {
        match commit_anomaly_observation_checked(&call) {
            Ok(binding) => {
                payload["behavior_history_generation"] = json!(binding.generation);
                payload["behavior_history_digest"] = json!(binding.record_sha256);
                None
            }
            Err(error) => {
                payload["behavior_history_generation"] = Value::Null;
                payload["behavior_history_digest"] = Value::Null;
                Some(error)
            }
        }
    } else {
        None
    };

    finalize_provider_completion_payload(
        &outcome,
        &call,
        arguments,
        execution_reservation_id.as_deref(),
        &mut payload,
    );

    if let Some(error) = reservation_finalization_error {
        let traced = append_mcp_provider_event(&outcome, &payload);
        let payload = traced.as_ref().unwrap_or(&payload);
        let error = anyhow::anyhow!(
            "failed to durably finalize execution reservation: {error}; provider event persisted={}",
            traced.is_ok()
        );
        return tool_error_result(id, trace_write_failure_payload(&outcome, payload, &error));
    }

    if let Some(error) = behavior_history_commit {
        let traced = append_mcp_provider_event(&outcome, &payload);
        let payload = traced.as_ref().unwrap_or(&payload);
        let error = anyhow::anyhow!(
            "failed to durably commit behavior history after provider execution: {error}; provider event persisted={}",
            traced.is_ok()
        );
        return tool_error_result(id, trace_write_failure_payload(&outcome, payload, &error));
    }
    match append_mcp_provider_event(&outcome, &payload) {
        Ok(payload) => tool_result(id, payload),
        Err(error) => {
            tool_error_result(id, trace_write_failure_payload(&outcome, &payload, &error))
        }
    }
}

fn finish_blocked_provider_call(
    id: Value,
    call: &ProviderCall,
    arguments: &Value,
    outcome: &ProviderOutcome,
    anomaly: Option<&Value>,
    pending_kind: Option<PendingApprovalKind>,
    anomaly_context: Option<&AnomalyContext>,
) -> Value {
    let pending_approval_id = match pending_kind {
        Some(kind) => match persist_pending_approval_mcp(call, outcome, kind, anomaly_context) {
            Ok(approval_id) => approval_id,
            Err(error) => {
                return fail_closed_before_external_effect(
                    id,
                    call,
                    arguments,
                    "approval_persist",
                    ErrorKind::TraceWriteFailed,
                    format!("failed to durably persist pending approval: {error}"),
                    anomaly,
                );
            }
        },
        None => None,
    };
    let mut payload = provider_outcome_payload(outcome, Some(arguments), anomaly);
    if let Some(approval_id) = pending_approval_id {
        payload["approval_id"] = json!(approval_id);
    }
    match append_mcp_provider_event(outcome, &payload) {
        Ok(payload) => tool_error_result(id, payload),
        Err(error) => tool_error_result(id, trace_write_failure_payload(outcome, &payload, &error)),
    }
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
    "language",
    "program",
    "trace_events",
    "report",
];

const PROVIDER_LIST_ALLOWED_ARGUMENT_KEYS: &[&str] = &[];
const PROVIDER_STATUS_ALLOWED_ARGUMENT_KEYS: &[&str] = &["provider"];
// OpenCode evaluates tool patterns in declaration order and the last match
// wins. The shipped JSON declares "*" first and this server-specific allow
// second, making future built-ins/plugins default-denied while exposing only
// tools prefixed by the sole MCP server named runwarden.
const OPENCODE_DEFAULT_DENY_PATTERN: &str = "*";
const OPENCODE_RUNWARDEN_TOOL_PATTERN: &str = "runwarden_*";
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

    validate_opencode_proxy_boundary(config, errors);

    let Some(tools) = config.get("tools").and_then(Value::as_object) else {
        errors.push(
            "OpenCode tools must default-deny all tools and allow only runwarden_*".to_string(),
        );
        return;
    };
    let exact_default_deny = tools.len() == 2
        && tools
            .get(OPENCODE_DEFAULT_DENY_PATTERN)
            .and_then(Value::as_bool)
            == Some(false)
        && tools
            .get(OPENCODE_RUNWARDEN_TOOL_PATTERN)
            .and_then(Value::as_bool)
            == Some(true);
    if !exact_default_deny {
        errors.push(
            r#"OpenCode tools must be exactly {"*": false, "runwarden_*": true}; unknown allows and partial deny maps are forbidden"#
                .to_string(),
        );
    }
}

fn validate_opencode_proxy_boundary(config: &Value, errors: &mut Vec<String>) {
    let enabled_providers_ok = config
        .get("enabled_providers")
        .and_then(Value::as_array)
        .is_some_and(|providers| {
            providers.len() == 1 && providers[0].as_str() == Some("runwarden-proxy")
        });
    if !enabled_providers_ok {
        errors.push("OpenCode enabled_providers must be exactly [\"runwarden-proxy\"]".to_string());
    }
    if config
        .get("disabled_providers")
        .and_then(Value::as_array)
        .is_some_and(|providers| {
            providers
                .iter()
                .any(|provider| provider.as_str() == Some("runwarden-proxy"))
        })
    {
        errors.push("OpenCode must not disable runwarden-proxy".to_string());
    }

    let Some(providers) = config.get("provider").and_then(Value::as_object) else {
        errors.push("OpenCode config must define only provider.runwarden-proxy".to_string());
        return;
    };
    if providers.len() != 1 || !providers.contains_key("runwarden-proxy") {
        errors.push("OpenCode provider map must contain only runwarden-proxy".to_string());
    }
    let Some(proxy) = providers.get("runwarden-proxy").and_then(Value::as_object) else {
        errors.push("OpenCode provider.runwarden-proxy must be an object".to_string());
        return;
    };
    if proxy.get("npm").and_then(Value::as_str) != Some("@ai-sdk/openai-compatible") {
        errors.push(
            "OpenCode provider.runwarden-proxy.npm must be @ai-sdk/openai-compatible".to_string(),
        );
    }
    if proxy
        .get("options")
        .and_then(|options| options.get("baseURL"))
        .and_then(Value::as_str)
        != Some("http://127.0.0.1:8787/v1")
    {
        errors.push(
            "OpenCode provider.runwarden-proxy.options.baseURL must be exactly http://127.0.0.1:8787/v1"
                .to_string(),
        );
    }
    if proxy
        .get("options")
        .and_then(|options| options.get("apiKey"))
        .and_then(Value::as_str)
        != Some("{env:RUNWARDEN_PROXY_CLIENT_TOKEN}")
    {
        errors.push(
            "OpenCode provider.runwarden-proxy.options.apiKey must be {env:RUNWARDEN_PROXY_CLIENT_TOKEN}"
                .to_string(),
        );
    }
    let Some(models) = proxy.get("models").and_then(Value::as_object) else {
        errors.push(
            "OpenCode provider.runwarden-proxy.models must be a non-empty object".to_string(),
        );
        return;
    };
    if models.is_empty() {
        errors.push(
            "OpenCode provider.runwarden-proxy.models must be a non-empty object".to_string(),
        );
    }

    validate_opencode_selected_model(config.get("model"), "model", models, errors);
    if config.get("small_model").is_some() {
        validate_opencode_selected_model(config.get("small_model"), "small_model", models, errors);
    }
}

fn validate_opencode_selected_model(
    selected: Option<&Value>,
    field: &str,
    models: &serde_json::Map<String, Value>,
    errors: &mut Vec<String>,
) {
    let Some(selected) = selected.and_then(Value::as_str) else {
        errors.push(format!(
            "OpenCode {field} must select a configured runwarden-proxy model"
        ));
        return;
    };
    let Some(model_id) = selected.strip_prefix("runwarden-proxy/") else {
        errors.push(format!(
            "OpenCode {field} must use the runwarden-proxy/<model> form"
        ));
        return;
    };
    if model_id.is_empty() || !models.contains_key(model_id) {
        errors.push(format!(
            "OpenCode {field} refers to an undeclared runwarden-proxy model: {model_id}"
        ));
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

#[cfg(test)]
fn provider_call_from_arguments_for_session(
    provider: &str,
    arguments: &Value,
    session_id: &str,
) -> ProviderCall {
    provider_call_from_arguments_for_identity(
        provider,
        arguments,
        &ServerIdentity {
            session_id: session_id.to_string(),
            actor_id: DEFAULT_MCP_ACTOR_ID.to_string(),
            mode: if session_id == SINGLE_SESSION_COMPATIBILITY_ID {
                ServerIdentityMode::SingleSessionCompatibility
            } else {
                ServerIdentityMode::LauncherScoped
            },
        },
    )
}

fn provider_call_from_arguments_for_identity(
    provider: &str,
    arguments: &Value,
    identity: &ServerIdentity,
) -> ProviderCall {
    let action = canonical_provider_action(provider)
        .or_else(|| {
            arguments
                .get("action")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "call".to_string());
    provider_call_from_arguments_with_action(provider, arguments, &action, identity)
}

fn provider_call_from_arguments_with_action(
    provider: &str,
    arguments: &Value,
    action: &str,
    identity: &ServerIdentity,
) -> ProviderCall {
    ProviderCall {
        session_id: identity.session_id.clone(),
        provider: provider.to_string(),
        action: action.to_string(),
        arguments: arguments.clone(),
        actor_id: Some(identity.actor_id.clone()),
        authz_id: None,
        approval_id: None,
    }
}

fn resolve_provider_action(provider: &str, arguments: &Value) -> Result<String, String> {
    let supplied = match arguments.get("action") {
        Some(Value::String(action)) => Some(action.as_str()),
        Some(_) => return Err("provider call arguments.action must be a string".to_string()),
        None => None,
    };
    let Some(expected) = canonical_provider_action(provider) else {
        return Ok(supplied.unwrap_or("call").to_string());
    };
    if let Some(supplied) = supplied
        && supplied != expected
    {
        return Err(format!(
            "provider action mismatch for {provider}: expected {expected}, received {supplied}"
        ));
    }
    Ok(expected)
}

fn canonical_provider_action(provider: &str) -> Option<String> {
    let first_party = match provider {
        "runwarden.input.inspect" => Some("inspect"),
        "runwarden.trace.verify" => Some("verify"),
        "runwarden.trace.export" => Some("export"),
        "runwarden.report.lint" => Some("lint"),
        "runwarden.report.render" => Some("render"),
        _ => None,
    };
    first_party.map(ToString::to_string).or_else(|| {
        default_external_provider_manifests()
            .into_iter()
            .find(|manifest| manifest.provider_id == provider)
            .and_then(|manifest| manifest.tool_identity)
    })
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

fn provider_call_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnomalyContext {
    sha256: String,
    score: usize,
    risk_level: String,
    recommendation: String,
    signal_count: usize,
    history_count: usize,
    history_window: usize,
    history_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachedApprovalKind {
    Kernel,
    DynamicAnomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DynamicAnomalyChallenge {
    schema_version: String,
    kind: String,
    profile_version: String,
    approval_id: String,
    issued_obs_id: String,
    context_sha256: String,
    issued_at_unix_nanos: String,
    expires_at_unix_nanos: String,
    risk_score: usize,
    risk_level: String,
    recommendation: String,
    signal_count: usize,
    history_count: usize,
    history_window: usize,
    history_generation: u64,
}

fn anomaly_context_for_call(
    call: &ProviderCall,
    report: &AnomalyReport,
) -> anyhow::Result<AnomalyContext> {
    let binding = approval_binding_for_mcp_call(call);
    let profile = BehaviorProfile::default_benign();
    let history_generation = read_durable_anomaly_history(call)?
        .map(|(generation, _)| generation)
        .unwrap_or(0);
    let material = json!({
        "schema_version": "runwarden.anomaly-context.v1",
        "profile_version": ANOMALY_PROFILE_VERSION,
        "call_binding": binding,
        "score": report.score,
        "risk_level": report.risk_level.as_str(),
        "recommendation": report.recommended_action.as_str(),
        "signals": report.signals.iter().map(|signal| json!({
            "kind": signal.kind.as_str(),
            "weight": signal.weight,
            "evidence_sha256": hex_sha256(signal.evidence.as_bytes())
        })).collect::<Vec<_>>(),
        "history": {
            "window": profile.history_window,
            "count": report.history.len(),
            "generation": history_generation,
            "observations": report.history.iter().map(|observation| json!({
                "provider": observation.provider,
                "arg_bytes": observation.arg_bytes,
                "egress_host": observation.egress_host
            })).collect::<Vec<_>>()
        }
    });
    Ok(AnomalyContext {
        sha256: hex_sha256(&canonical_json_bytes(&material)),
        score: report.score,
        risk_level: report.risk_level.as_str().to_string(),
        recommendation: report.recommended_action.as_str().to_string(),
        signal_count: report.signals.len(),
        history_count: report.history.len(),
        history_window: profile.history_window,
        history_generation,
    })
}

fn anomaly_challenges_dir_mcp() -> PathBuf {
    state_dir_mcp().join("anomaly-challenges")
}

fn anomaly_challenge_path_mcp(approval_id: &str) -> anyhow::Result<PathBuf> {
    Ok(anomaly_challenges_dir_mcp().join(format!("{}.json", safe_record_id_mcp(approval_id)?)))
}

fn read_dynamic_anomaly_challenge_mcp(
    approval_id: &str,
) -> anyhow::Result<Option<DynamicAnomalyChallenge>> {
    let path = anomaly_challenge_path_mcp(approval_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let challenge = serde_json::from_slice::<DynamicAnomalyChallenge>(&std::fs::read(&path)?)
        .with_context(|| format!("parse dynamic anomaly challenge {}", path.display()))?;
    Ok(Some(challenge))
}

fn verify_dynamic_anomaly_challenge_mcp(
    approval_id: &str,
    context: &AnomalyContext,
) -> anyhow::Result<()> {
    let challenge = read_dynamic_anomaly_challenge_mcp(approval_id)?
        .context("dynamic anomaly approval is missing its durable challenge")?;
    if challenge.schema_version != ANOMALY_CHALLENGE_SCHEMA
        || challenge.kind != "dynamic_anomaly"
        || challenge.profile_version != ANOMALY_PROFILE_VERSION
        || challenge.approval_id != approval_id
    {
        bail!("dynamic anomaly challenge identity or version is invalid");
    }
    if challenge.context_sha256 != context.sha256 {
        bail!("dynamic anomaly challenge does not match the current behavior context");
    }
    let expires_at = challenge
        .expires_at_unix_nanos
        .parse::<i128>()
        .context("parse dynamic anomaly challenge expiry")?;
    if expires_at <= time::OffsetDateTime::now_utc().unix_timestamp_nanos() {
        bail!("dynamic anomaly challenge expired");
    }
    Ok(())
}

fn attach_matching_approval_mcp(
    call: &mut ProviderCall,
    approvals: &[ApprovalRecord],
    anomaly_context: Option<&AnomalyContext>,
) -> Option<AttachedApprovalKind> {
    let binding = approval_binding_for_mcp_call(call);
    let matches = |approval: &&ApprovalRecord| {
        approval.binding == binding
            && approval.state == ApprovalState::Approved
            && approval
                .expires_at
                .is_none_or(|expires_at| expires_at > time::OffsetDateTime::now_utc())
    };
    let dynamic_approval = anomaly_context.and_then(|context| {
        approvals.iter().filter(matches).find(|approval| {
            verify_dynamic_anomaly_challenge_mcp(&approval.approval_id, context).is_ok()
        })
    });
    let kernel_approval = approvals.iter().filter(matches).find(|approval| {
        // A challenge-bearing approval may only be authorized through an
        // exact current anomaly context. Reserved anomaly ids without a
        // valid sidecar are also rejected fail-closed, never downgraded to
        // an ordinary kernel approval.
        !approval.approval_id.starts_with("anomaly-")
            && anomaly_challenge_path_mcp(&approval.approval_id).is_ok_and(|path| !path.exists())
    });
    if let Some(approval) = dynamic_approval {
        call.approval_id = Some(approval.approval_id.clone());
        Some(AttachedApprovalKind::DynamicAnomaly)
    } else if let Some(approval) = kernel_approval {
        call.approval_id = Some(approval.approval_id.clone());
        Some(AttachedApprovalKind::Kernel)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingApprovalKind {
    Kernel,
    DynamicAnomaly,
}

fn persist_pending_approval_mcp(
    call: &ProviderCall,
    outcome: &ProviderOutcome,
    kind: PendingApprovalKind,
    anomaly_context: Option<&AnomalyContext>,
) -> anyhow::Result<Option<String>> {
    if outcome.decision != PolicyDecision::RequiresReview {
        return Ok(None);
    }
    let dir = approvals_dir_mcp();
    create_and_sync_directory(&dir)?;
    let prefix = match kind {
        PendingApprovalKind::Kernel => "webui",
        PendingApprovalKind::DynamicAnomaly => "anomaly",
    };
    if kind == PendingApprovalKind::DynamicAnomaly && anomaly_context.is_none() {
        bail!("dynamic anomaly review is missing its current behavior context");
    }
    // Live observation ids include a per-invocation nonce. Approval identity,
    // however, should remain stable for an equivalent pending intent so a
    // retry cannot flood the ledger with indistinguishable review requests.
    // The full unique obs id is still retained in each sealed trace event and
    // in the dynamic challenge's issued_obs_id.
    let base_approval_id = format!(
        "{prefix}-{}",
        stable_observation_intent_key(&outcome.observation_id)
    );
    let binding = approval_binding_for_mcp_call(call);
    for attempt in 0..100 {
        let approval_id = if attempt == 0 {
            base_approval_id.clone()
        } else {
            format!("{base_approval_id}-{}", attempt + 1)
        };
        let path = dir.join(format!("{approval_id}.json"));
        if let Ok(body) = std::fs::read_to_string(&path)
            && let Ok(approval) = serde_json::from_str::<ApprovalRecord>(&body)
            && approval.binding == binding
            && approval.state == ApprovalState::Pending
            && (kind == PendingApprovalKind::Kernel
                || verify_dynamic_anomaly_challenge_mcp(
                    &approval.approval_id,
                    anomaly_context.expect("checked anomaly context"),
                )
                .is_ok())
        {
            return Ok(Some(approval.approval_id));
        }
        if path.exists()
            || (kind == PendingApprovalKind::DynamicAnomaly
                && anomaly_challenge_path_mcp(&approval_id)?.exists())
        {
            continue;
        }

        let mut approval = ApprovalRecord::new(approval_id.clone(), binding.clone());
        if kind == PendingApprovalKind::DynamicAnomaly {
            let now = time::OffsetDateTime::now_utc();
            approval.expires_at =
                Some(now + time::Duration::seconds(ANOMALY_CHALLENGE_TTL_SECONDS));
            approval.reason = Some(format!(
                "dynamic behavior anomaly review: {}",
                outcome.envelope.reason
            ));
            persist_dynamic_anomaly_challenge_mcp(
                &approval_id,
                &outcome.observation_id,
                anomaly_context.expect("checked anomaly context"),
                now,
            )?;
        }
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if kind == PendingApprovalKind::DynamicAnomaly {
                    let _ = std::fs::remove_file(anomaly_challenge_path_mcp(&approval_id)?);
                }
                continue;
            }
            Err(error) => {
                if kind == PendingApprovalKind::DynamicAnomaly {
                    let _ = std::fs::remove_file(anomaly_challenge_path_mcp(&approval_id)?);
                }
                return Err(error.into());
            }
        };
        let result = (|| -> anyhow::Result<()> {
            let mut bytes = serde_json::to_vec_pretty(&approval)?;
            bytes.push(b'\n');
            file.write_all(&bytes)?;
            file.sync_all()?;
            sync_directory(&dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            drop(file);
            let _ = std::fs::remove_file(&path);
            if kind == PendingApprovalKind::DynamicAnomaly {
                let _ = std::fs::remove_file(anomaly_challenge_path_mcp(&approval_id)?);
            }
            return Err(error);
        }
        return Ok(Some(approval_id));
    }
    bail!(
        "too many pending approval attempts for {}",
        outcome.observation_id
    )
}

fn stable_observation_intent_key(observation_id: &str) -> &str {
    let Some(rest) = observation_id.strip_prefix("obs_") else {
        return observation_id;
    };
    let mut components = rest.split('_');
    let Some(intent) = components.next() else {
        return observation_id;
    };
    let Some(invocation) = components.next() else {
        return observation_id;
    };
    if components.next().is_none()
        && intent.len() == 16
        && invocation.len() == 32
        && intent.bytes().all(|byte| byte.is_ascii_hexdigit())
        && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        // `obs_` is four ASCII bytes, so this boundary is always UTF-8 safe.
        &observation_id[..20]
    } else {
        observation_id
    }
}

fn persist_dynamic_anomaly_challenge_mcp(
    approval_id: &str,
    issued_obs_id: &str,
    context: &AnomalyContext,
    issued_at: time::OffsetDateTime,
) -> anyhow::Result<()> {
    let dir = anomaly_challenges_dir_mcp();
    create_and_sync_directory(&dir)?;
    let path = anomaly_challenge_path_mcp(approval_id)?;
    let expires_at = issued_at + time::Duration::seconds(ANOMALY_CHALLENGE_TTL_SECONDS);
    let challenge = DynamicAnomalyChallenge {
        schema_version: ANOMALY_CHALLENGE_SCHEMA.to_string(),
        kind: "dynamic_anomaly".to_string(),
        profile_version: ANOMALY_PROFILE_VERSION.to_string(),
        approval_id: approval_id.to_string(),
        issued_obs_id: issued_obs_id.to_string(),
        context_sha256: context.sha256.clone(),
        issued_at_unix_nanos: issued_at.unix_timestamp_nanos().to_string(),
        expires_at_unix_nanos: expires_at.unix_timestamp_nanos().to_string(),
        risk_score: context.score,
        risk_level: context.risk_level.clone(),
        recommendation: context.recommendation.clone(),
        signal_count: context.signal_count,
        history_count: context.history_count,
        history_window: context.history_window,
        history_generation: context.history_generation,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create dynamic anomaly challenge {}", path.display()))?;
    let mut bytes = serde_json::to_vec_pretty(&challenge)?;
    bytes.push(b'\n');
    let result = (|| -> anyhow::Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_directory(&dir)?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(&path);
    }
    result
}

fn approval_claims_dir_mcp() -> PathBuf {
    state_dir_mcp().join("approval-claims")
}

struct ApprovalReviewLock {
    path: PathBuf,
}

impl Drop for ApprovalReviewLock {
    fn drop(&mut self) {
        if std::fs::remove_file(&self.path).is_ok()
            && let Some(parent) = self.path.parent()
        {
            let _ = sync_directory(parent);
        }
    }
}

fn acquire_approval_review_lock_mcp(approval_id: &str) -> anyhow::Result<ApprovalReviewLock> {
    let approval_id = safe_record_id_mcp(approval_id)?;
    let dir = approvals_dir_mcp();
    create_and_sync_directory(&dir)?;
    let lock_path = dir.join(format!(".{approval_id}.review.lock"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "approval {approval_id} is being reviewed; refusing to claim it until the review transaction completes; if the reviewer crashed, verify the approval and audit ledger before manually removing the stale lock"
            )
        })?;
    let metadata = json!({
        "schema_version": "runwarden.approval-review-lock.v1",
        "owner": "runwarden-mcp-claim",
        "approval_id": approval_id,
        "pid": std::process::id(),
        "created_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
    });
    let result = (|| -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(&metadata)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_directory(&dir)?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = std::fs::remove_file(&lock_path);
        let _ = sync_directory(&dir);
        return Err(error);
    }
    Ok(ApprovalReviewLock { path: lock_path })
}

fn acquire_approval_audit_read_lock_mcp() -> anyhow::Result<ApprovalReviewLock> {
    let dir = state_dir_mcp();
    create_and_sync_directory(&dir)?;
    let lock_path = dir.join(".approval-events.jsonl.append.lock");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .with_context(|| {
            "approval audit is being appended; refusing to validate a partial ledger; if the writer crashed, verify approval-events.jsonl before manually removing the stale lock"
        })?;
    let metadata = json!({
        "schema_version": "runwarden.approval-event-append-lock.v1",
        "owner": "runwarden-mcp-audit-reader",
        "pid": std::process::id(),
        "created_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
    });
    let result = (|| -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(&metadata)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_directory(&dir)?;
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = std::fs::remove_file(&lock_path);
        let _ = sync_directory(&dir);
        return Err(error);
    }
    Ok(ApprovalReviewLock { path: lock_path })
}

fn verify_approval_decision_audit_mcp(approval: &ApprovalRecord) -> anyhow::Result<()> {
    let _audit_lock = acquire_approval_audit_read_lock_mcp()?;
    let path = state_dir_mcp().join("approval-events.jsonl");
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read approval decision audit {}", path.display()))?;
    anyhow::ensure!(!body.trim().is_empty(), "approval decision audit is empty");
    let mut events = Vec::new();
    for (index, line) in body.lines().enumerate() {
        anyhow::ensure!(
            !line.trim().is_empty(),
            "approval decision audit contains an empty line at {}",
            index + 1
        );
        let event = serde_json::from_str::<TraceEvent>(line)
            .with_context(|| format!("parse approval decision event line {}", index + 1))?;
        anyhow::ensure!(
            event.event_type == "approval_decision",
            "approval audit line {} has unexpected event type",
            index + 1
        );
        anyhow::ensure!(
            event.payload.get("schema_version").and_then(Value::as_str)
                == Some("runwarden.approval-decision.v1"),
            "approval audit line {} has an invalid schema",
            index + 1
        );
        events.push(event);
    }
    let mut store = InMemoryTraceStore::default();
    for event in events.iter().cloned() {
        store.append(event);
    }
    store.verify_hash_chain().map_err(|error| {
        anyhow::anyhow!("approval decision audit hash chain is invalid: {error:?}")
    })?;

    let event = events
        .iter()
        .rev()
        .find(|event| {
            event.payload.get("approval_id").and_then(Value::as_str)
                == Some(approval.approval_id.as_str())
        })
        .context("approved record is missing its approval_decision audit event")?;
    anyhow::ensure!(
        event.payload.get("decision").and_then(Value::as_str) == Some("approved")
            && event.payload.get("state").and_then(Value::as_str) == Some("approved"),
        "latest approval_decision audit event is not approved"
    );
    anyhow::ensure!(
        event.provider.as_deref() == Some(approval.binding.provider.as_str())
            && event.payload.get("provider").and_then(Value::as_str)
                == Some(approval.binding.provider.as_str())
            && event.payload.get("action").and_then(Value::as_str)
                == Some(approval.binding.action.as_str()),
        "approval decision audit provider/action does not match the approval binding"
    );
    let approval_value = serde_json::to_value(approval)?;
    let expected_record_sha256 = hex_sha256(&canonical_json_bytes(&approval_value));
    let binding_value = serde_json::to_value(&approval.binding)?;
    let expected_binding_sha256 = hex_sha256(&canonical_json_bytes(&binding_value));
    anyhow::ensure!(
        event.payload.get("record_sha256").and_then(Value::as_str)
            == Some(expected_record_sha256.as_str()),
        "approval decision audit record digest does not match the current approved record"
    );
    anyhow::ensure!(
        event.payload.get("binding_sha256").and_then(Value::as_str)
            == Some(expected_binding_sha256.as_str()),
        "approval decision audit binding digest does not match the current approval binding"
    );
    Ok(())
}

fn execution_reservations_dir_mcp() -> PathBuf {
    state_dir_mcp().join("execution-reservations")
}

fn claim_and_consume_approval_mcp(
    call: &ProviderCall,
    binding: &ApprovalBinding,
) -> anyhow::Result<String> {
    let Some(approval_id) = call.approval_id.as_deref() else {
        bail!("kernel allowed an approval-gated call without an approval id");
    };
    let approval_id = safe_record_id_mcp(approval_id)?;
    // Serialize the approved-record read, durable one-time claim, and consumed
    // write against the WebUI review transaction. If the reviewer owns this
    // lock, execution fails closed instead of observing an unaudited decision.
    let _review_lock = acquire_approval_review_lock_mcp(approval_id)?;
    let path = approvals_dir_mcp().join(format!("{approval_id}.json"));
    let body = std::fs::read_to_string(&path)?;
    let mut approval = serde_json::from_str::<ApprovalRecord>(&body)?;
    if approval.approval_id != approval_id {
        bail!("approval record id does not match the claimed approval id");
    }
    if approval.binding != *binding {
        bail!("approval binding changed before it could be claimed");
    }
    if approval.state != ApprovalState::Approved {
        bail!("approval is no longer approved");
    }
    if approval
        .expires_at
        .is_some_and(|expires_at| expires_at <= time::OffsetDateTime::now_utc())
    {
        bail!("approval expired before it could be claimed");
    }
    verify_approval_decision_audit_mcp(&approval)?;

    let claims_dir = approval_claims_dir_mcp();
    create_and_sync_directory(&claims_dir)?;
    let claim_path = claims_dir.join(format!("{approval_id}.json"));
    let mut claim_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&claim_path)
        .with_context(|| format!("create one-time approval claim {}", claim_path.display()))?;
    let claim = json!({
        "schema_version": "1",
        "approval_id": approval_id,
        "session_id": &call.session_id,
        "provider": &call.provider,
        "action": &call.action,
        "argument_hash": &binding.argument_hash,
        "authz_id": &call.authz_id,
        "actor_id": &call.actor_id,
        "claimed_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string(),
        "side_effect_executed": false
    });
    let mut claim_bytes = serde_json::to_vec(&claim)?;
    claim_bytes.push(b'\n');
    claim_file
        .write_all(&claim_bytes)
        .with_context(|| format!("write approval claim {}", claim_path.display()))?;
    claim_file
        .sync_all()
        .with_context(|| format!("sync approval claim {}", claim_path.display()))?;
    sync_directory(&claims_dir)
        .with_context(|| format!("sync approval claims directory {}", claims_dir.display()))?;

    approval.consume_once(binding)?;
    persist_approval_record_atomically(&path, &approval)?;
    Ok(approval_id.to_string())
}

fn persist_approval_record_atomically(
    path: &Path,
    approval: &ApprovalRecord,
) -> anyhow::Result<()> {
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    let parent = path
        .parent()
        .context("approval record path is missing its parent directory")?;
    let approval_id = safe_record_id_mcp(&approval.approval_id)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path = parent.join(format!(
        ".{approval_id}.consumed-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .with_context(|| {
                format!(
                    "create temporary consumed approval {}",
                    temporary_path.display()
                )
            })?;
        let mut bytes = serde_json::to_vec_pretty(approval)?;
        bytes.push(b'\n');
        file.write_all(&bytes).with_context(|| {
            format!(
                "write temporary consumed approval {}",
                temporary_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "sync temporary consumed approval {}",
                temporary_path.display()
            )
        })?;
        std::fs::rename(&temporary_path, path).with_context(|| {
            format!(
                "replace approval record {} with durable consumed state",
                path.display()
            )
        })?;
        sync_directory(parent)
            .with_context(|| format!("sync approvals directory {}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn persist_execution_reservation_mcp(
    call: &ProviderCall,
    outcome: &ProviderOutcome,
) -> anyhow::Result<String> {
    static RESERVATION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    let reservations_dir = execution_reservations_dir_mcp();
    create_and_sync_directory(&reservations_dir)?;
    let sequence = RESERVATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let reservation_id = format!(
        "{}-{}-{}-{sequence}",
        outcome.observation_id,
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let reservation_path = reservations_dir.join(format!("{reservation_id}.json"));
    let reservation = json!({
        "schema_version": "runwarden.execution-reservation.v2",
        "reservation_id": &reservation_id,
        "session_id": &call.session_id,
        "provider": &call.provider,
        "action": &call.action,
        "argument_hash": hex_sha256(&serde_json::to_vec(&call.arguments)?),
        "actor_id": &call.actor_id,
        "authz_id": &call.authz_id,
        "approval_id": &call.approval_id,
        "obs_ref": &outcome.observation_id,
        "decision": &outcome.decision,
        "state": "reserved",
        "created_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string(),
        "updated_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string(),
        "output_digest": Value::Null,
        "side_effect_executed": false
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&reservation_path)
        .with_context(|| {
            format!(
                "create execution reservation {}",
                reservation_path.display()
            )
        })?;
    let mut bytes = serde_json::to_vec(&reservation)?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .with_context(|| format!("write execution reservation {}", reservation_path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync execution reservation {}", reservation_path.display()))?;
    sync_directory(&reservations_dir).with_context(|| {
        format!(
            "sync execution reservations directory {}",
            reservations_dir.display()
        )
    })?;
    Ok(reservation_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReservationAuditBinding {
    state: String,
    record_sha256: String,
}

fn finalize_execution_reservation_mcp(
    reservation_id: &str,
    payload: &Value,
) -> anyhow::Result<ReservationAuditBinding> {
    static RESERVATION_UPDATE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    let reservation_id = safe_record_id_mcp(reservation_id)?;
    let dir = execution_reservations_dir_mcp();
    let path = dir.join(format!("{reservation_id}.json"));
    let mut reservation: Value = serde_json::from_slice(
        &std::fs::read(&path)
            .with_context(|| format!("read execution reservation {}", path.display()))?,
    )
    .with_context(|| format!("parse execution reservation {}", path.display()))?;
    if reservation.get("reservation_id").and_then(Value::as_str) != Some(reservation_id)
        || reservation.get("state").and_then(Value::as_str) != Some("reserved")
    {
        bail!("execution reservation is not in the expected reserved state");
    }
    let execution_status = payload
        .get("execution_status")
        .and_then(Value::as_str)
        .unwrap_or("indeterminate");
    let side_effect_executed = payload
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let state = match execution_status {
        "completed" | "simulated" => "completed",
        "failed" if !side_effect_executed => "failed",
        _ => "indeterminate",
    };
    reservation["state"] = json!(state);
    reservation["execution_status"] = json!(execution_status);
    reservation["side_effect_executed"] = json!(side_effect_executed);
    reservation["simulated"] = payload.get("simulated").cloned().unwrap_or(json!(false));
    reservation["output_digest"] = output_summary(payload.get("output").unwrap_or(&Value::Null));
    reservation["updated_at_unix_nanos"] = json!(
        time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
    );

    let sequence = RESERVATION_UPDATE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path = dir.join(format!(
        ".{reservation_id}.final-{}-{sequence}.tmp",
        std::process::id()
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        let mut bytes = serde_json::to_vec_pretty(&reservation)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary_path, &path)?;
        sync_directory(&dir)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result?;
    Ok(ReservationAuditBinding {
        state: state.to_string(),
        record_sha256: hex_sha256(&canonical_json_bytes(&reservation)),
    })
}

fn create_and_sync_directory(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create durable state directory {}", path.display()))?;
    if let Some(parent) = path.parent()
        && parent.exists()
    {
        sync_directory(parent)
            .with_context(|| format!("sync state parent directory {}", parent.display()))?;
    }
    sync_directory(path).with_context(|| format!("sync state directory {}", path.display()))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

fn create_new_lock_file_with_retry(path: &Path) -> std::io::Result<std::fs::File> {
    const RETRIES: usize = 200;
    for attempt in 0..=RETRIES {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => return Ok(file),
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < RETRIES =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("lock retry loop always returns")
}

fn safe_record_id_mcp(record_id: &str) -> anyhow::Result<&str> {
    if record_id.is_empty()
        || !record_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        bail!("approval id contains invalid characters");
    }
    Ok(record_id)
}

fn append_mcp_provider_event(outcome: &ProviderOutcome, payload: &Value) -> anyhow::Result<Value> {
    let path = state_dir_mcp().join("events.jsonl");
    append_mcp_provider_event_to_path(&path, outcome, payload)
}

fn fail_closed_before_external_effect(
    id: Value,
    call: &ProviderCall,
    arguments: &Value,
    gate_id: &str,
    error_kind: ErrorKind,
    reason: String,
    anomaly: Option<&Value>,
) -> Value {
    let outcome = ProviderOutcome::before_side_effect(
        PolicyDecision::Denied,
        call,
        gate_id,
        reason,
        Some(error_kind),
    );
    let payload = provider_outcome_payload(&outcome, Some(arguments), anomaly);
    match append_mcp_provider_event(&outcome, &payload) {
        Ok(payload) => tool_error_result(id, payload),
        Err(error) => {
            tool_error_result(id, trace_write_failure_payload(&outcome, &payload, &error))
        }
    }
}

fn trace_write_failure_payload(
    outcome: &ProviderOutcome,
    payload: &Value,
    error: &anyhow::Error,
) -> Value {
    let mut failure = payload.clone();
    let reason = format!("provider event trace write failed: {error}");
    let side_effect_executed = payload
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .unwrap_or(outcome.envelope.side_effect_executed);
    failure["provider"] = json!(&outcome.envelope.provider);
    failure["action"] = json!(&outcome.envelope.action);
    failure["decision"] = json!(&outcome.decision);
    failure["error_kind"] = json!(ErrorKind::TraceWriteFailed);
    failure["reason"] = json!(&reason);
    failure["obs_ref"] = json!(&outcome.observation_id);
    failure["side_effect_executed"] = json!(side_effect_executed);
    failure["trace_persisted"] = json!(false);
    if let Some(envelope) = failure.get_mut("envelope") {
        envelope["error_kind"] = json!(ErrorKind::TraceWriteFailed);
        envelope["reason"] = json!(reason);
        envelope["side_effect_executed"] = json!(side_effect_executed);
    }
    failure
}

fn mcp_provider_event_append_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut canonical = serde_json::Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize_json(&object[key]));
            }
            Value::Object(canonical)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(&canonicalize_json(value)).unwrap_or_default()
}

fn audit_payload_without_raw_output(payload: &Value) -> Value {
    let mut audit = payload.clone();
    let digest = payload
        .get("output_digest")
        .cloned()
        .unwrap_or_else(|| output_summary(payload.get("output").unwrap_or(&Value::Null)));
    audit["output"] = digest.clone();
    audit["output_digest"] = digest;
    audit
}

fn provider_event_canonical_sha256(event: &Value) -> anyhow::Result<String> {
    let mut canonical_event = event.clone();
    let data = canonical_event
        .get_mut("data")
        .and_then(Value::as_object_mut)
        .context("provider event is missing object data")?;
    data.remove("trace_event");
    Ok(hex_sha256(&canonical_json_bytes(&canonical_event)))
}

fn verify_provider_event_wrapper_binding(event: &Value) -> anyhow::Result<()> {
    let expected = event
        .get("data")
        .and_then(|data| data.get("trace_event"))
        .and_then(|trace| trace.get("payload"))
        .and_then(|payload| payload.get("provider_event_binding"))
        .context("provider trace is missing provider_event_binding")?;
    if expected.get("schema_version").and_then(Value::as_str) != Some(PROVIDER_EVENT_BINDING_SCHEMA)
    {
        bail!("provider event binding schema is invalid");
    }
    let expected_sha = expected
        .get("canonical_event_sha256")
        .and_then(Value::as_str)
        .context("provider event binding is missing canonical_event_sha256")?;
    let actual_sha = provider_event_canonical_sha256(event)?;
    if expected_sha != actual_sha {
        bail!("provider event wrapper does not match its sealed canonical binding");
    }
    let data = event
        .get("data")
        .context("provider event is missing data")?;
    verify_completion_wrapper_binding(data)?;
    Ok(())
}

struct DurableAppendLock {
    path: PathBuf,
}

impl Drop for DurableAppendLock {
    fn drop(&mut self) {
        if std::fs::remove_file(&self.path).is_ok()
            && let Some(parent) = self.path.parent()
        {
            let _ = sync_directory(parent);
        }
    }
}

fn acquire_durable_append_lock(path: &Path) -> anyhow::Result<DurableAppendLock> {
    let parent = path
        .parent()
        .context("provider event path is missing parent directory")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("provider event path has no UTF-8 file name")?;
    let lock_path = parent.join(format!(".{file_name}.append.lock"));
    let mut file = create_new_lock_file_with_retry(&lock_path)
        .with_context(|| {
            format!(
                "acquire provider event append lock {}; if a process crashed, verify events.jsonl before manually removing the stale lock",
                lock_path.display()
            )
        })?;
    let metadata = json!({
        "schema_version": "runwarden.provider-event-append-lock.v1",
        "pid": std::process::id(),
        "created_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
    });
    let mut bytes = serde_json::to_vec(&metadata)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_directory(parent)?;
    Ok(DurableAppendLock { path: lock_path })
}

fn append_mcp_provider_event_to_path(
    path: &Path,
    outcome: &ProviderOutcome,
    payload: &Value,
) -> anyhow::Result<Value> {
    let _append_guard = mcp_provider_event_append_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("MCP provider event append lock is poisoned"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _durable_lock = acquire_durable_append_lock(path)?;
    verify_completion_wrapper_binding(payload)?;
    let mut response_payload = payload.clone();
    let audit_payload = audit_payload_without_raw_output(payload);
    let mut event = json!({
        "kind": "provider_call",
        "provider": &outcome.envelope.provider,
        "action": &outcome.envelope.action,
        "decision": &outcome.decision,
        "error_kind": &outcome.envelope.error_kind,
        "reason": &outcome.envelope.reason,
        "obs_ref": &outcome.observation_id,
        "approval_id": audit_payload
            .get("approval_id")
            .cloned()
            .or_else(|| (outcome.decision == PolicyDecision::RequiresReview)
                .then(|| json!(format!("webui-{}", outcome.observation_id))))
            .unwrap_or(Value::Null),
        "side_effect_executed": audit_payload
            .get("side_effect_executed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "data": audit_payload
    });
    let mut trace_event: TraceEvent = serde_json::from_value(
        event
            .get("data")
            .and_then(|data| data.get("trace_event"))
            .cloned()
            .context("provider payload is missing trace_event")?,
    )?;
    let wrapper_sha256 = provider_event_canonical_sha256(&event)?;
    trace_event.payload["provider_event_binding"] = json!({
        "schema_version": PROVIDER_EVENT_BINDING_SCHEMA,
        "canonical_event_sha256": wrapper_sha256
    });
    let trace_event = TraceEvent::sealed(
        trace_event.obs_id,
        trace_event.event_type,
        trace_event.provider,
        trace_event.payload,
        last_verified_mcp_provider_event_hash(path)?,
    );
    let sealed_trace_event = serde_json::to_value(trace_event)?;
    event["data"]["trace_event"] = sealed_trace_event.clone();
    response_payload["trace_event"] = sealed_trace_event;
    verify_provider_event_wrapper_binding(&event)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(response_payload)
}

fn last_verified_mcp_provider_event_hash(path: &Path) -> anyhow::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let events = read_mcp_provider_trace_events_from_path(path)?;
    Ok(events.last().map(|event| event.event_hash.clone()))
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

fn provider_outcome_payload(
    outcome: &ProviderOutcome,
    arguments: Option<&Value>,
    anomaly: Option<&Value>,
) -> Value {
    let argument_preview = (outcome.decision == PolicyDecision::RequiresReview)
        .then(|| arguments.map(redacted_argument_preview))
        .flatten();
    let mut payload = serde_json::to_value(outcome).expect("provider outcome serializes");
    payload["provider"] = json!(&outcome.envelope.provider);
    payload["action"] = json!(&outcome.envelope.action);
    payload["error_kind"] = json!(&outcome.envelope.error_kind);
    payload["reason"] = json!(&outcome.envelope.reason);
    payload["side_effect_executed"] = json!(outcome.envelope.side_effect_executed);
    payload["obs_ref"] = json!(&outcome.observation_id);
    if outcome.decision == PolicyDecision::RequiresReview {
        payload["approval_id"] = json!(format!("webui-{}", outcome.observation_id));
    }
    if outcome.envelope.gate_id == "behavior_anomaly" {
        payload["defense_layer"] = json!("behavior-risk");
    }
    if let Some(argument_preview) = argument_preview.as_ref() {
        payload["argument_preview"] = argument_preview.clone();
    }
    payload["trace_event"] = trace_event_for_outcome(outcome, anomaly, argument_preview.as_ref());
    if let Some(anomaly) = anomaly {
        payload["anomaly"] = anomaly.clone();
    }
    payload
}

fn trace_event_for_outcome(
    outcome: &ProviderOutcome,
    anomaly: Option<&Value>,
    argument_preview: Option<&Value>,
) -> Value {
    let event_type = match outcome.decision {
        PolicyDecision::Allowed => "provider_policy_evaluated",
        PolicyDecision::Denied => "provider_denied",
        PolicyDecision::RequiresReview => "provider_approval_pending",
    };
    let execution_status = serde_json::to_value(&outcome.execution_status)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "not_executed".to_string());
    trace_event_for_provider_result(
        outcome,
        ProviderTraceDetails {
            event_type,
            execution_status: &execution_status,
            simulated: false,
            side_effect_executed: outcome.envelope.side_effect_executed,
            anomaly,
            argument_preview,
            completion_binding: None,
        },
    )
}

struct ProviderTraceDetails<'a> {
    event_type: &'a str,
    execution_status: &'a str,
    simulated: bool,
    side_effect_executed: bool,
    anomaly: Option<&'a Value>,
    argument_preview: Option<&'a Value>,
    completion_binding: Option<&'a Value>,
}

fn trace_event_for_provider_result(
    outcome: &ProviderOutcome,
    details: ProviderTraceDetails<'_>,
) -> Value {
    let mut payload = json!({
        "provider": &outcome.envelope.provider,
        "action": &outcome.envelope.action,
        "decision": &outcome.decision,
        "execution_status": details.execution_status,
        "gate_id": &outcome.envelope.gate_id,
        "reason": &outcome.envelope.reason,
        "error_kind": &outcome.envelope.error_kind,
        "side_effect_executed": details.side_effect_executed,
        "simulated": details.simulated
    });
    if let Some(anomaly) = details.anomaly {
        payload["anomaly"] = anomaly.clone();
    }
    if let Some(argument_preview) = details.argument_preview {
        payload["argument_preview"] = argument_preview.clone();
    }
    if let Some(completion_binding) = details.completion_binding {
        payload["completion_binding"] = completion_binding.clone();
    }
    if outcome.envelope.gate_id == "behavior_anomaly" {
        payload["defense_layer"] = json!("behavior-risk");
    }
    let event = TraceEvent::sealed(
        outcome.observation_id.clone(),
        details.event_type.to_string(),
        Some(outcome.envelope.provider.clone()),
        payload,
        None,
    );
    serde_json::to_value(event).expect("trace event serializes")
}

fn redacted_argument_preview(arguments: &Value) -> Value {
    let Some(arguments) = arguments.as_object() else {
        return summarized_value(arguments);
    };
    let mut preview = serde_json::Map::new();
    for (key, value) in arguments {
        let normalized = key.to_ascii_lowercase();
        let preview_value = if is_sensitive_argument_key(&normalized)
            || matches!(
                normalized.as_str(),
                "path" | "input_path" | "trace_path" | "report_path" | "to" | "subject" | "key"
            ) {
            summarized_value(value)
        } else if normalized == "url" {
            sanitized_url_preview(value)
        } else if matches!(
            normalized.as_str(),
            "provider" | "action" | "method" | "input_source" | "format"
        ) {
            value.clone()
        } else {
            summarized_value(value)
        };
        preview.insert(key.clone(), preview_value);
    }
    Value::Object(preview)
}

fn is_sensitive_argument_key(key: &str) -> bool {
    matches!(
        key,
        "content"
            | "body"
            | "value"
            | "input_text"
            | "payload"
            | "query"
            | "token"
            | "password"
            | "passwd"
            | "secret"
            | "authorization"
            | "cookie"
    ) || key.contains("token")
        || key.contains("password")
        || key.contains("passwd")
        || key.contains("secret")
        || key.contains("authorization")
        || key.contains("cookie")
        || (key != "key" && (key.ends_with("_key") || key.starts_with("key_")))
}

fn sanitized_url_preview(value: &Value) -> Value {
    let Some(raw) = value.as_str() else {
        return summarized_value(value);
    };
    let Ok(url) = Url::parse(raw) else {
        return summarized_value(value);
    };
    json!({
        "scheme": url.scheme(),
        "host": url.host_str().map(normalize_host),
        "port": url.port(),
        "path": summarized_value(&json!(url.path())),
        "query": url.query().map(|query| summarized_value(&json!(query)))
    })
}

fn summarized_value(value: &Value) -> Value {
    let bytes = match value {
        Value::String(value) => value.as_bytes().to_vec(),
        _ => serde_json::to_vec(value).unwrap_or_default(),
    };
    let value_type = match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    json!({
        "redacted": true,
        "type": value_type,
        "bytes": bytes.len(),
        "sha256": hex_sha256(&bytes)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AnomalyHistoryKey {
    state_scope: PathBuf,
    session_id: String,
}

fn anomaly_histories() -> &'static Mutex<HashMap<AnomalyHistoryKey, Vec<BehaviorObservation>>> {
    static STORE: OnceLock<Mutex<HashMap<AnomalyHistoryKey, Vec<BehaviorObservation>>>> =
        OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn anomaly_history_dir_mcp() -> PathBuf {
    state_dir_mcp().join("anomaly-history")
}

fn anomaly_history_session_key(call: &ProviderCall) -> String {
    hex_sha256(call.session_id.as_bytes())
}

fn anomaly_history_path_mcp(call: &ProviderCall) -> PathBuf {
    anomaly_history_dir_mcp().join(format!("{}.json", anomaly_history_session_key(call)))
}

struct AnomalyHistoryLock {
    path: PathBuf,
}

impl Drop for AnomalyHistoryLock {
    fn drop(&mut self) {
        if std::fs::remove_file(&self.path).is_ok()
            && let Some(parent) = self.path.parent()
        {
            let _ = sync_directory(parent);
        }
    }
}

fn acquire_anomaly_history_lock(call: &ProviderCall) -> anyhow::Result<AnomalyHistoryLock> {
    let dir = anomaly_history_dir_mcp();
    create_and_sync_directory(&dir)?;
    let session_key = anomaly_history_session_key(call);
    let path = dir.join(format!(".{session_key}.lock"));
    let mut file = create_new_lock_file_with_retry(&path)
        .with_context(|| {
            format!(
                "acquire behavior-history lock {}; a stale lock requires operator verification before removal",
                path.display()
            )
        })?;
    let metadata = json!({
        "schema_version": "runwarden.anomaly-history-lock.v1",
        "session_sha256": session_key,
        "pid": std::process::id(),
        "created_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
    });
    let mut bytes = serde_json::to_vec(&metadata)?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_directory(&dir)?;
    Ok(AnomalyHistoryLock { path })
}

fn anomaly_history_key(call: &ProviderCall) -> AnomalyHistoryKey {
    let state_scope = if state_dir_mcp().is_absolute() {
        state_dir_mcp()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(state_dir_mcp())
    };
    AnomalyHistoryKey {
        state_scope,
        session_id: call.session_id.clone(),
    }
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(normalize_host))
}

fn anomaly_observation(call: &ProviderCall) -> BehaviorObservation {
    let arg_bytes = serde_json::to_vec(&call.arguments)
        .map(|value| value.len())
        .unwrap_or(0);
    let egress_host = call
        .arguments
        .get("url")
        .and_then(Value::as_str)
        .and_then(host_of);
    BehaviorObservation {
        provider: call.provider.clone(),
        arg_bytes,
        egress_host,
    }
}

/// Score without committing the candidate. This lets kernel/anomaly denials
/// remain invisible to the learned benign baseline.
#[cfg(test)]
fn preview_anomaly_report(call: &ProviderCall) -> AnomalyReport {
    preview_anomaly_report_checked(call).expect("durable anomaly history must be readable")
}

fn preview_anomaly_report_checked(call: &ProviderCall) -> anyhow::Result<AnomalyReport> {
    let history = load_anomaly_history(call)?;
    let candidate = anomaly_observation(call);
    let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
    for observation in history {
        monitor.analyze(
            &observation.provider,
            observation.arg_bytes,
            observation.egress_host.as_deref(),
        );
    }
    Ok(monitor.analyze(
        &candidate.provider,
        candidate.arg_bytes,
        candidate.egress_host.as_deref(),
    ))
}

#[cfg(test)]
fn commit_anomaly_observation(call: &ProviderCall) {
    commit_anomaly_observation_checked(call).expect("durable anomaly history must be writable");
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnomalyHistoryCommitBinding {
    generation: u64,
    record_sha256: String,
}

fn load_anomaly_history(call: &ProviderCall) -> anyhow::Result<Vec<BehaviorObservation>> {
    if let Some((_, history)) = read_durable_anomaly_history(call)? {
        return Ok(history);
    }
    Ok(anomaly_histories()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&anomaly_history_key(call))
        .cloned()
        .unwrap_or_default())
}

fn read_durable_anomaly_history(
    call: &ProviderCall,
) -> anyhow::Result<Option<(u64, Vec<BehaviorObservation>)>> {
    let path = anomaly_history_path_mcp(call);
    if !path.exists() {
        return Ok(None);
    }
    let record: Value = serde_json::from_slice(
        &std::fs::read(&path)
            .with_context(|| format!("read behavior history {}", path.display()))?,
    )
    .with_context(|| format!("parse behavior history {}", path.display()))?;
    if record.get("schema_version").and_then(Value::as_str) != Some("runwarden.anomaly-history.v1")
        || record.get("profile_version").and_then(Value::as_str) != Some(ANOMALY_PROFILE_VERSION)
        || record.get("session_sha256").and_then(Value::as_str)
            != Some(anomaly_history_session_key(call).as_str())
    {
        bail!("behavior history identity or profile version is invalid");
    }
    let generation = record
        .get("generation")
        .and_then(Value::as_u64)
        .context("behavior history is missing generation")?;
    let observations = record
        .get("observations")
        .and_then(Value::as_array)
        .context("behavior history is missing observations")?;
    let profile = BehaviorProfile::default_benign();
    if observations.len() > profile.history_window {
        bail!("behavior history exceeds configured bounded window");
    }
    let mut history = Vec::with_capacity(observations.len());
    for observation in observations {
        let provider = observation
            .get("provider")
            .and_then(Value::as_str)
            .context("behavior observation is missing provider")?
            .to_string();
        let arg_bytes = observation
            .get("arg_bytes")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .context("behavior observation has invalid arg_bytes")?;
        let egress_host = match observation.get("egress_host") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .context("behavior observation has invalid egress_host")?
                    .to_string(),
            ),
        };
        history.push(BehaviorObservation {
            provider,
            arg_bytes,
            egress_host,
        });
    }
    Ok(Some((generation, history)))
}

fn commit_anomaly_observation_checked(
    call: &ProviderCall,
) -> anyhow::Result<AnomalyHistoryCommitBinding> {
    let profile = BehaviorProfile::default_benign();
    let (generation, mut history) = match read_durable_anomaly_history(call)? {
        Some(value) => value,
        None => (
            0,
            anomaly_histories()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&anomaly_history_key(call))
                .cloned()
                .unwrap_or_default(),
        ),
    };
    history.push(anomaly_observation(call));
    if history.len() > profile.history_window {
        history.drain(..history.len() - profile.history_window);
    }
    let generation = generation
        .checked_add(1)
        .context("behavior history generation overflow")?;
    let record = json!({
        "schema_version": "runwarden.anomaly-history.v1",
        "profile_version": ANOMALY_PROFILE_VERSION,
        "session_sha256": anomaly_history_session_key(call),
        "generation": generation,
        "history_window": profile.history_window,
        "updated_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string(),
        "observations": history.iter().map(|observation| json!({
            "provider": observation.provider,
            "arg_bytes": observation.arg_bytes,
            "egress_host": observation.egress_host
        })).collect::<Vec<_>>()
    });
    persist_anomaly_history_record(call, &record)?;
    anomaly_histories()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(anomaly_history_key(call), history);
    Ok(AnomalyHistoryCommitBinding {
        generation,
        record_sha256: hex_sha256(&canonical_json_bytes(&record)),
    })
}

fn persist_anomaly_history_record(call: &ProviderCall, record: &Value) -> anyhow::Result<()> {
    static HISTORY_UPDATE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    let dir = anomaly_history_dir_mcp();
    create_and_sync_directory(&dir)?;
    let path = anomaly_history_path_mcp(call);
    let sequence = HISTORY_UPDATE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_path = dir.join(format!(
        ".{}.{}-{sequence}.tmp",
        anomaly_history_session_key(call),
        std::process::id()
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        let mut bytes = serde_json::to_vec_pretty(record)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary_path, &path)?;
        sync_directory(&dir)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn anomaly_requires_denial(report: &AnomalyReport) -> bool {
    report.risk_level == RiskLevel::Critical || report.recommended_action == RecommendedAction::Deny
}

fn anomaly_requires_review(report: &AnomalyReport) -> bool {
    report.recommended_action == RecommendedAction::RequireReview
}

fn anomaly_policy_outcome(
    call: &ProviderCall,
    report: &AnomalyReport,
    decision: PolicyDecision,
) -> ProviderOutcome {
    let signals = report
        .signals
        .iter()
        .map(|signal| signal.kind.as_str())
        .collect::<Vec<_>>()
        .join(",");
    ProviderOutcome::before_side_effect(
        decision.clone(),
        call,
        "behavior_anomaly",
        format!(
            "behavior-risk score={} risk={} recommendation={} signals=[{}]",
            report.score,
            report.risk_level.as_str(),
            report.recommended_action.as_str(),
            signals
        ),
        Some(if decision == PolicyDecision::RequiresReview {
            ErrorKind::ApprovalInvalid
        } else {
            ErrorKind::ProviderNotAllowed
        }),
    )
}

fn external_provider_result(
    outcome: &ProviderOutcome,
    arguments: &Value,
    sandbox_root: &Path,
    anomaly: &Value,
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
    let mut result = json!({
        "provider": &outcome.envelope.provider,
        "action": &outcome.envelope.action,
        "decision": "allowed",
        "execution_status": execution_status,
        "simulated": simulated,
        "side_effect_executed": side_effect_executed,
        "obs_ref": &outcome.observation_id,
        "output": executed.get("output").cloned().unwrap_or(Value::Null),
        "anomaly": anomaly
    });
    for field in [
        "execution_mode",
        "language",
        "code_executed",
        "side_effect_kind",
        "resource_usage",
    ] {
        if let Some(value) = executed.get(field) {
            result[field] = value.clone();
        }
    }
    result
}

fn output_summary(value: &Value) -> Value {
    let bytes = canonical_json_bytes(value);
    let value_type = match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    };
    json!({
        "redacted": true,
        "type": value_type,
        "bytes": bytes.len(),
        "sha256": hex_sha256(&bytes)
    })
}

fn completion_wrapper_binding(payload: &Value) -> Value {
    let output = payload.get("output").unwrap_or(&Value::Null);
    let stored_digest = payload.get("output_digest");
    let output_is_audit_digest = output
        .get("redacted")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && output.get("sha256").is_some()
        && stored_digest == Some(output);
    let output_digest = if output_is_audit_digest {
        output.clone()
    } else {
        output_summary(output)
    };
    json!({
        "output_digest": &output_digest,
        "output_summary": &output_digest,
        "side_effect_executed": payload
            .get("side_effect_executed")
            .cloned()
            .unwrap_or(json!(false)),
        "execution_reservation_id": payload
            .get("execution_reservation_id")
            .cloned()
            .unwrap_or(Value::Null),
        "reservation_state": payload
            .get("reservation_state")
            .cloned()
            .unwrap_or(Value::Null),
        "reservation_digest": payload
            .get("reservation_digest")
            .cloned()
            .unwrap_or(Value::Null),
        "approval_id": payload.get("approval_id").cloned().unwrap_or(Value::Null),
        "argument_preview": payload
            .get("argument_preview")
            .cloned()
            .unwrap_or(Value::Null),
        "anomaly": payload.get("anomaly").cloned().unwrap_or(Value::Null)
    })
}

fn finalize_provider_completion_payload(
    outcome: &ProviderOutcome,
    call: &ProviderCall,
    arguments: &Value,
    execution_reservation_id: Option<&str>,
    payload: &mut Value,
) {
    let argument_preview = redacted_argument_preview(arguments);
    payload["argument_preview"] = argument_preview.clone();
    payload["output_digest"] = output_summary(payload.get("output").unwrap_or(&Value::Null));
    if let Some(approval_id) = call.approval_id.as_ref() {
        payload["approval_id"] = json!(approval_id);
    }
    if let Some(reservation_id) = execution_reservation_id {
        payload["execution_reservation_id"] = json!(reservation_id);
    }
    let completion_binding = completion_wrapper_binding(payload);
    let execution_status = payload
        .get("execution_status")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    let simulated = payload
        .get("simulated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let side_effect_executed = payload
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let event_type = if simulated {
        "provider_simulated_replay"
    } else {
        "provider_completed"
    };
    payload["trace_event"] = trace_event_for_provider_result(
        outcome,
        ProviderTraceDetails {
            event_type,
            execution_status,
            simulated,
            side_effect_executed,
            anomaly: payload.get("anomaly"),
            argument_preview: Some(&argument_preview),
            completion_binding: Some(&completion_binding),
        },
    );
}

fn verify_completion_wrapper_binding(payload: &Value) -> anyhow::Result<()> {
    let Some(expected) = payload
        .get("trace_event")
        .and_then(|trace| trace.get("payload"))
        .and_then(|trace_payload| trace_payload.get("completion_binding"))
    else {
        return Ok(());
    };
    let actual = completion_wrapper_binding(payload);
    if expected != &actual {
        bail!("provider completion wrapper does not match its sealed trace binding");
    }
    Ok(())
}

fn provider_is_external(provider_id: &str) -> bool {
    default_external_providers()
        .into_iter()
        .any(|provider| provider.id == provider_id)
}

fn inline_trace_events(arguments: &Value) -> anyhow::Result<Vec<TraceEvent>> {
    let value = arguments
        .get("trace_events")
        .context("trace_events is required")?;
    if !value.is_array() {
        bail!("trace_events must be an array");
    }
    serde_json::from_value::<Vec<TraceEvent>>(value.clone())
        .context("trace_events contains an invalid trace event")
}

fn invalid_inline_trace(error_kind: &str, message: &str, event_count: usize) -> Value {
    json!({
        "verified": false,
        "event_count": event_count,
        "error": {
            "kind": error_kind,
            "message": message
        }
    })
}

fn handle_trace_verify(id: Value, arguments: &Value) -> Value {
    let trace_events = match inline_trace_events(arguments) {
        Ok(events) => events,
        Err(_) => {
            return tool_error_result(
                id,
                json!({
                    "verified": false,
                    "event_count": 0,
                    "error": invalid_inline_trace(
                        "trace_invalid",
                        "trace_events must be a non-empty array of valid sealed trace events",
                        0
                    )["error"],
                    "side_effect_executed": false
                }),
            );
        }
    };
    let verification = verify_inline_trace(&trace_events);
    let payload = json!({
        "verified": verification["verified"],
        "event_count": verification["event_count"],
        "error": verification.get("error"),
        "side_effect_executed": false
    });
    if verification["verified"].as_bool() == Some(true) {
        tool_result(id, payload)
    } else {
        tool_error_result(id, payload)
    }
}

fn handle_trace_export(id: Value, arguments: &Value, identity: &ServerIdentity) -> Value {
    let trace_events = match inline_trace_events(arguments) {
        Ok(events) => events,
        Err(_) => {
            return tool_error_result(
                id,
                json!({
                    "exported": false,
                    "verified": false,
                    "verification": invalid_inline_trace(
                        "trace_invalid",
                        "trace_events must be a non-empty array of valid sealed trace events",
                        0
                    ),
                    "side_effect_executed": false
                }),
            );
        }
    };
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

    let call =
        provider_call_from_arguments_for_identity("runwarden.trace.export", arguments, identity);
    let mut enforcer = KernelEnforcer::new(
        first_party_provider_registry(),
        mcp_single_provider_policy("runwarden.trace.export"),
    );
    let outcome = enforcer.evaluate_call(&call);
    if outcome.decision != PolicyDecision::Allowed {
        return tool_error_result(id, provider_outcome_payload(&outcome, None, None));
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
    if trace_events.is_empty() {
        return invalid_inline_trace(
            "trace_empty",
            "an empty trace is not evidence and cannot be verified",
            0,
        );
    }
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

fn handle_report_render(id: Value, params: Option<&Value>, identity: &ServerIdentity) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let call =
        provider_call_from_arguments_for_identity("runwarden.report.render", arguments, identity);
    let mut enforcer = KernelEnforcer::new(
        first_party_provider_registry(),
        mcp_single_provider_policy("runwarden.report.render"),
    );
    let outcome = enforcer.evaluate_call(&call);
    if outcome.decision != PolicyDecision::Allowed {
        return tool_error_result(id, provider_outcome_payload(&outcome, None, None));
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
    read_mcp_provider_trace_events_from_path(&path)
}

fn read_mcp_provider_trace_events_from_path(path: &Path) -> anyhow::Result<Vec<TraceEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read MCP provider events from {}", path.display()))?;
    let mut trace_events = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(line)
            .with_context(|| format!("parse MCP provider event line {}", index + 1))?;
        verify_provider_event_wrapper_binding(&event).with_context(|| {
            format!(
                "verify canonical provider event binding on MCP provider event line {}",
                index + 1
            )
        })?;
        let data = event
            .get("data")
            .with_context(|| format!("MCP provider event line {} is missing data", index + 1))?;
        let trace_event = data.get("trace_event").cloned().with_context(|| {
            format!(
                "MCP provider event line {} is missing data.trace_event",
                index + 1
            )
        })?;
        trace_events.push(serde_json::from_value(trace_event).with_context(|| {
            format!("parse trace_event on MCP provider event line {}", index + 1)
        })?);
    }
    let mut store = InMemoryTraceStore::default();
    for event in trace_events.iter().cloned() {
        store.append(event);
    }
    store.verify_hash_chain().map_err(|error| {
        anyhow::anyhow!(
            "MCP provider trace chain failed at offset {} ({}): {}",
            error.offset,
            error.obs_id,
            error.reason
        )
    })?;
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
    use std::ffi::OsString;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "runwarden-mcp-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("test dir");
        dir
    }

    fn unit_test_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct ScopedMcpEnv {
        old_state: Option<OsString>,
        old_sandbox: Option<OsString>,
    }

    impl ScopedMcpEnv {
        fn set(state_dir: &Path, sandbox_root: &Path) -> Self {
            let old_state = std::env::var_os("RUNWARDEN_STATE_DIR");
            let old_sandbox = std::env::var_os("RUNWARDEN_SANDBOX_ROOT");
            unsafe {
                std::env::set_var("RUNWARDEN_STATE_DIR", state_dir);
                std::env::set_var("RUNWARDEN_SANDBOX_ROOT", sandbox_root);
            }
            Self {
                old_state,
                old_sandbox,
            }
        }
    }

    impl Drop for ScopedMcpEnv {
        fn drop(&mut self) {
            unsafe {
                match self.old_state.take() {
                    Some(value) => std::env::set_var("RUNWARDEN_STATE_DIR", value),
                    None => std::env::remove_var("RUNWARDEN_STATE_DIR"),
                }
                match self.old_sandbox.take() {
                    Some(value) => std::env::set_var("RUNWARDEN_SANDBOX_ROOT", value),
                    None => std::env::remove_var("RUNWARDEN_SANDBOX_ROOT"),
                }
            }
        }
    }

    fn call_provider_for_session(id: u64, session_id: &str, arguments: Value) -> Value {
        let params = json!({"arguments": arguments});
        handle_provider_call_for_session(json!(id), Some(&params), session_id)
    }

    fn tool_payload(response: &Value) -> &Value {
        &response["result"]["structuredContent"]
    }

    fn approve_pending(state_dir: &Path, approval_id: &str) {
        let path = state_dir
            .join("approvals")
            .join(format!("{approval_id}.json"));
        let mut approval: ApprovalRecord =
            serde_json::from_slice(&fs::read(&path).expect("pending approval record"))
                .expect("pending approval json");
        approval
            .approve("behavior-reviewer", "reviewed anomaly evidence")
            .expect("approve pending behavior review");
        persist_approval_record_atomically(&path, &approval).expect("persist approved record");
        append_approval_audit_for_test(state_dir, &approval);
    }

    fn append_approval_audit_for_test(state_dir: &Path, approval: &ApprovalRecord) {
        let path = state_dir.join("approval-events.jsonl");
        let previous_hash = fs::read_to_string(&path).ok().and_then(|body| {
            body.lines()
                .rfind(|line| !line.trim().is_empty())
                .and_then(|line| serde_json::from_str::<TraceEvent>(line).ok())
                .map(|event| event.event_hash)
        });
        let approval_value = serde_json::to_value(approval).expect("approval value");
        let binding_value = serde_json::to_value(&approval.binding).expect("binding value");
        let event = TraceEvent::sealed(
            format!("obs_approval_test_{}", approval.approval_id),
            "approval_decision".to_string(),
            Some(approval.binding.provider.clone()),
            json!({
                "schema_version": "runwarden.approval-decision.v1",
                "approval_id": approval.approval_id,
                "state": approval.state,
                "provider": approval.binding.provider,
                "action": approval.binding.action,
                "binding_sha256": hex_sha256(&canonical_json_bytes(&binding_value)),
                "record_sha256": hex_sha256(&canonical_json_bytes(&approval_value)),
                "decision": "approved",
                "side_effect_executed": false
            }),
            previous_hash,
        );
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("approval audit");
        writeln!(
            file,
            "{}",
            serde_json::to_string(&event).expect("approval event JSON")
        )
        .expect("append approval audit");
        file.sync_all().expect("sync approval audit");
    }

    fn approved_call_fixture(
        state_dir: &Path,
        approval_id: &str,
    ) -> (ProviderCall, ApprovalBinding, ApprovalRecord, PathBuf) {
        let arguments = json!({
            "provider": "external.email.send",
            "action": "send",
            "to": "security@example.test"
        });
        let mut call = provider_call_from_arguments_for_identity(
            "external.email.send",
            &arguments,
            &ServerIdentity::from_environment_values(Some("audit-test"), Some("actor"))
                .expect("identity"),
        );
        call.approval_id = Some(approval_id.to_string());
        let binding = approval_binding_for_mcp_call(&call);
        let mut approval = ApprovalRecord::new(approval_id, binding.clone());
        approval
            .approve("reviewer", "approved with audited authority")
            .expect("approve");
        let approvals_dir = state_dir.join("approvals");
        fs::create_dir_all(&approvals_dir).expect("approvals dir");
        let path = approvals_dir.join(format!("{approval_id}.json"));
        persist_approval_record_atomically(&path, &approval).expect("persist approval");
        (call, binding, approval, path)
    }

    #[test]
    fn bounded_code_provider_runs_only_after_audited_one_use_approval() {
        let _guard = unit_test_env_lock().lock().expect("unit env lock");
        let temp = unique_test_dir("bounded-code-provider");
        let sandbox = temp.join("sandbox");
        let _env = ScopedMcpEnv::set(&temp, &sandbox);
        let arguments = json!({
            "provider": "external.code.execute",
            "action": "execute",
            "language": "runwarden-expression-v1",
            "program": {
                "op": "add",
                "args": [
                    {"op": "literal", "value": 20},
                    {"op": "literal", "value": 22}
                ]
            }
        });

        let review = call_provider_for_session(991, "code-review-session", arguments.clone());
        let review_payload = tool_payload(&review);
        assert_eq!(review_payload["decision"], "requires_review");
        assert_eq!(review_payload["side_effect_executed"], false);
        let approval_id = review_payload["approval_id"]
            .as_str()
            .expect("code approval id");
        approve_pending(&temp, approval_id);

        let allowed = call_provider_for_session(992, "code-review-session", arguments);
        let payload = tool_payload(&allowed);
        assert_eq!(payload["decision"], "allowed");
        assert_eq!(payload["execution_status"], "completed");
        assert_eq!(payload["execution_mode"], "bounded_expression_vm");
        assert_eq!(payload["code_executed"], true);
        assert_eq!(payload["side_effect_executed"], false);
        assert_eq!(
            payload["resource_usage"]["network"],
            "denied_by_construction"
        );
        assert_eq!(payload["output"], 42.0);
        let saved: ApprovalRecord = serde_json::from_slice(
            &fs::read(temp.join("approvals").join(format!("{approval_id}.json")))
                .expect("consumed code approval"),
        )
        .expect("approval JSON");
        assert_eq!(saved.state, ApprovalState::Consumed);
        fs::remove_dir_all(&temp).expect("remove code provider state");
    }

    #[test]
    fn server_identity_parser_generates_stable_epoch_and_requires_explicit_compatibility() {
        let generated =
            ServerIdentity::from_environment_values(None, None).expect("generated identity");
        let generated_again =
            ServerIdentity::from_environment_values(None, None).expect("stable identity");
        assert!(generated.session_id().starts_with("mcp-epoch-"));
        assert_eq!(generated.session_id(), generated_again.session_id());
        assert_eq!(generated.actor_id(), "mcp-agent");
        assert_eq!(generated.mode(), "generated_process_epoch");

        let compatibility = ServerIdentity::from_environment_values(Some("mcp-inline"), None)
            .expect("explicit compatibility identity");
        assert_eq!(compatibility.session_id(), "mcp-inline");
        assert_eq!(compatibility.mode(), "single_session_compatibility");

        let scoped = ServerIdentity::from_environment_values(
            Some("contest-session_01"),
            Some("agent:red-team@node-2"),
        )
        .expect("launcher identity");
        assert_eq!(scoped.session_id(), "contest-session_01");
        assert_eq!(scoped.actor_id(), "agent:red-team@node-2");
        assert_eq!(scoped.mode(), "launcher_scoped");

        for (session, actor) in [
            (Some(""), None),
            (Some("has whitespace"), None),
            (Some("path/segment"), None),
            (Some(".punctuation"), None),
            (Some("会话"), None),
            (Some("ok"), Some("line\nbreak")),
        ] {
            assert!(
                ServerIdentity::from_environment_values(session, actor).is_err(),
                "unsafe identity was accepted: session={session:?}, actor={actor:?}"
            );
        }
        let oversized = "a".repeat(MAX_SERVER_IDENTITY_BYTES + 1);
        assert!(
            ServerIdentity::from_environment_values(Some(&oversized), None).is_err(),
            "oversized identity was accepted"
        );
    }

    #[test]
    fn server_owned_identities_isolate_binding_history_and_approval_authority() {
        let arguments = json!({
            "provider": "external.email.send",
            "action": "send",
            "to": "security@example.test",
            "subject": "identity isolation"
        });
        let identity_a =
            ServerIdentity::from_environment_values(Some("launcher-a"), Some("actor-a"))
                .expect("identity A");
        let identity_b =
            ServerIdentity::from_environment_values(Some("launcher-b"), Some("actor-b"))
                .expect("identity B");
        let call_a = provider_call_from_arguments_for_identity(
            "external.email.send",
            &arguments,
            &identity_a,
        );
        let mut call_b = provider_call_from_arguments_for_identity(
            "external.email.send",
            &arguments,
            &identity_b,
        );
        assert_eq!(call_a.session_id, "launcher-a");
        assert_eq!(call_a.actor_id.as_deref(), Some("actor-a"));
        assert_eq!(call_b.session_id, "launcher-b");
        assert_eq!(call_b.actor_id.as_deref(), Some("actor-b"));
        assert_ne!(
            anomaly_history_session_key(&call_a),
            anomaly_history_session_key(&call_b),
            "launcher sessions must not share behavior history"
        );

        let binding_a = approval_binding_for_mcp_call(&call_a);
        let binding_b = approval_binding_for_mcp_call(&call_b);
        assert_ne!(binding_a, binding_b);
        let mut approval_a = ApprovalRecord::new("approval-launcher-a", binding_a.clone());
        approval_a
            .approve("reviewer", "approved only for launcher A")
            .expect("approve A");

        assert_eq!(
            attach_matching_approval_mcp(&mut call_b, &[approval_a.clone()], None),
            None,
            "launcher B must not attach launcher A's approval"
        );
        assert!(call_b.approval_id.is_none());
        assert!(
            approval_a.consume_once(&binding_b).is_err(),
            "launcher B must not consume launcher A's approval"
        );
    }

    #[test]
    fn every_catalog_provider_has_one_canonical_action_and_rejects_mismatch() {
        let first_party_actions = [
            ("runwarden.input.inspect", "inspect"),
            ("runwarden.trace.verify", "verify"),
            ("runwarden.trace.export", "export"),
            ("runwarden.report.lint", "lint"),
            ("runwarden.report.render", "render"),
        ];
        let first_party = default_first_party_providers();
        assert_eq!(first_party.len(), first_party_actions.len());
        for provider in first_party {
            let expected = first_party_actions
                .iter()
                .find_map(|(id, action)| (provider.id == *id).then_some(*action))
                .expect("first-party provider action");
            assert_eq!(
                canonical_provider_action(&provider.id).as_deref(),
                Some(expected)
            );
            assert_eq!(
                resolve_provider_action(
                    &provider.id,
                    &json!({"provider": provider.id, "action": expected})
                )
                .expect("canonical first-party action"),
                expected
            );
        }

        for manifest in default_external_provider_manifests() {
            let expected = manifest
                .tool_identity
                .as_deref()
                .expect("external tool identity");
            let valid = json!({
                "provider": manifest.provider_id,
                "action": expected
            });
            assert_eq!(
                resolve_provider_action(&manifest.provider_id, &valid)
                    .expect("canonical external action"),
                expected
            );
            let call = provider_call_from_arguments_for_identity(
                &manifest.provider_id,
                &valid,
                &ServerIdentity::from_environment_values(Some("catalog-test"), None)
                    .expect("identity"),
            );
            assert_eq!(call.action, expected);
            assert!(
                resolve_provider_action(
                    &manifest.provider_id,
                    &json!({"provider": manifest.provider_id, "action": "mismatched"})
                )
                .is_err(),
                "{} accepted a mismatched action",
                manifest.provider_id
            );
        }
    }

    #[test]
    fn approval_claim_fails_closed_while_web_review_lock_exists() {
        let state_dir = unique_test_dir("approval-review-lock");
        let sandbox = state_dir.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        let _guard = unit_test_env_lock().lock().expect("env lock");
        let _env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let arguments = json!({
            "provider": "external.email.send",
            "action": "send",
            "to": "security@example.test"
        });
        let mut call = provider_call_from_arguments_for_identity(
            "external.email.send",
            &arguments,
            &ServerIdentity::from_environment_values(Some("review-lock"), Some("actor"))
                .expect("identity"),
        );
        call.approval_id = Some("approval-review-lock".to_string());
        let binding = approval_binding_for_mcp_call(&call);
        let mut approval = ApprovalRecord::new("approval-review-lock", binding.clone());
        approval
            .approve("reviewer", "approved")
            .expect("approve record");
        let approvals_dir = approvals_dir_mcp();
        fs::create_dir_all(&approvals_dir).expect("approvals dir");
        let approval_path = approvals_dir.join("approval-review-lock.json");
        persist_approval_record_atomically(&approval_path, &approval).expect("persist approval");
        let review_lock_path = approvals_dir.join(".approval-review-lock.review.lock");
        fs::write(&review_lock_path, b"web review in progress\n").expect("review lock fixture");

        let error = claim_and_consume_approval_mcp(&call, &binding)
            .expect_err("claim must wait for audited review transaction");

        assert!(error.to_string().contains("is being reviewed"));
        assert!(
            !state_dir
                .join("approval-claims/approval-review-lock.json")
                .exists(),
            "failed review-lock acquisition must not create a claim"
        );
        let unchanged: ApprovalRecord =
            serde_json::from_slice(&fs::read(&approval_path).expect("approval record"))
                .expect("approval JSON");
        assert_eq!(unchanged.state, ApprovalState::Approved);
        assert!(review_lock_path.exists());
        fs::remove_dir_all(state_dir).expect("cleanup");
    }

    #[test]
    fn manually_approved_record_without_decision_audit_cannot_be_claimed() {
        let state_dir = unique_test_dir("approval-missing-audit");
        let sandbox = state_dir.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        let _guard = unit_test_env_lock().lock().expect("env lock");
        let _env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let (call, binding, _approval, path) =
            approved_call_fixture(&state_dir, "approval-missing-audit");

        let error = claim_and_consume_approval_mcp(&call, &binding)
            .expect_err("manual Approved state must not be sufficient authority");

        assert!(error.to_string().contains("approval decision audit"));
        assert!(
            !state_dir
                .join("approval-claims/approval-missing-audit.json")
                .exists()
        );
        let unchanged: ApprovalRecord =
            serde_json::from_slice(&fs::read(path).expect("approval record"))
                .expect("approval JSON");
        assert_eq!(unchanged.state, ApprovalState::Approved);
        fs::remove_dir_all(state_dir).expect("cleanup");
    }

    #[test]
    fn approved_record_drift_after_audit_cannot_be_claimed() {
        let state_dir = unique_test_dir("approval-record-drift");
        let sandbox = state_dir.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        let _guard = unit_test_env_lock().lock().expect("env lock");
        let _env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let (call, binding, mut approval, path) =
            approved_call_fixture(&state_dir, "approval-record-drift");
        append_approval_audit_for_test(&state_dir, &approval);
        approval.reason = Some("record changed after audit".to_string());
        persist_approval_record_atomically(&path, &approval).expect("persist drifted approval");

        let error = claim_and_consume_approval_mcp(&call, &binding)
            .expect_err("record digest drift must fail closed");

        assert!(error.to_string().contains("record digest"));
        assert!(
            !state_dir
                .join("approval-claims/approval-record-drift.json")
                .exists()
        );
        fs::remove_dir_all(state_dir).expect("cleanup");
    }

    #[test]
    fn resealed_audit_with_wrong_binding_digest_cannot_be_claimed() {
        let state_dir = unique_test_dir("approval-audit-drift");
        let sandbox = state_dir.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        let _guard = unit_test_env_lock().lock().expect("env lock");
        let _env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let (call, binding, approval, _path) =
            approved_call_fixture(&state_dir, "approval-audit-drift");
        append_approval_audit_for_test(&state_dir, &approval);
        let audit_path = state_dir.join("approval-events.jsonl");
        let original: TraceEvent = serde_json::from_str(
            fs::read_to_string(&audit_path)
                .expect("approval audit")
                .trim(),
        )
        .expect("approval audit event");
        let mut payload = original.payload;
        payload["binding_sha256"] = json!(hex_sha256(b"forged-binding"));
        let forged = TraceEvent::sealed(
            original.obs_id,
            original.event_type,
            original.provider,
            payload,
            original.previous_hash,
        );
        fs::write(
            &audit_path,
            format!(
                "{}\n",
                serde_json::to_string(&forged).expect("forged audit JSON")
            ),
        )
        .expect("write forged audit");

        let error = claim_and_consume_approval_mcp(&call, &binding)
            .expect_err("semantic audit digest drift must fail closed");

        assert!(error.to_string().contains("binding digest"));
        assert!(
            !state_dir
                .join("approval-claims/approval-audit-drift.json")
                .exists()
        );
        fs::remove_dir_all(state_dir).expect("cleanup");
    }

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
        let anomaly = serde_json::to_value(AnomalyReport::default()).expect("anomaly json");
        let mut payload = external_provider_result(&outcome, &arguments, &sandbox, &anomaly);
        finalize_provider_completion_payload(
            &outcome,
            &call,
            &arguments,
            Some("reservation-test"),
            &mut payload,
        );

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
            payload["trace_event"]["payload"]["completion_binding"]["execution_reservation_id"],
            "reservation-test"
        );
        assert_eq!(
            payload["trace_event"]["payload"]["completion_binding"]["output_summary"],
            output_summary(&payload["output"])
        );
        assert_eq!(payload["argument_preview"]["content"]["redacted"], true);
        verify_completion_wrapper_binding(&payload).expect("completion binding");
        let mut tampered = payload.clone();
        tampered["output"]["bytes"] = json!(999_999);
        assert!(
            verify_completion_wrapper_binding(&tampered).is_err(),
            "changing wrapper output must be detected by the sealed digest"
        );
        assert_eq!(
            fs::read_to_string(sandbox.join("notes.txt")).expect("written file"),
            "hello"
        );

        let _ = fs::remove_dir_all(&sandbox);
    }

    #[test]
    fn completion_trace_failure_preserves_already_executed_side_effect() {
        let sandbox = std::env::temp_dir().join(format!(
            "runwarden-mcp-completion-trace-failure-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        fs::create_dir_all(&sandbox).expect("sandbox");
        let arguments = json!({"path": "notes.txt", "content": "already written"});
        let call = ProviderCall {
            session_id: "mcp-inline".to_string(),
            provider: "external.mcp.filesystem.write_file".to_string(),
            action: "write_file".to_string(),
            arguments: arguments.clone(),
            actor_id: None,
            authz_id: None,
            approval_id: Some("approval-test".to_string()),
        };
        let outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::Allowed,
            &call,
            "approval",
            "allowed for trace failure test",
            None,
        );
        let anomaly = serde_json::to_value(AnomalyReport::default()).expect("anomaly json");
        let mut payload = external_provider_result(&outcome, &arguments, &sandbox, &anomaly);
        finalize_provider_completion_payload(
            &outcome,
            &call,
            &arguments,
            Some("reservation-trace-failure"),
            &mut payload,
        );
        assert_eq!(payload["side_effect_executed"], true);

        let trace_path = sandbox.join("events.jsonl");
        fs::create_dir_all(&trace_path).expect("trace failure directory");
        let error = append_mcp_provider_event_to_path(&trace_path, &outcome, &payload)
            .expect_err("completion append must fail");
        let failure = trace_write_failure_payload(&outcome, &payload, &error);

        assert_eq!(failure["error_kind"], "trace_write_failed");
        assert_eq!(failure["trace_persisted"], false);
        assert_eq!(
            failure["side_effect_executed"], true,
            "trace failure must not conceal an already executed effect"
        );
        assert_eq!(
            fs::read_to_string(sandbox.join("notes.txt")).expect("written file"),
            "already written"
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

        let anomaly = serde_json::to_value(preview_anomaly_report(&call)).expect("anomaly json");
        let payload = provider_outcome_payload(&outcome, Some(&call.arguments), Some(&anomaly));

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
    fn review_argument_preview_preserves_decision_fields_without_raw_secrets() {
        let arguments = json!({
            "provider": "external.api.request",
            "method": "POST",
            "url": "https://user:password@api.example.com/callback?token=query-secret",
            "path": "reports/q3.txt",
            "to": "reviewer@example.com",
            "subject": "Quarterly review",
            "key": "customer-record-17",
            "token": "token-raw-secret",
            "password": "password-raw-secret",
            "secret": "secret-raw-secret",
            "authorization": "Bearer authorization-raw-secret",
            "cookie": "session=cookie-raw-secret",
            "content": "content-raw-secret",
            "body": {"private": "body-raw-secret"},
            "value": "value-raw-secret",
            "custom": "unknown-raw-secret"
        });
        let call = ProviderCall {
            session_id: "preview-redaction-session".to_string(),
            provider: "external.api.request".to_string(),
            action: "request".to_string(),
            arguments: arguments.clone(),
            actor_id: None,
            authz_id: None,
            approval_id: None,
        };
        let report = AnomalyReport::default();
        let anomaly = serde_json::to_value(report).expect("anomaly json");
        let outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::RequiresReview,
            &call,
            "behavior_anomaly",
            "review redacted arguments",
            Some(ErrorKind::ApprovalInvalid),
        );

        let payload = provider_outcome_payload(&outcome, Some(&arguments), Some(&anomaly));
        let preview = &payload["argument_preview"];

        assert_eq!(preview["provider"], "external.api.request");
        assert_eq!(preview["method"], "POST");
        for key in ["path", "to", "subject", "key"] {
            assert_eq!(preview[key]["redacted"], true, "unredacted PII key {key}");
            assert!(preview[key]["sha256"].is_string());
        }
        assert_eq!(preview["url"]["host"], "api.example.com");
        assert_eq!(preview["url"]["path"]["redacted"], true);
        for key in [
            "token",
            "password",
            "secret",
            "authorization",
            "cookie",
            "content",
            "body",
            "value",
            "custom",
        ] {
            assert_eq!(preview[key]["redacted"], true, "unredacted key {key}");
            assert!(preview[key]["sha256"].is_string(), "missing hash for {key}");
            assert!(preview[key]["bytes"].is_number(), "missing size for {key}");
        }
        assert_eq!(
            payload["trace_event"]["payload"]["argument_preview"],
            *preview
        );
        assert_eq!(payload["defense_layer"], "behavior-risk");
        assert_eq!(
            payload["trace_event"]["payload"]["defense_layer"],
            "behavior-risk"
        );
        let serialized = serde_json::to_string(&payload).expect("payload json");
        for secret in [
            "password@",
            "query-secret",
            "token-raw-secret",
            "password-raw-secret",
            "secret-raw-secret",
            "authorization-raw-secret",
            "cookie-raw-secret",
            "content-raw-secret",
            "body-raw-secret",
            "value-raw-secret",
            "unknown-raw-secret",
        ] {
            assert!(
                !serialized.contains(secret),
                "review event leaked raw secret {secret}"
            );
        }
    }

    #[test]
    fn inspect_source_sink_is_upgraded_before_effect_then_executes_once_after_approval() {
        let _guard = unit_test_env_lock().lock().expect("unit env lock");
        let root = unique_test_dir("dynamic-anomaly-flow");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        fs::write(sandbox.join("sensitive.txt"), "contest-secret").expect("sensitive fixture");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session = format!(
            "dynamic-flow-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        );

        let inspect = call_provider_for_session(
            1,
            &session,
            json!({
                "provider": "runwarden.input.inspect",
                "input_source": "user_prompt",
                "input_text": "Summarize the approved local fixture"
            }),
        );
        assert_eq!(inspect["result"]["isError"], false);
        assert_eq!(
            tool_payload(&inspect)["anomaly"]["recommended_action"],
            "allow"
        );

        let source_arguments = json!({
            "provider": "external.mcp.filesystem.read_file",
            "path": "sensitive.txt"
        });
        let source_review = call_provider_for_session(2, &session, source_arguments.clone());
        assert_eq!(source_review["result"]["isError"], true);
        let source_approval = tool_payload(&source_review)["approval_id"]
            .as_str()
            .expect("source approval id")
            .to_string();
        assert!(source_approval.starts_with("webui-"));
        approve_pending(&state_dir, &source_approval);
        let source_allowed = call_provider_for_session(3, &session, source_arguments);
        assert_eq!(source_allowed["result"]["isError"], false);
        assert_eq!(
            tool_payload(&source_allowed)["execution_status"],
            "completed"
        );

        let sink_arguments = json!({
            "provider": "external.email.send",
            "to": "ops@example.com",
            "subject": "Approved summary",
            "body": "contest-secret must never appear in review events"
        });
        let sink_review = call_provider_for_session(4, &session, sink_arguments.clone());
        assert_eq!(sink_review["result"]["isError"], true);
        let review_payload = tool_payload(&sink_review);
        assert_eq!(review_payload["decision"], "requires_review");
        assert_eq!(review_payload["envelope"]["gate_id"], "behavior_anomaly");
        assert_eq!(review_payload["defense_layer"], "behavior-risk");
        assert_eq!(
            review_payload["anomaly"]["recommended_action"],
            "require_review"
        );
        assert!(
            review_payload["anomaly"]["signals"]
                .as_array()
                .expect("anomaly signals")
                .iter()
                .any(|signal| signal["kind"] == "sensitive_source_to_sink")
        );
        assert_eq!(review_payload["argument_preview"]["body"]["redacted"], true);
        assert!(
            !serde_json::to_string(review_payload)
                .expect("review payload json")
                .contains("contest-secret must never appear"),
            "pending review event must not contain the raw body"
        );
        assert!(
            !sandbox.join("mailbox.mbox").exists(),
            "dynamic review must happen before the sink side effect"
        );

        let sink_approval = review_payload["approval_id"]
            .as_str()
            .expect("sink approval id")
            .to_string();
        assert!(sink_approval.starts_with("anomaly-"));
        approve_pending(&state_dir, &sink_approval);
        let sink_allowed = call_provider_for_session(5, &session, sink_arguments.clone());
        assert_eq!(sink_allowed["result"]["isError"], false);
        let allowed_payload = tool_payload(&sink_allowed);
        assert_eq!(allowed_payload["side_effect_executed"], true);
        assert_eq!(allowed_payload["approval_id"], sink_approval);
        assert_eq!(
            allowed_payload["trace_event"]["payload"]["completion_binding"]["execution_reservation_id"],
            allowed_payload["execution_reservation_id"]
        );
        assert_eq!(
            allowed_payload["trace_event"]["payload"]["completion_binding"]["anomaly"]["recommended_action"],
            "require_review"
        );
        assert_eq!(
            fs::read_to_string(sandbox.join("mailbox.mbox"))
                .expect("mailbox")
                .lines()
                .count(),
            1
        );
        let sink_call = provider_call_from_arguments_for_session(
            "external.email.send",
            &sink_arguments,
            &session,
        );
        assert_eq!(
            anomaly_histories()
                .lock()
                .expect("anomaly histories")
                .get(&anomaly_history_key(&sink_call))
                .expect("session history")
                .len(),
            3,
            "inspect, source, and sink must each be committed exactly once"
        );
        let consumed: ApprovalRecord = serde_json::from_slice(
            &fs::read(
                state_dir
                    .join("approvals")
                    .join(format!("{sink_approval}.json")),
            )
            .expect("dynamic approval record"),
        )
        .expect("dynamic approval json");
        assert_eq!(consumed.state, ApprovalState::Consumed);
        let reservation_path = fs::read_dir(state_dir.join("execution-reservations"))
            .expect("reservation directory")
            .map(|entry| entry.expect("reservation entry").path())
            .find(|path| fs::read_to_string(path).is_ok_and(|body| body.contains(&sink_approval)))
            .expect("sink reservation");
        let reservation: Value =
            serde_json::from_slice(&fs::read(&reservation_path).expect("final reservation record"))
                .expect("reservation json");
        assert_eq!(reservation["state"], "completed");
        assert_eq!(reservation["side_effect_executed"], true);
        assert_eq!(
            allowed_payload["reservation_digest"],
            hex_sha256(&canonical_json_bytes(&reservation))
        );
        assert_eq!(
            allowed_payload["trace_event"]["payload"]["completion_binding"]["reservation_state"],
            "completed"
        );

        let retry = call_provider_for_session(6, &session, sink_arguments);
        assert_eq!(retry["result"]["isError"], true);
        assert_eq!(tool_payload(&retry)["decision"], "requires_review");
        assert_eq!(
            fs::read_to_string(sandbox.join("mailbox.mbox"))
                .expect("mailbox")
                .lines()
                .count(),
            1,
            "consumed dynamic approval must not execute twice"
        );
        assert_eq!(
            anomaly_histories()
                .lock()
                .expect("anomaly histories")
                .get(&anomaly_history_key(&sink_call))
                .expect("session history")
                .len(),
            3,
            "blocked retries must not be committed to the behavior baseline"
        );

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn dynamic_approval_is_replaced_when_behavior_context_changes() {
        let _guard = unit_test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = unique_test_dir("dynamic-context-replacement");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        fs::write(sandbox.join("sensitive.txt"), "source-secret").expect("source fixture");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session = format!("context-replacement-{}", std::process::id());

        assert_eq!(
            call_provider_for_session(
                40,
                &session,
                json!({
                    "provider": "runwarden.input.inspect",
                    "input_source": "user_prompt",
                    "input_text": "inspect"
                })
            )["result"]["isError"],
            false
        );
        let source_arguments = json!({
            "provider": "external.mcp.filesystem.read_file",
            "path": "sensitive.txt"
        });
        let source_review = call_provider_for_session(41, &session, source_arguments.clone());
        let source_approval = tool_payload(&source_review)["approval_id"]
            .as_str()
            .expect("source approval");
        approve_pending(&state_dir, source_approval);
        assert_eq!(
            call_provider_for_session(42, &session, source_arguments)["result"]["isError"],
            false
        );

        let sink_arguments = json!({
            "provider": "external.email.send",
            "to": "ops@example.com",
            "subject": "context-bound review",
            "body": "source-secret"
        });
        let first_review = call_provider_for_session(43, &session, sink_arguments.clone());
        let first_approval = tool_payload(&first_review)["approval_id"]
            .as_str()
            .expect("first anomaly approval")
            .to_string();
        let first_challenge: DynamicAnomalyChallenge = serde_json::from_slice(
            &fs::read(
                state_dir
                    .join("anomaly-challenges")
                    .join(format!("{first_approval}.json")),
            )
            .expect("first anomaly challenge"),
        )
        .expect("challenge json");
        assert_eq!(first_challenge.kind, "dynamic_anomaly");
        assert_eq!(first_challenge.profile_version, ANOMALY_PROFILE_VERSION);
        assert_eq!(first_challenge.history_count, 3);
        approve_pending(&state_dir, &first_approval);

        // A new committed observation changes the bounded behavior context
        // after the reviewer made the decision.
        assert_eq!(
            call_provider_for_session(
                44,
                &session,
                json!({
                    "provider": "runwarden.input.inspect",
                    "input_source": "user_prompt",
                    "input_text": "new context"
                })
            )["result"]["isError"],
            false
        );
        let replacement = call_provider_for_session(45, &session, sink_arguments.clone());
        assert_eq!(replacement["result"]["isError"], true);
        let replacement_payload = tool_payload(&replacement);
        assert_eq!(replacement_payload["decision"], "requires_review");
        let replacement_approval = replacement_payload["approval_id"]
            .as_str()
            .expect("replacement approval")
            .to_string();
        assert_ne!(replacement_approval, first_approval);
        assert!(!sandbox.join("mailbox.mbox").exists());
        let replacement_challenge: DynamicAnomalyChallenge = serde_json::from_slice(
            &fs::read(
                state_dir
                    .join("anomaly-challenges")
                    .join(format!("{replacement_approval}.json")),
            )
            .expect("replacement challenge"),
        )
        .expect("replacement challenge json");
        assert_ne!(
            replacement_challenge.context_sha256,
            first_challenge.context_sha256
        );
        assert_eq!(replacement_challenge.history_count, 4);

        approve_pending(&state_dir, &replacement_approval);
        let allowed = call_provider_for_session(46, &session, sink_arguments);
        assert_eq!(allowed["result"]["isError"], false);
        assert_eq!(
            fs::read_to_string(sandbox.join("mailbox.mbox"))
                .expect("mailbox")
                .lines()
                .count(),
            1
        );

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn dynamic_approval_authority_comes_from_challenge_not_id_prefix() {
        let _guard = unit_test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = unique_test_dir("dynamic-challenge-authority");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let call = provider_call_from_arguments_for_session(
            "external.email.send",
            &json!({"provider": "external.email.send", "to": "ops@example.com"}),
            "challenge-authority-session",
        );
        let report = preview_anomaly_report(&call);
        let context = anomaly_context_for_call(&call, &report).expect("anomaly context");
        let now = time::OffsetDateTime::now_utc();
        let opaque_id = "opaque-review-authority";
        persist_dynamic_anomaly_challenge_mcp(opaque_id, "obs-opaque", &context, now)
            .expect("opaque challenge");
        let mut opaque = ApprovalRecord::new(opaque_id, approval_binding_for_mcp_call(&call));
        opaque
            .approve("reviewer", "approved context")
            .expect("approve");
        opaque.expires_at = Some(now + time::Duration::minutes(5));

        let mut attached_call = call.clone();
        assert_eq!(
            attach_matching_approval_mcp(&mut attached_call, &[opaque], Some(&context)),
            Some(AttachedApprovalKind::DynamicAnomaly)
        );
        assert_eq!(attached_call.approval_id.as_deref(), Some(opaque_id));

        let mut fake = ApprovalRecord::new(
            "anomaly-prefix-is-not-authority",
            approval_binding_for_mcp_call(&call),
        );
        fake.approve("reviewer", "no challenge")
            .expect("approve fake");
        let mut rejected_call = call;
        assert_eq!(
            attach_matching_approval_mcp(&mut rejected_call, &[fake], Some(&context)),
            None
        );
        assert!(rejected_call.approval_id.is_none());

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn raw_provider_output_is_returned_but_never_persisted_to_events() {
        let _guard = unit_test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = unique_test_dir("output-audit-redaction");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        fs::create_dir_all(&sandbox).expect("sandbox");
        let secret = "output-secret-only-for-the-caller-7f8a";
        fs::write(sandbox.join("secret.txt"), secret).expect("secret fixture");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session = "output-redaction-session";
        let arguments = json!({
            "provider": "external.mcp.filesystem.read_file",
            "path": "secret.txt"
        });
        let review = call_provider_for_session(50, session, arguments.clone());
        let approval = tool_payload(&review)["approval_id"]
            .as_str()
            .expect("read approval");
        approve_pending(&state_dir, approval);
        let response = call_provider_for_session(51, session, arguments);
        assert_eq!(response["result"]["isError"], false);
        let response_json = serde_json::to_string(&response).expect("response json");
        assert!(
            response_json.contains(secret),
            "caller must receive provider output"
        );
        let events = fs::read_to_string(state_dir.join("events.jsonl")).expect("events");
        assert!(
            !events.contains(secret),
            "audit log leaked raw provider output"
        );
        let last: Value =
            serde_json::from_str(events.lines().last().expect("last event")).expect("event json");
        assert_eq!(last["data"]["output"]["redacted"], true);
        assert_eq!(last["data"]["output"], last["data"]["output_digest"]);
        verify_provider_event_wrapper_binding(&last).expect("sealed redacted event");

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn anomaly_history_is_isolated_by_real_call_session() {
        let _guard = unit_test_env_lock().lock().expect("unit env lock");
        let root = unique_test_dir("anomaly-session-isolation");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session_a = format!("session-a-{}", std::process::id());
        let session_b = format!("session-b-{}", std::process::id());
        let inspect_arguments = json!({
            "provider": "runwarden.input.inspect",
            "input_text": "benign"
        });
        let inspect_a = provider_call_from_arguments_for_session(
            "runwarden.input.inspect",
            &inspect_arguments,
            &session_a,
        );
        let inspect_b = provider_call_from_arguments_for_session(
            "runwarden.input.inspect",
            &inspect_arguments,
            &session_b,
        );
        commit_anomaly_observation(&inspect_a);
        commit_anomaly_observation(&inspect_b);
        let source_arguments = json!({
            "provider": "external.mcp.filesystem.read_file",
            "path": "sensitive.txt"
        });
        let source_a = provider_call_from_arguments_for_session(
            "external.mcp.filesystem.read_file",
            &source_arguments,
            &session_a,
        );
        commit_anomaly_observation(&source_a);
        let sink_arguments = json!({
            "provider": "external.email.send",
            "to": "ops@example.com"
        });
        let sink_a = provider_call_from_arguments_for_session(
            "external.email.send",
            &sink_arguments,
            &session_a,
        );
        let sink_b = provider_call_from_arguments_for_session(
            "external.email.send",
            &sink_arguments,
            &session_b,
        );

        let report_a = preview_anomaly_report(&sink_a);
        let report_b = preview_anomaly_report(&sink_b);

        assert_eq!(
            report_a.recommended_action,
            RecommendedAction::RequireReview
        );
        assert!(report_a.signals.iter().any(|signal| {
            signal.kind == runwarden_anomaly::AnomalySignalKind::SensitiveSourceToSink
        }));
        assert_eq!(report_b.recommended_action, RecommendedAction::Allow);
        assert!(report_b.signals.is_empty());
        assert_eq!(report_a.history.len(), 3);
        assert_eq!(report_b.history.len(), 2);

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn anomaly_history_survives_in_memory_cache_loss_without_storing_arguments() {
        let _guard = unit_test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = unique_test_dir("anomaly-durable-history");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session = "durable-history-session";
        let inspect_arguments = json!({
            "provider": "runwarden.input.inspect",
            "input_text": "raw prompt must not enter behavior history"
        });
        let inspect = provider_call_from_arguments_for_session(
            "runwarden.input.inspect",
            &inspect_arguments,
            session,
        );
        commit_anomaly_observation(&inspect);
        let source_arguments = json!({
            "provider": "external.mcp.filesystem.read_file",
            "path": "private/customer-17.txt"
        });
        let source = provider_call_from_arguments_for_session(
            "external.mcp.filesystem.read_file",
            &source_arguments,
            session,
        );
        commit_anomaly_observation(&source);

        anomaly_histories()
            .lock()
            .expect("anomaly cache")
            .remove(&anomaly_history_key(&inspect));
        let sink = provider_call_from_arguments_for_session(
            "external.email.send",
            &json!({
                "provider": "external.email.send",
                "to": "customer@example.com"
            }),
            session,
        );
        let report = preview_anomaly_report(&sink);
        assert_eq!(report.recommended_action, RecommendedAction::RequireReview);
        assert!(report.signals.iter().any(|signal| {
            signal.kind == runwarden_anomaly::AnomalySignalKind::SensitiveSourceToSink
        }));
        assert_eq!(report.history.len(), 3);
        let stored =
            fs::read_to_string(anomaly_history_path_mcp(&sink)).expect("durable behavior history");
        for raw in [
            "raw prompt must not enter behavior history",
            "private/customer-17.txt",
            "customer@example.com",
        ] {
            assert!(
                !stored.contains(raw),
                "behavior history leaked raw argument {raw}"
            );
        }
        assert!(stored.contains("runwarden.input.inspect"));
        assert!(stored.contains("external.mcp.filesystem.read_file"));

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn critical_anomaly_recommendation_denies_before_reservation_or_execution() {
        let _guard = unit_test_env_lock().lock().expect("unit env lock");
        let root = unique_test_dir("critical-anomaly-denial");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session = format!("critical-session-{}", std::process::id());
        let inspect_arguments = json!({
            "provider": "runwarden.input.inspect",
            "input_text": "benign"
        });
        let inspect = provider_call_from_arguments_for_session(
            "runwarden.input.inspect",
            &inspect_arguments,
            &session,
        );
        commit_anomaly_observation(&inspect);
        let source_arguments = json!({
            "provider": "external.mcp.filesystem.read_file",
            "path": "sensitive.txt"
        });
        let source = provider_call_from_arguments_for_session(
            "external.mcp.filesystem.read_file",
            &source_arguments,
            &session,
        );
        commit_anomaly_observation(&source);

        let denied = call_provider_for_session(
            30,
            &session,
            json!({
                "provider": "external.api.request",
                "method": "POST",
                "url": "https://api.example.com/callback",
                "body": "x".repeat(5_000)
            }),
        );
        assert_eq!(denied["result"]["isError"], true);
        let payload = tool_payload(&denied);
        assert_eq!(payload["decision"], "denied");
        assert_eq!(payload["envelope"]["gate_id"], "behavior_anomaly");
        assert_eq!(payload["defense_layer"], "behavior-risk");
        assert_eq!(payload["anomaly"]["risk_level"], "critical");
        assert_eq!(payload["anomaly"]["recommended_action"], "deny");
        assert_eq!(payload["side_effect_executed"], false);
        assert!(
            !state_dir.join("execution-reservations").exists(),
            "critical anomaly must stop before reservation"
        );
        assert!(
            !state_dir.join("approvals").exists(),
            "critical anomaly is not reviewable"
        );

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn kernel_denied_intent_does_not_pollute_later_benign_baseline() {
        let _guard = unit_test_env_lock().lock().expect("unit env lock");
        let root = unique_test_dir("denied-history");
        let state_dir = root.join("state");
        let sandbox = root.join("sandbox");
        let env = ScopedMcpEnv::set(&state_dir, &sandbox);
        let session = format!("denied-session-{}", std::process::id());
        let inspect = call_provider_for_session(
            20,
            &session,
            json!({
                "provider": "runwarden.input.inspect",
                "input_text": "benign"
            }),
        );
        assert_eq!(inspect["result"]["isError"], false);
        let denied = call_provider_for_session(
            21,
            &session,
            json!({
                "provider": "external.api.request",
                "method": "GET",
                "url": "http://127.0.0.1/latest/meta-data"
            }),
        );
        assert_eq!(denied["result"]["isError"], true);
        assert_eq!(tool_payload(&denied)["decision"], "denied");
        assert!(tool_payload(&denied).get("anomaly").is_none());

        let benign_sink_arguments = json!({
            "provider": "external.email.send",
            "to": "ops@example.com"
        });
        let benign_sink = provider_call_from_arguments_for_session(
            "external.email.send",
            &benign_sink_arguments,
            &session,
        );
        let report = preview_anomaly_report(&benign_sink);
        assert_eq!(report.recommended_action, RecommendedAction::Allow);
        assert!(report.signals.is_empty());
        assert_eq!(
            report
                .history
                .iter()
                .map(|observation| observation.provider.as_str())
                .collect::<Vec<_>>(),
            vec!["runwarden.input.inspect", "external.email.send"]
        );

        drop(env);
        fs::remove_dir_all(root).expect("cleanup");
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
            &provider_outcome_payload(&first_outcome, None, None),
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
            &provider_outcome_payload(&second_outcome, None, None),
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
            verify_provider_event_wrapper_binding(&event).expect("wrapper binding");
            let trace: TraceEvent =
                serde_json::from_value(event["data"]["trace_event"].clone()).expect("trace event");
            store.append(trace);
        }
        store.verify_hash_chain().expect("provider trace verifies");

        let lines = content.lines().collect::<Vec<_>>();
        let mut first_event: Value = serde_json::from_str(lines[0]).expect("first event json");
        first_event["provider"] = json!("external.tampered.provider");
        let tampered = format!("{}\n{}\n", first_event, lines[1]);
        fs::write(&path, tampered).expect("write outer-wrapper tamper");
        let error = read_mcp_provider_trace_events_from_path(&path)
            .expect_err("outer wrapper tamper must be rejected");
        assert!(
            error
                .to_string()
                .contains("canonical provider event binding")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn durable_append_lock_refuses_ambiguous_cross_process_tail() {
        let dir = unique_test_dir("durable-append-lock");
        let path = dir.join("events.jsonl");
        let lock_path = dir.join(".events.jsonl.append.lock");
        fs::write(&lock_path, b"stale-or-active-lock\n").expect("lock fixture");
        let call = ProviderCall {
            session_id: "lock-test".to_string(),
            provider: "external.api.request".to_string(),
            action: "call".to_string(),
            arguments: json!({"url": "http://127.0.0.1"}),
            actor_id: None,
            authz_id: None,
            approval_id: None,
        };
        let outcome = ProviderOutcome::before_side_effect(
            PolicyDecision::Denied,
            &call,
            "egress",
            "lock test",
            Some(ErrorKind::EgressDenied),
        );
        let error = append_mcp_provider_event_to_path(
            &path,
            &outcome,
            &provider_outcome_payload(&outcome, None, None),
        )
        .expect_err("ambiguous durable lock must fail closed");
        assert!(
            error
                .to_string()
                .contains("manually removing the stale lock")
        );
        assert!(!path.exists(), "append must not race past durable lock");
        assert!(
            lock_path.exists(),
            "caller must explicitly resolve stale lock"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
