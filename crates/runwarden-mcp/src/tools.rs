use std::path::PathBuf;

use anyhow::Context as _;
use runwarden_assurance::report::{ReportDraft, lint_report_against_trace};
use runwarden_kernel::ErrorKind;
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery};
use runwarden_kernel::kernel::provider_requires_approval;
use runwarden_kernel::story::OperationId;
use runwarden_providers::catalog::{
    canonical_runtime_provider_action, default_external_providers, default_first_party_providers,
};
use runwarden_runtime::{McpRuntime, RuntimeError};
use serde_json::{Value, json};

use crate::approval_wait::{response_is_error, response_payload};
use crate::provider_call::{
    PROVIDER_CALL_ALLOWED_ARGUMENT_KEYS, ProviderCallError, invoke_provider,
};
use crate::server::{InvocationKeyDeriver, JsonRpcRequestId, jsonrpc_error, jsonrpc_ok};

const RUNWARDEN_TOOLS: &[(&str, &str)] = &[
    (
        "runwarden.agent.bootstrap",
        "Return the agent-facing Runwarden-only security boundary.",
    ),
    (
        "runwarden.provider.call",
        "Submit typed provider arguments to the durable Runwarden runtime.",
    ),
    (
        "runwarden.provider.list",
        "Return kernel-managed providers available to the active session.",
    ),
    (
        "runwarden.provider.status",
        "Return provider availability, risk, effects, and approval requirements.",
    ),
    (
        "runwarden.operation.status",
        "Return the display-safe durable state for one operation.",
    ),
    (
        "runwarden.operation.resume",
        "Resume one durable approved or leased operation by id only.",
    ),
    (
        "runwarden.trace.verify",
        "Verify an inline Runwarden trace hash chain.",
    ),
    (
        "runwarden.trace.export",
        "Page an already verified inline trace without writing files.",
    ),
    (
        "runwarden.report.lint",
        "Lint report claims against server-owned compatibility evidence.",
    ),
    (
        "runwarden.report.render",
        "Report that rendering requires the reviewer-controlled artifact route.",
    ),
];

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
    "instance_token",
    "execution_permit",
    "lease_id",
    "env",
    "environment",
    "cwd",
    "transport",
];

pub(crate) fn tool_descriptors() -> Vec<Value> {
    RUNWARDEN_TOOLS
        .iter()
        .map(|(name, description)| {
            json!({
                "name": name,
                "description": description,
                "inputSchema": tool_input_schema(name),
                "outputSchema": {"type": "object", "additionalProperties": true}
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
            "properties": {
                "provider": {"type": "string"},
                "input_text": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string"},
                "body": {},
                "path": {"type": "string"},
                "content": {"type": "string"},
                "to": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "subject": {"type": "string"},
                "key": {"type": "string"},
                "value": {}
            }
        }),
        "runwarden.provider.list" => exact_object(&[], json!({})),
        "runwarden.provider.status" => {
            exact_object(&["provider"], json!({"provider": {"type": "string"}}))
        }
        "runwarden.operation.status" | "runwarden.operation.resume" => exact_object(
            &["operation_id"],
            json!({"operation_id": {"type": "string"}}),
        ),
        "runwarden.trace.verify" => exact_object(
            &["trace_events"],
            json!({"trace_events": {"type": "array"}}),
        ),
        "runwarden.trace.export" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["trace_events"],
            "properties": {
                "trace_events": {"type": "array"},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1},
                "provider": {"type": "string"},
                "event_type": {"type": "string"},
                "obs_prefix": {"type": "string"},
                "max_bytes": {"type": "integer", "minimum": 1},
                "compact_refs": {"type": "boolean"}
            }
        }),
        "runwarden.report.lint" | "runwarden.report.render" => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["report"],
            "properties": {
                "report": {"type": "object"},
                "format": {"type": "string"}
            }
        }),
        _ => exact_object(&[], json!({})),
    }
}

fn exact_object(required: &[&str], properties: Value) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    })
}

pub(crate) fn handle_tools_call<R: McpRuntime>(
    runtime: &R,
    invocation_keys: &InvocationKeyDeriver,
    request_id: &JsonRpcRequestId,
    id: Value,
    params: Option<&Value>,
) -> Value {
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
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    if let Err(message) = validate_no_policy_envelope_arguments(arguments, tool_name) {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }

    match tool_name {
        "runwarden.agent.bootstrap" => tool_result(
            id,
            json!({
                "architecture": "durable_agent_security_kernel",
                "agent_only_sees_runwarden": true,
                "raw_side_effect_tools_allowed": false,
                "approval_is_one_shot": true,
                "operation_resume_requires_only_id": true
            }),
        ),
        "runwarden.provider.call" => {
            handle_provider_call(runtime, invocation_keys, request_id, id, arguments)
        }
        "runwarden.operation.status" => handle_operation(runtime, id, arguments, false),
        "runwarden.operation.resume" => handle_operation(runtime, id, arguments, true),
        "runwarden.provider.list" => handle_provider_list(id, arguments),
        "runwarden.provider.status" => handle_provider_status(id, arguments),
        "runwarden.trace.verify" => handle_trace_verify(id, arguments),
        "runwarden.trace.export" => handle_trace_export(id, arguments),
        "runwarden.report.lint" => handle_report_lint(id, arguments),
        "runwarden.report.render" => tool_error_result(
            id,
            json!({
                "error_kind": "reviewer_artifact_route_required",
                "reason_code": "agent_render_disabled",
                "side_effect_executed": false
            }),
        ),
        _ => jsonrpc_error(
            id,
            -32602,
            "tool is not exposed by Runwarden MCP boundary",
            json!({"tool": tool_name, "side_effect_executed": false}),
        ),
    }
}

fn handle_provider_call<R: McpRuntime>(
    runtime: &R,
    invocation_keys: &InvocationKeyDeriver,
    request_id: &JsonRpcRequestId,
    id: Value,
    arguments: &Value,
) -> Value {
    match invoke_provider(runtime, invocation_keys, request_id, arguments) {
        Ok(response) => runtime_response_result(id, response_payload(response)),
        Err(ProviderCallError::Runtime(error)) => runtime_error_result(id, error),
        Err(ProviderCallError::UnsupportedProvider) => tool_error_result(
            id,
            json!({
                "error_kind": ErrorKind::ProviderUnknown,
                "reason_code": "provider_not_on_durable_call_surface",
                "side_effect_executed": false
            }),
        ),
        Err(error) => jsonrpc_error(
            id,
            -32602,
            &error.to_string(),
            json!({"side_effect_executed": false}),
        ),
    }
}

fn handle_operation<R: McpRuntime>(
    runtime: &R,
    id: Value,
    arguments: &Value,
    resume: bool,
) -> Value {
    if let Err(message) = validate_argument_object(
        arguments,
        &["operation_id"],
        if resume {
            "operation resume"
        } else {
            "operation status"
        },
    ) {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
    let Some(raw_operation_id) = arguments.get("operation_id").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            -32602,
            "operation_id is required",
            json!({"side_effect_executed": false}),
        );
    };
    let operation_id: OperationId =
        match serde_json::from_value(Value::String(raw_operation_id.to_owned())) {
            Ok(operation_id) => operation_id,
            Err(_) => {
                return jsonrpc_error(
                    id,
                    -32602,
                    "operation_id is not canonical",
                    json!({"side_effect_executed": false}),
                );
            }
        };
    let result = if resume {
        runtime.resume(operation_id)
    } else {
        runtime.operation_status(operation_id)
    };
    match result {
        Ok(response) => runtime_response_result(id, response_payload(response)),
        Err(error) => runtime_error_result(id, error),
    }
}

fn runtime_response_result(id: Value, payload: Value) -> Value {
    if response_is_error(&payload) {
        tool_error_result(id, payload)
    } else {
        tool_result(id, payload)
    }
}

fn runtime_error_result(id: Value, error: RuntimeError) -> Value {
    let (error_kind, operation_id, side_effect_executed) = match &error {
        RuntimeError::ContextUnavailable(_) => ("context_unavailable", None, Some(false)),
        RuntimeError::ProviderUnknown(_) => ("provider_unknown", None, Some(false)),
        RuntimeError::ResourceInvalid(_) => ("resource_invalid", None, Some(false)),
        RuntimeError::JournalBeforeExecution(_) => ("journal_before_execution", None, Some(false)),
        RuntimeError::JournalAfterExecution { operation_id, .. } => {
            ("journal_after_execution", Some(*operation_id), None)
        }
        RuntimeError::CleanupAfterCommit { operation_id, .. } => {
            ("cleanup_after_commit", Some(*operation_id), Some(true))
        }
        RuntimeError::JournalAndCleanupAfterExecution { operation_id, .. } => (
            "journal_and_cleanup_after_execution",
            Some(*operation_id),
            None,
        ),
        RuntimeError::ApprovalDenied { operation_id, .. } => {
            ("approval_denied", Some(*operation_id), Some(false))
        }
        RuntimeError::ApprovalExpired { operation_id } => {
            ("approval_expired", Some(*operation_id), Some(false))
        }
        RuntimeError::OperationConflict { operation_id } => {
            ("operation_conflict", Some(*operation_id), Some(false))
        }
        RuntimeError::OperationNotResumable { operation_id, .. } => {
            ("operation_not_resumable", Some(*operation_id), Some(false))
        }
    };
    tool_error_result(
        id,
        json!({
            "error_kind": error_kind,
            "operation_id": operation_id,
            "reason_code": error_kind,
            "side_effect_executed": side_effect_executed
        }),
    )
}

fn handle_provider_list(id: Value, arguments: &Value) -> Value {
    if let Err(message) = validate_argument_object(arguments, &[], "provider list") {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
    tool_result(
        id,
        json!({
            "providers": all_kernel_managed_providers(),
            "side_effect_executed": false
        }),
    )
}

fn handle_provider_status(id: Value, arguments: &Value) -> Value {
    if let Err(message) = validate_argument_object(arguments, &["provider"], "provider status") {
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
    let Some(provider) = all_kernel_managed_providers()
        .into_iter()
        .find(|provider| provider.id == provider_id)
    else {
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
    let action = canonical_runtime_provider_action(&provider.id);
    let durable_call_available = action.is_some();
    tool_result(
        id,
        json!({
            "provider": provider.id,
            "available": durable_call_available,
            "availability_scope": "durable_provider_call",
            "durable_call_action": action,
            "unavailable_reason": (!durable_call_available)
                .then_some("not_on_durable_provider_call_surface"),
            "kind": provider.kind,
            "risk": provider.risk,
            "side_effects": provider.side_effects,
            "approval_required": provider_requires_approval(&provider),
            "side_effect_executed": false
        }),
    )
}

fn all_kernel_managed_providers() -> Vec<runwarden_kernel::KernelProvider> {
    default_first_party_providers()
        .into_iter()
        .chain(default_external_providers())
        .collect()
}

fn handle_trace_verify(id: Value, arguments: &Value) -> Value {
    if let Err(message) = validate_argument_object(arguments, &["trace_events"], "trace verify") {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
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
    let allowed = [
        "trace_events",
        "offset",
        "limit",
        "provider",
        "event_type",
        "obs_prefix",
        "max_bytes",
        "compact_refs",
    ];
    if let Err(message) = validate_argument_object(arguments, &allowed, "trace export") {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
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
    let mut store = InMemoryTraceStore::default();
    for event in trace_events {
        store.append(event);
    }
    let page = store.query(trace_query_from_args(arguments));
    let refs = page
        .events
        .iter()
        .map(|event| event.obs_id.clone())
        .collect::<Vec<_>>();
    let compact_refs = arguments
        .get("compact_refs")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    tool_result(
        id,
        json!({
            "exported": true,
            "verified": true,
            "page": page,
            "compact_refs": compact_refs.then_some(refs),
            "side_effect_executed": false
        }),
    )
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

fn verify_inline_trace(trace_events: &[TraceEvent]) -> Value {
    let mut store = InMemoryTraceStore::default();
    for event in trace_events {
        store.append(event.clone());
    }
    match store.verify_hash_chain() {
        Ok(()) => json!({"verified": true, "event_count": trace_events.len()}),
        Err(error) => json!({
            "verified": false,
            "event_count": trace_events.len(),
            "error": {
                "kind": "trace_tampered",
                "offset": error.offset,
                "obs_id": error.obs_id,
                "message": error.reason
            }
        }),
    }
}

fn trace_query_from_args(arguments: &Value) -> TraceQuery {
    TraceQuery {
        offset: arguments
            .get("offset")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        limit: arguments
            .get("limit")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(100),
        provider: arguments
            .get("provider")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        event_type: arguments
            .get("event_type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        obs_prefix: arguments
            .get("obs_prefix")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        max_bytes: arguments
            .get("max_bytes")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok()),
    }
}

fn handle_report_lint(id: Value, arguments: &Value) -> Value {
    if let Err(message) = validate_argument_object(arguments, &["report"], "report lint") {
        return jsonrpc_error(id, -32602, &message, json!({"side_effect_executed": false}));
    }
    let Some(report) = arguments
        .get("report")
        .cloned()
        .and_then(|report| serde_json::from_value::<ReportDraft>(report).ok())
    else {
        return jsonrpc_error(
            id,
            -32602,
            "report lint requires a valid arguments.report",
            json!({"side_effect_executed": false}),
        );
    };
    let trace_events = match read_legacy_provider_trace_events() {
        Ok(events) => events,
        Err(_) => {
            return tool_error_result(
                id,
                json!({
                    "ok": false,
                    "errors": [{"kind": "trace_store_unreadable"}],
                    "trace_source": "legacy_read_only",
                    "side_effect_executed": false
                }),
            );
        }
    };
    let result = lint_report_against_trace(&report, &trace_events);
    let payload = json!({
        "ok": result.ok,
        "errors": result.errors,
        "trace_source": "legacy_read_only",
        "trace_event_count": trace_events.len(),
        "side_effect_executed": false
    });
    if result.ok {
        tool_result(id, payload)
    } else {
        tool_error_result(id, payload)
    }
}

fn read_legacy_provider_trace_events() -> anyhow::Result<Vec<TraceEvent>> {
    let state_dir = std::env::var_os("RUNWARDEN_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".runwarden"));
    let path = state_dir.join("events.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("read legacy MCP evidence from {}", path.display()))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            let event: Value = serde_json::from_str(line)
                .with_context(|| format!("parse legacy event line {}", index + 1))?;
            let trace_event = event
                .get("data")
                .and_then(|data| data.get("trace_event"))
                .cloned()
                .context("legacy event is missing data.trace_event")?;
            serde_json::from_value(trace_event).context("decode legacy trace event")
        })
        .collect()
}

fn validate_no_policy_envelope_arguments(arguments: &Value, label: &str) -> Result<(), String> {
    let Some(object) = arguments.as_object() else {
        return Ok(());
    };
    if let Some(key) = object
        .keys()
        .find(|key| POLICY_ENVELOPE_ARGUMENT_KEYS.contains(&key.as_str()))
    {
        return Err(format!("{label} argument is not allowed: {key}"));
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
    if let Some(key) = object
        .keys()
        .find(|key| !allowed_keys.contains(&key.as_str()))
    {
        return Err(format!("{label} argument is not allowed: {key}"));
    }
    Ok(())
}

fn tool_result(id: Value, payload: Value) -> Value {
    jsonrpc_ok(
        id,
        json!({
            "structuredContent": payload,
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&payload).expect("tool payload serializes")
            }],
            "isError": false
        }),
    )
}

fn tool_error_result(id: Value, payload: Value) -> Value {
    jsonrpc_ok(
        id,
        json!({
            "structuredContent": payload,
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&payload).expect("tool payload serializes")
            }],
            "isError": true
        }),
    )
}

const _: &[&str] = PROVIDER_CALL_ALLOWED_ARGUMENT_KEYS;
