use anyhow::{Context, bail};
use runwarden_assurance::accountability::accountability_summary;
use runwarden_assurance::audit::audit_summary;
use runwarden_assurance::eval::{
    AgentNativeConfigCase, AgentNativeExpectation, evaluate_agent_native_configs,
};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report,
};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery};
use runwarden_kernel::kernel::{KernelEnforcer, KernelPolicy, ProviderRegistry};
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_kernel::{ErrorKind, KernelProvider, PolicyDecision, ProviderCall, ProviderOutcome};
use runwarden_providers::catalog::default_first_party_providers;
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use serde_json::{Value, json};

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
        "runwarden.session.create_from_manifest",
        "Create a session manifest from an assessment manifest without side effects.",
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

pub fn handle_stdio_payload(payload: &str) -> anyhow::Result<String> {
    let body = decode_stdio_body(payload)?;
    let response = handle_jsonrpc_body(body)?;
    let response_body = serde_json::to_string(&response).context("serialize JSON-RPC response")?;

    Ok(format!(
        "Content-Length: {}\r\n\r\n{}",
        response_body.len(),
        response_body
    ))
}

pub fn handle_jsonrpc_body(body: &str) -> anyhow::Result<Value> {
    let request: Value = serde_json::from_str(body).context("parse JSON-RPC request")?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Ok(jsonrpc_error(
            id,
            -32600,
            "JSON-RPC request is missing method",
            json!({"side_effect_executed": false}),
        ));
    };

    match method {
        "initialize" => Ok(jsonrpc_ok(
            id,
            json!({
                "protocolVersion": "2025-03-26",
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
        )),
        "tools/list" => Ok(jsonrpc_ok(id, json!({ "tools": tool_descriptors() }))),
        "tools/call" => Ok(handle_tools_call(id, request.get("params"))),
        _ => Ok(jsonrpc_error(
            id,
            -32601,
            "method is not supported by Runwarden MCP",
            json!({"method": method, "side_effect_executed": false}),
        )),
    }
}

fn decode_stdio_body(payload: &str) -> anyhow::Result<&str> {
    if !payload.starts_with("Content-Length:") {
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
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": true
                },
                "outputSchema": {
                    "type": "object",
                    "additionalProperties": true
                }
            })
        })
        .collect()
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
        "runwarden.session.create_from_manifest" => handle_session_create_from_manifest(id, params),
        "runwarden.trace.verify" => handle_trace_verify(id, params),
        "runwarden.trace.export" => handle_trace_export(id, params),
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
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let Some(provider) = arguments.get("provider").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            -32602,
            "provider call requires arguments.provider",
            json!({"side_effect_executed": false}),
        );
    };

    let call = provider_call_from_arguments(provider, arguments);
    let mut enforcer = KernelEnforcer::new(
        first_party_provider_registry(),
        kernel_policy_from_arguments(provider, arguments),
    );
    let outcome = enforcer.evaluate_call(&call);
    if outcome.decision != PolicyDecision::Allowed {
        return tool_error_result(id, provider_outcome_payload(&outcome));
    }

    match provider {
        "runwarden.input.inspect" => {
            let input_text = arguments
                .get("input_text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let inspection = inspect_input(
                InputSource::ToolInput,
                input_text.as_bytes(),
                InputInspectPolicy::default(),
            );
            tool_result(
                id,
                json!({
                    "provider": provider,
                    "decision": "allowed",
                    "execution_status": "completed",
                    "side_effect_executed": false,
                    "output": inspection
                }),
            )
        }
        "runwarden.audit.summary" => {
            let trace_events = inline_trace_events(arguments);
            tool_result(
                id,
                json!({
                    "provider": provider,
                    "decision": "allowed",
                    "execution_status": "completed",
                    "side_effect_executed": false,
                    "output": audit_summary(&trace_events)
                }),
            )
        }
        "runwarden.accountability.summary" => {
            let trace_events = inline_trace_events(arguments);
            tool_result(
                id,
                json!({
                    "provider": provider,
                    "decision": "allowed",
                    "execution_status": "completed",
                    "side_effect_executed": false,
                    "output": accountability_summary(&trace_events)
                }),
            )
        }
        "runwarden.eval.agent-native" => {
            let cases = inline_agent_native_cases(arguments);
            let result = evaluate_agent_native_configs(&cases);
            tool_result(
                id,
                json!({
                    "provider": provider,
                    "decision": if result.passed { "allowed" } else { "denied" },
                    "execution_status": "completed",
                    "side_effect_executed": false,
                    "output": result
                }),
            )
        }
        other => tool_error_result(
            id,
            json!({
                "error_kind": ErrorKind::ProviderUnknown,
                "message": "provider is not implemented by the MCP inline call path",
                "provider": other,
                "side_effect_executed": false
            }),
        ),
    }
}

fn provider_call_from_arguments(provider: &str, arguments: &Value) -> ProviderCall {
    ProviderCall {
        session_id: arguments
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("mcp-inline")
            .to_string(),
        provider: provider.to_string(),
        action: arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("call")
            .to_string(),
        arguments: arguments.clone(),
        actor_id: arguments
            .get("actor_id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        authz_id: arguments
            .get("authz_id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        approval_id: arguments
            .get("approval_id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    }
}

fn first_party_provider_registry() -> ProviderRegistry {
    let mut registry = ProviderRegistry::default();
    for provider in default_first_party_providers() {
        registry.register(provider);
    }
    registry
}

fn kernel_policy_from_arguments(provider: &str, arguments: &Value) -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.active_assessment = arguments
        .get("active_assessment")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    if let Some(allowed) = arguments.get("session_allowed_providers") {
        for provider_id in allowed
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            policy.allow_provider(provider_id);
        }
    } else {
        policy.allow_provider(provider);
    }

    policy
}

fn provider_outcome_payload(outcome: &ProviderOutcome) -> Value {
    let mut payload = serde_json::to_value(outcome).expect("provider outcome serializes");
    payload["provider"] = json!(&outcome.envelope.provider);
    payload["action"] = json!(&outcome.envelope.action);
    payload["error_kind"] = json!(&outcome.envelope.error_kind);
    payload["reason"] = json!(&outcome.envelope.reason);
    payload["side_effect_executed"] = json!(outcome.envelope.side_effect_executed);
    payload
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

fn handle_trace_verify(id: Value, params: Option<&Value>) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
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

fn handle_trace_export(id: Value, params: Option<&Value>) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
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

fn inline_agent_native_cases(arguments: &Value) -> Vec<AgentNativeConfigCase> {
    arguments
        .get("agent_configs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|case| {
            let id = case.get("id").and_then(Value::as_str)?.to_string();
            let config = case.get("config")?.clone();
            let expectation = match case.get("expectation").and_then(Value::as_str) {
                Some("raw_tools_denied") => AgentNativeExpectation::RawToolsDenied,
                _ => AgentNativeExpectation::RunwardenOnlyAllowed,
            };
            Some(AgentNativeConfigCase {
                id,
                config,
                expectation,
            })
        })
        .collect()
}

fn handle_provider_list(id: Value, params: Option<&Value>) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let allowed: Vec<_> = arguments
        .get("session_allowed_providers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();

    let providers: Vec<_> = default_first_party_providers()
        .into_iter()
        .filter(|provider| allowed.is_empty() || allowed.contains(&provider.id.as_str()))
        .collect();

    tool_result(
        id,
        json!({
            "providers": providers,
            "side_effect_executed": false
        }),
    )
}

fn handle_provider_status(id: Value, params: Option<&Value>) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let Some(provider_id) = arguments.get("provider").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            -32602,
            "provider status requires arguments.provider",
            json!({"side_effect_executed": false}),
        );
    };

    let Some(provider) = find_first_party_provider(provider_id) else {
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
            "approval_required": approval_required(&provider),
            "side_effect_executed": false
        }),
    )
}

fn handle_session_create_from_manifest(id: Value, params: Option<&Value>) -> Value {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let session_id = arguments
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let Some(manifest_toml) = arguments.get("manifest_toml").and_then(Value::as_str) else {
        return jsonrpc_error(
            id,
            -32602,
            "session creation requires arguments.manifest_toml",
            json!({"side_effect_executed": false}),
        );
    };

    let assessment = match AssessmentManifest::from_toml_str(manifest_toml) {
        Ok(assessment) => assessment,
        Err(err) => {
            return tool_error_result(
                id,
                json!({
                    "error_kind": ErrorKind::ManifestInvalid,
                    "message": err.to_string(),
                    "side_effect_executed": false
                }),
            );
        }
    };
    let session = SessionManifest::from_assessment(session_id, &assessment);

    tool_result(
        id,
        json!({
            "session": session,
            "side_effect_executed": false
        }),
    )
}

fn handle_report_lint(id: Value, params: Option<&Value>) -> Value {
    let Some((report, trace_events)) = report_and_trace_args(id.clone(), params) else {
        return jsonrpc_error(
            id,
            -32602,
            "report lint requires arguments.report and arguments.trace_events",
            json!({"side_effect_executed": false}),
        );
    };

    let result = lint_report_against_trace(&report, &trace_events);
    let payload = json!({
        "ok": result.ok,
        "errors": result.errors,
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
    let Some((report, trace_events)) = report_and_trace_args(id.clone(), params) else {
        return jsonrpc_error(
            id,
            -32602,
            "report render requires arguments.report and arguments.trace_events",
            json!({"side_effect_executed": false}),
        );
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

fn report_and_trace_args(
    _id: Value,
    params: Option<&Value>,
) -> Option<(ReportDraft, Vec<TraceEvent>)> {
    let arguments = params
        .and_then(|params| params.get("arguments"))
        .unwrap_or(&Value::Null);
    let report = serde_json::from_value(arguments.get("report")?.clone()).ok()?;
    let trace_events = serde_json::from_value(
        arguments
            .get("trace_events")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .ok()?;
    Some((report, trace_events))
}

fn find_first_party_provider(provider_id: &str) -> Option<KernelProvider> {
    default_first_party_providers()
        .into_iter()
        .find(|provider| provider.id == provider_id)
}

fn approval_required(provider: &KernelProvider) -> bool {
    provider
        .authority_requirements
        .get("approval_required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
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
