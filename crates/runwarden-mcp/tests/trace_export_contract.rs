use runwarden_kernel::evidence::TraceEvent;
use runwarden_mcp::handle_jsonrpc_body;
use serde_json::{Value, json};

fn trace_events() -> Vec<TraceEvent> {
    let first = TraceEvent::sealed(
        "obs_1".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.input.inspect".to_string()),
        json!({"decision":"allowed"}),
        None,
    );
    let second = TraceEvent::sealed(
        "obs_2".to_string(),
        "provider_denied".to_string(),
        Some("external.api.request".to_string()),
        json!({"decision":"denied"}),
        Some(first.event_hash.clone()),
    );
    let third = TraceEvent::sealed(
        "obs_3".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.report.lint".to_string()),
        json!({"decision":"allowed"}),
        Some(second.event_hash.clone()),
    );
    vec![first, second, third]
}

#[test]
fn trace_verify_tool_verifies_inline_hash_chain() {
    let response = call_tool(
        30,
        "runwarden.trace.verify",
        json!({ "trace_events": trace_events() }),
    );
    let payload = tool_payload(&response);

    assert_eq!(payload["verified"], true);
    assert_eq!(payload["event_count"], 3);
    assert_eq!(payload["side_effect_executed"], false);
}

#[test]
fn trace_export_tool_pages_filtered_verified_events() {
    let response = call_tool(
        31,
        "runwarden.trace.export",
        json!({
            "trace_events": trace_events(),
            "provider": "runwarden.report.lint",
            "limit": 10,
            "compact_refs": true
        }),
    );
    let payload = tool_payload(&response);

    assert_eq!(response["result"]["isError"], false);
    assert_eq!(payload["exported"], true);
    assert_eq!(payload["verified"], true);
    assert_eq!(payload["page"]["events"].as_array().unwrap().len(), 1);
    assert_eq!(payload["page"]["events"][0]["obs_id"], "obs_3");
    assert_eq!(payload["compact_refs"], json!(["obs_3"]));
    assert_eq!(payload["side_effect_executed"], false);
}

#[test]
fn trace_export_tool_denies_tampered_inline_trace_without_exporting() {
    let mut events = trace_events();
    events[1].payload = json!({"decision":"allowed_after_tamper"});

    let response = call_tool(
        32,
        "runwarden.trace.export",
        json!({ "trace_events": events }),
    );
    let payload = tool_payload(&response);

    assert_eq!(response["result"]["isError"], true);
    assert_eq!(payload["exported"], false);
    assert_eq!(payload["verified"], false);
    assert_eq!(payload["verification"]["error"]["kind"], "trace_tampered");
    assert_eq!(payload["side_effect_executed"], false);
}

fn call_tool(id: u64, name: &str, arguments: Value) -> Value {
    handle_jsonrpc_body(
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        })
        .to_string(),
    )
    .expect("tools/call")
}

fn tool_payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text");
    serde_json::from_str(text).expect("tool payload")
}
