use std::{
    convert::Infallible,
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::State,
    response::{
        Html, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use runwarden_cli::web_server::{reviewer_router, reviewer_state_for_listener};
use runwarden_kernel::{
    authority::{ApprovalRecord, ApprovalState},
    evidence::{InMemoryTraceStore, TraceEvent},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio_stream::{StreamExt, wrappers::BroadcastStream};

const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
pub struct AppState {
    pub event_tx: broadcast::Sender<DemoEvent>,
    pub state_dir: PathBuf,
    pub trace_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DemoEvent {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obs_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side_effect_executed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defense_layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<String>,
    pub data: Value,
}

pub fn defense_layer_for(
    provider: Option<&str>,
    decision: Option<&str>,
    error_kind: Option<&str>,
) -> &'static str {
    match error_kind {
        Some("root_escape" | "scope_violation") => "scoped-root",
        Some("egress_denied") => "egress",
        Some("approval_invalid" | "approval_expired" | "approval_consumed") => "approval",
        Some("provider_not_allowed" | "provider_unknown") => "provider-policy",
        Some("budget_exceeded") => "budget",
        _ if decision == Some("requires_review") => "approval",
        _ if provider.is_some_and(|provider| provider == "runwarden.input.inspect") => {
            "input-inspection"
        }
        _ if provider.is_some_and(|provider| provider.starts_with("runwarden.report.")) => {
            "report-evidence"
        }
        _ if provider.is_some_and(|provider| provider.starts_with("runwarden.trace.")) => {
            "trace-verification"
        }
        _ => "kernel-policy",
    }
}

pub fn run_console_server(
    bind: &str,
    port: u16,
    state: AppState,
    json_output: bool,
) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let bind_ip: IpAddr = bind.parse().context("reviewer bind must be an IP address")?;
        anyhow::ensure!(
            bind_ip.is_loopback(),
            "reviewer server must bind a loopback address"
        );
        let listener = tokio::net::TcpListener::bind((bind_ip, port)).await?;
        let addr = listener.local_addr()?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "mode": "interactive_demo",
                    "listen_addr": addr.to_string(),
                    "url": format!("http://{addr}"),
                    "events_url": format!("http://{addr}/events"),
                    "side_effect_executed": false
                }))?
            );
        } else {
            println!("Runwarden demo server running.");
            println!();
            println!("  Console:   http://{addr}");
            println!("  LLM proxy: http://127.0.0.1:8787/v1");
            println!();
            println!("In another terminal:");
            println!("  export PATH=\"$PWD/target/debug:$PATH\"");
            println!("  export RUNWARDEN_LLM_API_KEY=dummy");
            println!("  export RUNWARDEN_STATE_DIR=\"$PWD/.runwarden\"");
            println!("  export XDG_CONFIG_HOME=/tmp/oc-runwarden/xdg/config");
            println!("  export XDG_DATA_HOME=/tmp/oc-runwarden/xdg/data");
            println!("  export XDG_CACHE_HOME=/tmp/oc-runwarden/xdg/cache");
            println!("  export XDG_STATE_HOME=/tmp/oc-runwarden/xdg/state");
            println!("  mkdir -p /tmp/oc-runwarden \"$XDG_CONFIG_HOME/opencode\"");
            println!(
                "  cp examples/agent-configs/opencode.runwarden-only.json \"$XDG_CONFIG_HOME/opencode/opencode.json\""
            );
            println!("  cd /tmp/oc-runwarden");
            println!("  opencode run \"send an email to test@example.com\" -m opencode/big-pickle --print-logs");
            println!();
            println!("Press Ctrl+C to stop.");
        }
        std::io::stdout().flush().ok();

        let reviewer_state = reviewer_state_for_listener(&state.state_dir, addr)?;
        let reviewer_routes = reviewer_router(reviewer_state);
        let legacy_routes = Router::new()
            .route("/", get(|| async { Html(CONSOLE_HTML) }))
            .route("/events", get(sse_handler))
            .route("/api/approve", post(approve_handler))
            .route("/api/deny", post(deny_handler))
            .route("/api/pending", get(pending_handler))
            .route("/api/trace/verify", get(trace_verify_handler))
            .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
            .with_state(state);
        let app = legacy_routes.merge(reviewer_routes);
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.event_tx.subscribe()).filter_map(|result| {
        result.ok().and_then(|event| {
            Event::default()
                .event(event.kind.clone())
                .json_data(event)
                .ok()
                .map(Ok)
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Debug, Deserialize)]
struct ApprovalBody {
    approval_id: String,
}

async fn approve_handler(
    State(state): State<AppState>,
    Json(body): Json<ApprovalBody>,
) -> Json<Value> {
    update_approval(&state, &body.approval_id, true)
}

async fn deny_handler(
    State(state): State<AppState>,
    Json(body): Json<ApprovalBody>,
) -> Json<Value> {
    update_approval(&state, &body.approval_id, false)
}

async fn pending_handler(State(state): State<AppState>) -> Json<Value> {
    let approvals = read_all_approvals(&state.state_dir).unwrap_or_default();
    let pending: Vec<_> = approvals
        .into_iter()
        .filter(|approval| approval.state == ApprovalState::Pending)
        .collect();
    Json(json!({ "pending": pending, "side_effect_executed": false }))
}

async fn trace_verify_handler(State(state): State<AppState>) -> Json<Value> {
    // Verify LLM proxy trace (model_call events)
    let model_result = match read_trace(&state.trace_path) {
        Ok(events) => verify_trace_events(events),
        Err(_) => json!({ "verified": false, "error": "trace file not found", "event_count": 0 }),
    };

    let mcp_result = provider_trace_verify_result(&state.state_dir.join("events.jsonl"));

    Json(json!({
        "model_trace": model_result,
        "provider_trace": mcp_result,
        "verified": model_result["verified"].as_bool().unwrap_or(false)
            || mcp_result["verified"].as_bool().unwrap_or(false),
        "side_effect_executed": false
    }))
}

fn read_provider_trace_events(path: &Path) -> anyhow::Result<Vec<TraceEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("read provider events from {}", path.display()))?;
    let mut trace_events = Vec::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(line)
            .with_context(|| format!("parse event line {}", index + 1))?;
        let trace_event = event
            .get("data")
            .and_then(|data| data.get("trace_event"))
            .cloned()
            .with_context(|| format!("event line {} is missing data.trace_event", index + 1))?;
        trace_events.push(
            serde_json::from_value(trace_event)
                .with_context(|| format!("parse trace_event on event line {}", index + 1))?,
        );
    }
    Ok(trace_events)
}

fn provider_trace_verify_result(path: &Path) -> Value {
    match read_provider_trace_events(path) {
        Ok(events) if events.is_empty() => {
            json!({ "verified": false, "error": "no provider trace events", "event_count": 0 })
        }
        Ok(events) => verify_trace_events(events),
        Err(err) => json!({ "verified": false, "error": err.to_string(), "event_count": 0 }),
    }
}

fn update_approval(state: &AppState, approval_id: &str, approve: bool) -> Json<Value> {
    let result = (|| -> anyhow::Result<ApprovalRecord> {
        let path = approval_path(&state.state_dir, approval_id)?;
        let body = fs::read_to_string(&path)?;
        let mut approval = serde_json::from_str::<ApprovalRecord>(&body)?;
        if approve {
            approval.approve("webui", "approved via webui")?;
        } else {
            approval.deny("webui", "denied via webui")?;
        }
        fs::write(&path, serde_json::to_string_pretty(&approval)?)?;
        Ok(approval)
    })();

    match result {
        Ok(approval) => {
            let state_text = if approve { "approved" } else { "denied" };
            let _ = state.event_tx.send(DemoEvent {
                kind: if approve {
                    "approval_granted".to_string()
                } else {
                    "approval_denied".to_string()
                },
                provider: Some(approval.binding.provider.clone()),
                action: Some(approval.binding.action.clone()),
                decision: Some(state_text.to_string()),
                error_kind: None,
                reason: approval.reason.clone(),
                obs_ref: approval_id.strip_prefix("webui-").map(ToString::to_string),
                approval_id: Some(approval.approval_id.clone()),
                side_effect_executed: Some(false),
                defense_layer: Some("approval".to_string()),
                upstream_status: None,
                data: json!(approval),
            });
            Json(json!({
                "approval_id": approval_id,
                "state": state_text,
                "side_effect_executed": false
            }))
        }
        Err(err) => Json(json!({
            "error": err.to_string(),
            "side_effect_executed": false
        })),
    }
}

fn approval_path(state_dir: &Path, approval_id: &str) -> anyhow::Result<PathBuf> {
    Ok(state_dir
        .join("approvals")
        .join(format!("{}.json", safe_record_id(approval_id)?)))
}

fn safe_record_id(record_id: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(!record_id.is_empty(), "approval id must not be empty");
    anyhow::ensure!(
        record_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')),
        "approval id contains invalid characters"
    );
    Ok(record_id)
}

fn read_all_approvals(state_dir: &Path) -> anyhow::Result<Vec<ApprovalRecord>> {
    let dir = state_dir.join("approvals");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut approvals = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let body = fs::read_to_string(entry.path())?;
        if let Ok(approval) = serde_json::from_str::<ApprovalRecord>(&body) {
            approvals.push(approval);
        }
    }
    approvals.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
    Ok(approvals)
}

pub fn watch_jsonl_events(
    path: PathBuf,
    fallback_kind: &'static str,
    tx: broadcast::Sender<DemoEvent>,
) {
    // Note: 500ms polling — use the notify crate if sub-second latency matters.
    std::thread::spawn(move || {
        let mut last_len = 0usize;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            if content.len() < last_len {
                last_len = 0;
            }
            let new_content = &content[last_len..];
            last_len = content.len();
            for line in new_content.lines().filter(|line| !line.trim().is_empty()) {
                if let Ok(value) = serde_json::from_str::<Value>(line) {
                    let event = demo_event_from_value(value, fallback_kind);
                    let _ = tx.send(event);
                }
            }
        }
    });
}

fn demo_event_from_value(value: Value, fallback_kind: &str) -> DemoEvent {
    let payload = value
        .get("payload")
        .cloned()
        .unwrap_or_else(|| value.clone());
    let kind = value
        .get("kind")
        .or_else(|| value.get("event_type"))
        .and_then(Value::as_str)
        .unwrap_or(fallback_kind)
        .to_string();
    let provider = value
        .get("provider")
        .or_else(|| payload.get("provider"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let action = value
        .get("action")
        .or_else(|| payload.get("action"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let decision = value
        .get("decision")
        .or_else(|| payload.get("decision"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let error_kind = value
        .get("error_kind")
        .or_else(|| payload.get("error_kind"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let defense_layer = value
        .get("defense_layer")
        .or_else(|| payload.get("defense_layer"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            (provider.is_some() || decision.is_some() || error_kind.is_some()).then(|| {
                defense_layer_for(
                    provider.as_deref(),
                    decision.as_deref(),
                    error_kind.as_deref(),
                )
                .to_string()
            })
        });
    DemoEvent {
        kind,
        provider,
        action,
        decision,
        error_kind,
        reason: value
            .get("reason")
            .or_else(|| payload.get("reason"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        obs_ref: value
            .get("obs_ref")
            .or_else(|| value.get("obs_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        approval_id: value
            .get("approval_id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        side_effect_executed: value
            .get("side_effect_executed")
            .or_else(|| payload.get("side_effect_executed"))
            .and_then(Value::as_bool),
        defense_layer,
        upstream_status: payload
            .get("upstream_status")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        data: value,
    }
}

pub fn render_static_console_for_scenarios(
    input: &Path,
    scenarios: &[&str],
) -> anyhow::Result<String> {
    let files = scenarios
        .iter()
        .map(|scenario| input.join(scenario).join("webui.json"))
        .collect();
    render_static_console_from_files(files)
}

fn render_static_console_from_files(files: Vec<PathBuf>) -> anyhow::Result<String> {
    let mut events = Vec::new();
    for file in files {
        let value = read_json_value(&file)?;
        let scenario = value["scenario"].as_str().unwrap_or("unknown");
        for call in value["provider_calls"].as_array().into_iter().flatten() {
            let provider = call.get("provider").and_then(Value::as_str);
            let decision = call.get("decision").and_then(Value::as_str);
            let error_kind = call.get("error_kind").and_then(Value::as_str);
            events.push(json!({
                "kind": "provider_call",
                "scenario": scenario,
                "provider": call["provider"],
                "action": call["action"],
                "decision": call["decision"],
                "error_kind": call.get("error_kind"),
                "reason": call.get("reason"),
                "obs_ref": call.get("obs_ref"),
                "defense_layer": call
                    .get("defense_layer")
                    .cloned()
                    .unwrap_or_else(|| json!(defense_layer_for(provider, decision, error_kind))),
                "side_effect_executed": call.get("side_effect_executed"),
                "data": call
            }));
        }
    }
    Ok(CONSOLE_HTML.replace(
        "window.STATIC_EVENTS = null;",
        &format!(
            "window.STATIC_EVENTS = {};",
            serde_json::to_string(&events)?
        ),
    ))
}

fn read_json_value(path: &Path) -> anyhow::Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn read_trace(path: &Path) -> anyhow::Result<Vec<TraceEvent>> {
    let content = fs::read_to_string(path)?;
    if content.trim_start().starts_with('[') {
        Ok(serde_json::from_str(&content)?)
    } else {
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<TraceEvent>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)
    }
}

fn verify_trace_events(events: Vec<TraceEvent>) -> Value {
    let event_count = events.len();
    let mut store = InMemoryTraceStore::default();
    for event in events {
        store.append(event);
    }
    match store.verify_hash_chain() {
        Ok(()) => json!({ "verified": true, "event_count": event_count }),
        Err(err) => json!({
            "verified": false,
            "error_kind": "trace_tampered",
            "event_count": event_count,
            "offset": err.offset,
            "obs_id": err.obs_id,
            "message": err.reason
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runwarden_kernel::authority::ApprovalBinding;

    #[test]
    fn approval_path_accepts_record_ids_only() {
        let path = approval_path(Path::new("/tmp/state"), "webui-obs_1").expect("valid id");
        assert_eq!(path, PathBuf::from("/tmp/state/approvals/webui-obs_1.json"));
    }

    #[test]
    fn approval_path_rejects_path_like_ids() {
        assert!(approval_path(Path::new("/tmp/state"), "").is_err());
        assert!(approval_path(Path::new("/tmp/state"), "../webui-obs_1").is_err());
        assert!(approval_path(Path::new("/tmp/state"), "webui/obs_1").is_err());
        assert!(approval_path(Path::new("/tmp/state"), "webui.obs_1").is_err());
    }

    #[test]
    fn webui_approval_updates_pending_record_and_broadcasts_without_side_effect() {
        let dir = tempfile::tempdir().expect("state dir");
        let approvals_dir = dir.path().join("approvals");
        fs::create_dir_all(&approvals_dir).expect("approvals dir");
        let approval = ApprovalRecord::new(
            "webui-obs_loop",
            ApprovalBinding {
                session_id: "mcp-inline".to_string(),
                provider: "external.email.send".to_string(),
                action: "call".to_string(),
                argument_hash: "hash".to_string(),
                authz_id: None,
                actor_id: Some("mcp-agent".to_string()),
            },
        );
        fs::write(
            approvals_dir.join("webui-obs_loop.json"),
            serde_json::to_string_pretty(&approval).expect("approval json"),
        )
        .expect("write approval");

        let (tx, mut rx) = broadcast::channel(4);
        let state = AppState {
            event_tx: tx,
            state_dir: dir.path().to_path_buf(),
            trace_path: dir.path().join("trace.jsonl"),
        };

        let pending = read_all_approvals(dir.path()).expect("pending approvals");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].state, ApprovalState::Pending);

        let response = update_approval(&state, "webui-obs_loop", true).0;
        assert_eq!(response["state"], "approved");
        assert_eq!(response["side_effect_executed"], false);

        let saved: ApprovalRecord = serde_json::from_str(
            &fs::read_to_string(approvals_dir.join("webui-obs_loop.json")).expect("saved approval"),
        )
        .expect("saved approval json");
        assert_eq!(saved.state, ApprovalState::Approved);
        assert_eq!(saved.reviewer.as_deref(), Some("webui"));

        let event = rx.try_recv().expect("approval event");
        assert_eq!(event.kind, "approval_granted");
        assert_eq!(event.provider.as_deref(), Some("external.email.send"));
        assert_eq!(event.obs_ref.as_deref(), Some("obs_loop"));
        assert_eq!(event.side_effect_executed, Some(false));
    }

    #[test]
    fn provider_trace_verification_rejects_event_lines_without_trace_event() {
        let dir = tempfile::tempdir().expect("state dir");
        let path = dir.path().join("events.jsonl");
        let trace_event = TraceEvent::sealed(
            "obs_console_trace".to_string(),
            "provider_completed".to_string(),
            Some("external.email.send".to_string()),
            json!({"decision": "allowed", "side_effect_executed": true}),
            None,
        );
        fs::write(
            &path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&json!({"data": {"trace_event": trace_event}}))
                    .expect("valid event"),
                serde_json::to_string(&json!({"data": {"decision": "allowed"}}))
                    .expect("missing trace event")
            ),
        )
        .expect("events jsonl");

        let result = provider_trace_verify_result(&path);

        assert_eq!(result["verified"], false);
        assert!(
            result["error"]
                .as_str()
                .is_some_and(|error| error.contains("missing data.trace_event"))
        );
    }

    #[test]
    fn console_polls_trace_verification_after_page_load() {
        assert!(CONSOLE_HTML.contains("setInterval(verifyTrace, 1500);"));
    }
}
