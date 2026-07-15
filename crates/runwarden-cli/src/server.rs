use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{
        Html, IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use runwarden_assurance::report::{ReportDraft, lint_report_against_trace};
use runwarden_kernel::{
    authority::{ApprovalRecord, ApprovalState},
    evidence::{InMemoryTraceStore, TraceEvent, hex_sha256},
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

#[derive(Clone)]
struct HttpAppState {
    app: AppState,
    reviewer: ReviewerSession,
}

#[derive(Clone)]
struct ReviewerSession {
    token: String,
    reviewer_id: String,
    expected_host: String,
    expected_origin: String,
}

impl ReviewerSession {
    fn generate(expected_host: String) -> anyhow::Result<Self> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).context("generate reviewer session secret")?;
        let token = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        let reviewer_id = format!("reviewer-session-{}", &hex_sha256(&secret)[..16]);
        Ok(Self {
            token,
            reviewer_id,
            expected_origin: format!("http://{expected_host}"),
            expected_host,
        })
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        let supplied = headers
            .get("x-runwarden-reviewer-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let origin = headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let fetch_site = headers
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok());
        let authorized = constant_time_eq(supplied.as_bytes(), self.token.as_bytes())
            && host == self.expected_host
            && origin == self.expected_origin
            && fetch_site.is_none_or(|value| value == "same-origin");
        if authorized {
            Ok(())
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "reviewer_authentication_failed",
                    "message": "a valid reviewer capability, exact Host, and same-origin request are required",
                    "side_effect_executed": false
                })),
            ))
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DemoEvent {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_family: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomaly_reasons: Vec<String>,
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
        _ if provider.is_some_and(|provider| provider == "external.code.execute") => "code-runtime",
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
    let bind_ip: IpAddr = bind
        .parse()
        .with_context(|| format!("parse console bind address {bind}"))?;
    anyhow::ensure!(
        bind_ip.is_loopback(),
        "the reviewer console may only bind to a loopback address"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(format!("{bind}:{port}")).await?;
        let addr = listener.local_addr()?;
        let reviewer = ReviewerSession::generate(addr.to_string())?;
        let proxy_client_token = std::env::var("RUNWARDEN_PROXY_CLIENT_TOKEN")
            .context("RUNWARDEN_PROXY_CLIENT_TOKEN must be generated before the console starts")?;
        let reviewer_url = format!(
            "http://{addr}/#review_token={}",
            reviewer.token
        );
        if json_output {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "mode": "interactive_demo",
                    "listen_addr": addr.to_string(),
                    "url": format!("http://{addr}"),
                    "reviewer_url": reviewer_url,
                    "reviewer_id": reviewer.reviewer_id,
                    "review_token_sha256": hex_sha256(reviewer.token.as_bytes()),
                    "proxy_client_token": proxy_client_token,
                    "proxy_client_token_sha256": hex_sha256(proxy_client_token.as_bytes()),
                    "events_url": format!("http://{addr}/events"),
                    "snapshot_url": format!("http://{addr}/api/console/snapshot"),
                    "console_schema": "runwarden.console.v2",
                    "state_dir": state.state_dir,
                    "side_effect_executed": false
                }))?
            );
        } else {
            println!("Runwarden demo server running.");
            println!();
            println!("  Reviewer:  {reviewer_url}");
            println!("  LLM proxy: http://127.0.0.1:8787/v1");
            println!();
            println!("In another terminal:");
            println!("  export PATH=\"$PWD/target/debug:$PATH\"");
            println!("  export RUNWARDEN_PROXY_CLIENT_TOKEN=\"{proxy_client_token}\"");
            println!("  unset RUNWARDEN_LLM_API_KEY  # keep the upstream key out of the agent process");
            println!(
                "  export RUNWARDEN_STATE_DIR=\"{}\"",
                state.state_dir.display()
            );
            println!("  export RUNWARDEN_SESSION_ID=\"demo-$(date +%s%N)-$$\"");
            println!("  export RUNWARDEN_ACTOR_ID=opencode-demo-agent");
            println!("  export XDG_CONFIG_HOME=/tmp/oc-runwarden/xdg/config");
            println!("  export XDG_DATA_HOME=/tmp/oc-runwarden/xdg/data");
            println!("  export XDG_CACHE_HOME=/tmp/oc-runwarden/xdg/cache");
            println!("  export XDG_STATE_HOME=/tmp/oc-runwarden/xdg/state");
            println!("  mkdir -p /tmp/oc-runwarden \"$XDG_CONFIG_HOME/opencode\"");
            println!(
                "  cp examples/agent-configs/opencode.runwarden-only.json \"$XDG_CONFIG_HOME/opencode/opencode.json\""
            );
            println!("  cd /tmp/oc-runwarden");
            println!("  opencode run \"send an email to test@example.com\" -m runwarden-proxy/big-pickle --print-logs");
            println!();
            println!("Press Ctrl+C to stop.");
        }
        std::io::stdout().flush().ok();

        let http_state = HttpAppState {
            app: state,
            reviewer,
        };
        let app = Router::new()
            .route("/", get(console_handler))
            .route("/events", get(sse_handler))
            .route("/api/console/snapshot", get(snapshot_handler))
            .route(
                "/api/approvals/{approval_id}/decision",
                post(approval_decision_handler),
            )
            .route("/api/pending", get(pending_handler))
            .route("/api/trace/verify", get(trace_verify_handler))
            .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
            .with_state(http_state);
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn console_handler(State(_state): State<HttpAppState>) -> Response {
    let mut response = Html(CONSOLE_HTML).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn sse_handler(
    State(state): State<HttpAppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.app.event_tx.subscribe()).filter_map(|result| {
        result.ok().and_then(|event| {
            let event_id = event
                .obs_ref
                .clone()
                .or_else(|| event.approval_id.clone())
                .unwrap_or_else(|| event.kind.clone());
            Event::default()
                .event(event.kind.clone())
                .id(event_id)
                .retry(std::time::Duration::from_secs(2))
                .json_data(event)
                .ok()
                .map(Ok)
        })
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionBody {
    decision: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn approval_decision_handler(
    State(state): State<HttpAppState>,
    AxumPath(approval_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<ApprovalDecisionBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    state.reviewer.authorize(&headers)?;
    let approve = match body.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "invalid_decision",
                    "message": "decision must be approve or deny",
                    "side_effect_executed": false
                })),
            ));
        }
    };
    let reviewer = state.reviewer.reviewer_id.as_str();
    let reason = body.reason.as_deref().unwrap_or(if approve {
        "approved via review desk"
    } else {
        "denied via review desk"
    });
    match decide_approval_record(&state.app, &approval_id, approve, reviewer, reason) {
        Ok(approval) => {
            broadcast_approval_event(&state.app, &approval, approve);
            Ok(Json(json!({
                "approval_id": approval.approval_id,
                "state": if approve { "approved" } else { "denied" },
                "reviewer": reviewer,
                "reason": reason,
                "side_effect_executed": false
            })))
        }
        Err(err) => {
            let message = err.to_string();
            let status = if message.contains("invalid characters")
                || message.contains("must not be empty")
                || message.contains("exceeds")
            {
                StatusCode::UNPROCESSABLE_ENTITY
            } else if message.contains("No such file") || message.contains("not found") {
                StatusCode::NOT_FOUND
            } else if message.contains("transition")
                || message.contains("pending")
                || message.contains("approved")
                || message.contains("denied")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            Err((
                status,
                Json(json!({
                    "error": "approval_decision_failed",
                    "message": message,
                    "side_effect_executed": false
                })),
            ))
        }
    }
}

async fn pending_handler(
    State(state): State<HttpAppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let approvals = read_all_approvals(&state.app.state_dir).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "approval_ledger_unreadable",
                "message": format!("{error:#}"),
                "side_effect_executed": false
            })),
        )
    })?;
    let pending: Vec<_> = approvals
        .into_iter()
        .filter(|approval| approval.state == ApprovalState::Pending)
        .collect();
    Ok(Json(
        json!({ "pending": pending, "side_effect_executed": false }),
    ))
}

async fn snapshot_handler(
    State(state): State<HttpAppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    build_live_snapshot(&state.app).map(Json).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "console_snapshot_unavailable",
                "message": err.to_string(),
                "side_effect_executed": false
            })),
        )
    })
}

fn build_live_snapshot(state: &AppState) -> anyhow::Result<Value> {
    let model_events = read_console_events(&state.trace_path, "model_call");
    let provider_events =
        read_console_events(&state.state_dir.join("events.jsonl"), "provider_call");
    let approval_events = read_console_events(
        &state.state_dir.join("approval-events.jsonl"),
        "approval_decision",
    );
    let mut events = model_events.events;
    events.extend(provider_events.events);
    events.extend(approval_events.events);
    let mut ingestion_errors = model_events
        .errors
        .into_iter()
        .chain(provider_events.errors)
        .chain(approval_events.errors)
        .collect::<Vec<_>>();
    for (index, event) in events.iter_mut().enumerate() {
        event.sequence = Some((index + 1) as u64);
    }
    let approvals = match read_all_approvals(&state.state_dir) {
        Ok(approvals) => approvals,
        Err(error) => {
            ingestion_errors.push(format!("read approval ledger: {error:#}"));
            Vec::new()
        }
    };
    let pending_review_count = approvals
        .iter()
        .filter(|approval| approval.state == ApprovalState::Pending)
        .count();
    let reviews = approvals
        .into_iter()
        .map(|approval| {
            let review_event = events
                .iter()
                .rev()
                .find(|event| event.approval_id.as_deref() == Some(&approval.approval_id));
            let argument_preview = review_event
                .and_then(event_argument_preview)
                .unwrap_or(Value::Null);
            let reason = approval
                .reason
                .clone()
                .or_else(|| review_event.and_then(|event| event.reason.clone()))
                .unwrap_or_else(|| {
                    "A side-effecting capability requires a bound, one-use human decision."
                        .to_string()
                });
            json!({
                "approval_id": approval.approval_id,
                "state": approval.state,
                "provider": approval.binding.provider,
                "action": approval.binding.action,
                "argument_hash": approval.binding.argument_hash,
                "actor_id": approval.binding.actor_id,
                "authz_id": approval.binding.authz_id,
                "expires_at": approval.expires_at,
                "risk_score": review_event.and_then(|event| event.risk_score),
                "risk_level": review_event
                    .and_then(|event| event.risk_level.clone())
                    .unwrap_or_else(|| "high".to_string()),
                "anomaly_reasons": review_event
                    .map(|event| event.anomaly_reasons.clone())
                    .unwrap_or_default(),
                "obs_ref": review_event.and_then(|event| event.obs_ref.clone()),
                "argument_preview": argument_preview,
                "reason": reason,
                "reviewer": approval.reviewer
            })
        })
        .collect::<Vec<_>>();
    let mut evidence = trace_overview(state);
    if !ingestion_errors.is_empty() {
        evidence["status"] = json!("tampered");
        evidence["verified"] = json!(false);
        evidence["ingestion_verified"] = json!(false);
    } else {
        evidence["ingestion_verified"] = json!(true);
    }
    let summary = summarize_events(&events, pending_review_count, &evidence);
    Ok(json!({
        "schema_version": "runwarden.console.v2",
        "mode": "live",
        "cursor": events.len(),
        "system": {
            "name": "Runwarden Causal Defense Fabric",
            "enforcement": "fail_closed",
            "agent_tool_boundary": "runwarden-mcp",
            "model_boundary": "runwarden-llm-proxy",
            "bind_scope": "loopback"
        },
        "summary": summary,
        "events": events,
        "reviews": reviews,
        "scenarios": scenario_catalog(),
        "evidence": evidence,
        "defense_layers": defense_layer_counts(&events),
        "ingestion": {
            "ok": ingestion_errors.is_empty(),
            "errors": ingestion_errors
        }
    }))
}

#[derive(Default)]
struct ConsoleEventRead {
    events: Vec<DemoEvent>,
    errors: Vec<String>,
}

fn read_console_events(path: &Path, fallback_kind: &str) -> ConsoleEventRead {
    if !path.exists() {
        return ConsoleEventRead::default();
    }
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            return ConsoleEventRead {
                events: Vec::new(),
                errors: vec![format!("read {}: {error}", path.display())],
            };
        }
    };
    if content.trim_start().starts_with('[') {
        return match serde_json::from_str::<Vec<Value>>(&content) {
            Ok(values) => ConsoleEventRead {
                events: values
                    .into_iter()
                    .map(|value| demo_event_from_value(value, fallback_kind))
                    .collect(),
                errors: Vec::new(),
            },
            Err(error) => ConsoleEventRead {
                events: Vec::new(),
                errors: vec![format!("parse event array {}: {error}", path.display())],
            },
        };
    }

    let mut batch = ConsoleEventRead::default();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(value) => batch
                .events
                .push(demo_event_from_value(value, fallback_kind)),
            Err(error) => batch.errors.push(format!(
                "parse {} line {}: {error}",
                path.display(),
                index + 1
            )),
        }
    }
    batch
}

fn summarize_events(events: &[DemoEvent], pending: usize, evidence: &Value) -> Value {
    let denied = events
        .iter()
        .filter(|event| event.decision.as_deref() == Some("denied"))
        .count();
    let held = events
        .iter()
        .filter(|event| event.decision.as_deref() == Some("requires_review"))
        .count();
    let anomalous = events
        .iter()
        .filter(|event| event.risk_score.unwrap_or(0) >= 40 || !event.anomaly_reasons.is_empty())
        .count();
    let blocked_before_effect = events
        .iter()
        .filter(|event| {
            matches!(
                event.decision.as_deref(),
                Some("denied" | "requires_review")
            ) && event.side_effect_executed == Some(false)
        })
        .count();
    let risk_sum: usize = events
        .iter()
        .map(|event| usize::from(event.risk_score.unwrap_or(0)))
        .sum();
    let risk_index = if events.is_empty() {
        0
    } else {
        risk_sum / events.len()
    };
    json!({
        "operations": events.len(),
        "denied": denied,
        "held_for_review": held,
        "pending_reviews": pending,
        "anomalous": anomalous,
        "blocked_before_effect": blocked_before_effect,
        "side_effects_executed": events.iter().filter(|event| event.side_effect_executed == Some(true)).count(),
        "risk_index": risk_index,
        "evidence_status": evidence["status"]
    })
}

fn defense_layer_counts(events: &[DemoEvent]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for layer in events
        .iter()
        .filter_map(|event| event.defense_layer.as_ref())
    {
        *counts.entry(layer.clone()).or_default() += 1;
    }
    counts
}

fn scenario_catalog() -> Value {
    json!([
        {"id":"prompt-injection-file-exfil","family":"indirect_prompt_injection","label":"提示注入与文件外泄","layers":["input-inspection","approval","provider-policy","trace-verification"]},
        {"id":"tool-hijack-email-api","family":"tool_hijack","label":"工具劫持与影子回调","layers":["input-inspection","approval","provider-policy","anomaly"]},
        {"id":"memory-knowledge-poisoning","family":"memory_poisoning","label":"记忆与知识投毒","layers":["input-inspection","approval","provider-policy","trace-verification"]},
        {"id":"environment-local-web-risk","family":"environment_pollution","label":"环境污染与 SSRF","layers":["input-inspection","egress","provider-policy","trace-verification"]},
        {"id":"path-escape-file-boundary","family":"path_escape","label":"文件边界逃逸","layers":["input-inspection","scoped-root","provider-policy","trace-verification"]}
    ])
}

async fn trace_verify_handler(State(state): State<HttpAppState>) -> Json<Value> {
    Json(trace_overview(&state.app))
}

fn trace_overview(state: &AppState) -> Value {
    let model_result = match read_trace(&state.trace_path) {
        Ok(events) => verify_trace_events(events),
        Err(error) => json!({
            "verified": false,
            "error": format!("{error:#}"),
            "event_count": 0
        }),
    };

    let mcp_result = provider_trace_verify_result(&state.state_dir.join("events.jsonl"));
    let approval_result = match read_trace(&state.state_dir.join("approval-events.jsonl")) {
        Ok(events) => verify_trace_events(events),
        Err(error) => json!({
            "verified": false,
            "error": format!("{error:#}"),
            "event_count": 0
        }),
    };
    let provider_approval_ids = provider_trace_approval_ids(&state.state_dir.join("events.jsonl"));
    let approval_ledger_result = match (read_all_approvals(&state.state_dir), provider_approval_ids)
    {
        (Ok(approvals), Ok(required_ids)) => {
            verify_approval_ledger_against_audit(&state.state_dir, &approvals, &required_ids)
        }
        (Err(error), _) => json!({
            "verified": false,
            "required": true,
            "error": format!("read approval ledger: {error:#}"),
            "checked_records": 0
        }),
        (Ok(_), Err(error)) => json!({
            "verified": false,
            "required": true,
            "error": format!("read provider approval references: {error:#}"),
            "checked_records": 0
        }),
    };

    let model_status = verification_status(&model_result);
    let provider_status = verification_status(&mcp_result);
    let approval_status = verification_status(&approval_result);
    let status = if model_status == "tampered"
        || provider_status == "tampered"
        || approval_status == "tampered"
        || approval_ledger_result["verified"].as_bool() != Some(true)
    {
        "tampered"
    } else if model_status == "verified" && provider_status == "verified" {
        "verified"
    } else if model_status == "verified"
        || provider_status == "verified"
        || approval_status == "verified"
    {
        "partial"
    } else {
        "empty"
    };

    json!({
        "model_trace": model_result,
        "provider_trace": mcp_result,
        "approval_trace": approval_result,
        "approval_ledger": approval_ledger_result,
        "status": status,
        "verified": status == "verified",
        "side_effect_executed": false
    })
}

fn verify_approval_ledger_against_audit(
    state_dir: &Path,
    approvals: &[ApprovalRecord],
    provider_approval_ids: &std::collections::BTreeSet<String>,
) -> Value {
    let required = approvals
        .iter()
        .any(|approval| approval.state != ApprovalState::Pending);
    let path = state_dir.join("approval-events.jsonl");
    if !required && !path.exists() {
        let ledger_ids = approvals
            .iter()
            .map(|approval| approval.approval_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let missing = provider_approval_ids
            .iter()
            .filter(|approval_id| !ledger_ids.contains(approval_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        return json!({
            "verified": missing.is_empty(),
            "required": false,
            "ledger_required": !provider_approval_ids.is_empty(),
            "checked_records": 0,
            "audit_events": 0,
            "missing_provider_approval_records": missing
        });
    }

    let events = match read_trace(&path) {
        Ok(events) => events,
        Err(error) => {
            return json!({
                "verified": false,
                "required": required,
                "checked_records": 0,
                "audit_events": 0,
                "error": format!("read approval decision audit: {error:#}")
            });
        }
    };
    let trace_verification = verify_trace_events(events.clone());
    if trace_verification["verified"].as_bool() != Some(true) {
        return json!({
            "verified": false,
            "required": required,
            "checked_records": 0,
            "audit_events": events.len(),
            "error": "approval decision hash chain is invalid"
        });
    }

    let mut errors = Vec::new();
    let ledger_ids = approvals
        .iter()
        .map(|approval| approval.approval_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for approval_id in provider_approval_ids {
        if !ledger_ids.contains(approval_id.as_str()) {
            errors.push(format!(
                "provider trace references approval {approval_id}, but its ledger record is missing"
            ));
        }
    }
    let mut events_by_id: BTreeMap<String, Vec<&TraceEvent>> = BTreeMap::new();
    for event in &events {
        let approval_id = event
            .payload
            .get("approval_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if event.event_type != "approval_decision" || approval_id.is_empty() {
            errors.push(format!(
                "{} is not a well-formed approval_decision event",
                event.obs_id
            ));
            continue;
        }
        events_by_id
            .entry(approval_id.to_string())
            .or_default()
            .push(event);
    }

    let mut checked_records = 0_usize;
    for approval in approvals {
        let audit_events = events_by_id
            .remove(&approval.approval_id)
            .unwrap_or_default();
        if approval.state == ApprovalState::Pending {
            if !audit_events.is_empty() {
                errors.push(format!(
                    "pending approval {} unexpectedly has a decision audit",
                    approval.approval_id
                ));
            }
            continue;
        }
        checked_records += 1;
        if audit_events.len() != 1 {
            errors.push(format!(
                "approval {} has {} decision audits; expected exactly one",
                approval.approval_id,
                audit_events.len()
            ));
            continue;
        }
        if let Err(error) = verify_approval_record_binding(approval, audit_events[0]) {
            errors.push(format!("approval {}: {error:#}", approval.approval_id));
        }
    }
    for (approval_id, orphaned) in events_by_id {
        errors.push(format!(
            "approval decision audit {} has no ledger record ({} event(s))",
            approval_id,
            orphaned.len()
        ));
    }

    json!({
        "verified": errors.is_empty(),
        "required": required,
        "ledger_required": !provider_approval_ids.is_empty(),
        "checked_records": checked_records,
        "audit_events": events.len(),
        "errors": errors
    })
}

fn provider_trace_approval_ids(path: &Path) -> anyhow::Result<std::collections::BTreeSet<String>> {
    if !path.exists() {
        return Ok(Default::default());
    }
    let content = fs::read_to_string(path)?;
    let mut approval_ids = std::collections::BTreeSet::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Value = serde_json::from_str(line)
            .with_context(|| format!("parse provider event line {}", index + 1))?;
        if let Some(approval_id) = event.get("approval_id").and_then(Value::as_str) {
            approval_ids.insert(approval_id.to_string());
        }
    }
    Ok(approval_ids)
}

fn verify_approval_record_binding(
    approval: &ApprovalRecord,
    event: &TraceEvent,
) -> anyhow::Result<()> {
    let expected_state = match approval.state {
        ApprovalState::Approved | ApprovalState::Denied => approval.state.clone(),
        ApprovalState::Consumed => ApprovalState::Approved,
        ApprovalState::Pending => anyhow::bail!("pending approvals do not have decision audits"),
        ApprovalState::Expired | ApprovalState::Revoked => {
            anyhow::bail!("terminal state has no authoritative decision transition")
        }
    };
    let mut decided_record = approval.clone();
    decided_record.state = expected_state.clone();
    let record_sha256 = canonical_sha256(&serde_json::to_value(&decided_record)?)?;
    let binding_sha256 = canonical_sha256(&serde_json::to_value(&approval.binding)?)?;
    let expected_state_value = serde_json::to_value(expected_state)?;
    anyhow::ensure!(
        event.provider.as_deref() == Some(approval.binding.provider.as_str()),
        "audit provider does not match the approval binding"
    );
    anyhow::ensure!(
        event.payload.get("schema_version").and_then(Value::as_str)
            == Some("runwarden.approval-decision.v1"),
        "unsupported approval decision schema"
    );
    anyhow::ensure!(
        event.payload.get("approval_id").and_then(Value::as_str)
            == Some(approval.approval_id.as_str())
            && event.payload.get("provider").and_then(Value::as_str)
                == Some(approval.binding.provider.as_str())
            && event.payload.get("action").and_then(Value::as_str)
                == Some(approval.binding.action.as_str()),
        "audit identity does not match the approval record"
    );
    anyhow::ensure!(
        event.payload.get("state") == Some(&expected_state_value),
        "audit state does not match the authoritative decision"
    );
    anyhow::ensure!(
        event.payload.get("record_sha256").and_then(Value::as_str) == Some(record_sha256.as_str())
            && event.payload.get("binding_sha256").and_then(Value::as_str)
                == Some(binding_sha256.as_str()),
        "approval record or binding digest does not match the decision audit"
    );
    Ok(())
}

fn canonical_sha256(value: &Value) -> anyhow::Result<String> {
    Ok(hex_sha256(&serde_json::to_vec(&canonical_json_value(
        value,
    ))?))
}

fn verification_status(result: &Value) -> &'static str {
    if result["verified"].as_bool() == Some(true) {
        "verified"
    } else {
        let error = result["error"].as_str().unwrap_or_default();
        if result["event_count"].as_u64().unwrap_or(0) == 0
            && (error.contains("not found")
                || error == "no provider trace events"
                || error == "no trace events")
        {
            "empty"
        } else {
            "tampered"
        }
    }
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
        let data = event
            .get("data")
            .with_context(|| format!("event line {} is missing data", index + 1))?;
        let trace_event = data
            .get("trace_event")
            .cloned()
            .with_context(|| format!("event line {} is missing data.trace_event", index + 1))?;
        let trace_event: TraceEvent = serde_json::from_value(trace_event)
            .with_context(|| format!("parse trace_event on event line {}", index + 1))?;
        verify_provider_event_binding(&event, &trace_event)
            .with_context(|| format!("verify provider event binding on line {}", index + 1))?;
        trace_events.push(trace_event);
    }
    Ok(trace_events)
}

fn verify_provider_event_binding(event: &Value, trace_event: &TraceEvent) -> anyhow::Result<()> {
    let expected = trace_event
        .payload
        .pointer("/provider_event_binding/canonical_event_sha256")
        .and_then(Value::as_str)
        .context("sealed trace is missing provider_event_binding")?;
    let actual = provider_event_binding_digest(event)?;
    anyhow::ensure!(
        expected == actual,
        "provider event wrapper does not match its sealed trace binding"
    );
    Ok(())
}

fn provider_event_binding_digest(event: &Value) -> anyhow::Result<String> {
    let mut material = event.clone();
    material
        .get_mut("data")
        .and_then(Value::as_object_mut)
        .context("provider event binding material is missing data")?
        .remove("trace_event");
    let canonical = canonical_json_value(&material);
    Ok(hex_sha256(&serde_json::to_vec(&canonical)?))
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical_json_value(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        _ => value.clone(),
    }
}

fn provider_trace_verify_result(path: &Path) -> Value {
    match read_provider_trace_events(path) {
        Ok(events) if events.is_empty() => {
            json!({ "verified": false, "error": "no provider trace events", "event_count": 0 })
        }
        Ok(events) => verify_trace_events(events),
        Err(err) => json!({
            "verified": false,
            "error": format!("{err:#}"),
            "event_count": 0
        }),
    }
}

#[cfg(test)]
fn update_approval(state: &AppState, approval_id: &str, approve: bool) -> Json<Value> {
    let result = decide_approval_record(
        state,
        approval_id,
        approve,
        "webui",
        if approve {
            "approved via webui"
        } else {
            "denied via webui"
        },
    );

    match result {
        Ok(approval) => {
            let state_text = if approve { "approved" } else { "denied" };
            broadcast_approval_event(state, &approval, approve);
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

fn decide_approval_record(
    state: &AppState,
    approval_id: &str,
    approve: bool,
    reviewer: &str,
    reason: &str,
) -> anyhow::Result<ApprovalRecord> {
    anyhow::ensure!(!reviewer.trim().is_empty(), "reviewer must not be empty");
    anyhow::ensure!(!reason.trim().is_empty(), "review reason must not be empty");
    anyhow::ensure!(reviewer.len() <= 128, "reviewer exceeds 128 bytes");
    anyhow::ensure!(reason.len() <= 2_048, "review reason exceeds 2048 bytes");
    let path = approval_path(&state.state_dir, approval_id)?;
    let lock_path = path
        .parent()
        .context("approval record path is missing its parent")?
        .join(format!(".{approval_id}.review.lock"));
    let mut review_lock = acquire_server_lock(
        &lock_path,
        "runwarden.approval-review-lock.v1",
        "approval review",
    )?;
    let body = fs::read_to_string(&path)?;
    let original = serde_json::from_str::<ApprovalRecord>(&body)?;
    let mut approval = original.clone();
    if approve {
        approval.approve(reviewer, reason)?;
    } else {
        approval.deny(reviewer, reason)?;
    }
    persist_approval_record(&path, &approval)?;
    if let Err(audit_error) = append_approval_decision_event(state, &approval) {
        if let Err(rollback_error) = persist_approval_record(&path, &original) {
            review_lock.retain_fail_closed();
            anyhow::bail!(
                "approval audit failed ({audit_error:#}) and rollback failed ({rollback_error:#}); review lock retained fail-closed"
            );
        }
        anyhow::bail!("approval audit failed and record was rolled back: {audit_error:#}");
    }
    Ok(approval)
}

fn persist_approval_record(path: &Path, approval: &ApprovalRecord) -> anyhow::Result<()> {
    let temp = path.with_extension(format!(
        "json.{}.{}.tmp",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let mut bytes = serde_json::to_vec_pretty(approval)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

struct DurableServerLock {
    path: PathBuf,
    remove_on_drop: bool,
}

impl DurableServerLock {
    fn retain_fail_closed(&mut self) {
        self.remove_on_drop = false;
    }
}

impl Drop for DurableServerLock {
    fn drop(&mut self) {
        if self.remove_on_drop
            && fs::remove_file(&self.path).is_ok()
            && let Some(parent) = self.path.parent()
        {
            let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
        }
    }
}

fn acquire_server_lock(
    path: &Path,
    schema_version: &str,
    label: &str,
) -> anyhow::Result<DurableServerLock> {
    const RETRIES: usize = 200;
    let parent = path.parent().context("lock path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut file = None;
    let mut last_error = None;
    for attempt in 0..=RETRIES {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(created) => {
                file = Some(created);
                break;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < RETRIES =>
            {
                last_error = Some(error);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => return Err(error).with_context(|| format!("acquire {label} lock")),
        }
    }
    let mut file = file.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to acquire {label} lock after retries: {}; verify approval/audit state before manually removing a stale lock",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "lock exists".to_string())
        )
    })?;
    let mut bytes = serde_json::to_vec(&json!({
        "schema_version": schema_version,
        "pid": std::process::id(),
        "created_at_unix_nanos": time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string()
    }))?;
    bytes.push(b'\n');
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(DurableServerLock {
        path: path.to_path_buf(),
        remove_on_drop: true,
    })
}

fn approval_event_append_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn append_approval_decision_event(
    state: &AppState,
    approval: &ApprovalRecord,
) -> anyhow::Result<TraceEvent> {
    let _process_guard = approval_event_append_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("approval event append lock is poisoned"))?;
    fs::create_dir_all(&state.state_dir)?;
    let path = state.state_dir.join("approval-events.jsonl");
    let append_lock_path = state.state_dir.join(".approval-events.jsonl.append.lock");
    let _append_lock = acquire_server_lock(
        &append_lock_path,
        "runwarden.approval-event-append-lock.v1",
        "approval event append",
    )?;
    let previous_hash = if path.exists() {
        let events = read_trace(&path)?;
        let verification = verify_trace_events(events.clone());
        anyhow::ensure!(
            verification["verified"].as_bool() == Some(true),
            "refusing to append to an invalid approval event chain"
        );
        events.last().map(|event| event.event_hash.clone())
    } else {
        None
    };
    let approval_value = serde_json::to_value(approval)?;
    let record_sha256 = hex_sha256(&serde_json::to_vec(&canonical_json_value(&approval_value))?);
    let binding_value = serde_json::to_value(&approval.binding)?;
    let binding_sha256 = hex_sha256(&serde_json::to_vec(&canonical_json_value(&binding_value))?);
    let reviewer = approval.reviewer.as_deref().unwrap_or_default();
    let reason = approval.reason.as_deref().unwrap_or_default();
    let identity = hex_sha256(
        format!(
            "{}:{:?}:{record_sha256}",
            approval.approval_id, approval.state
        )
        .as_bytes(),
    );
    let event = TraceEvent::sealed(
        format!("obs_approval_{}", &identity[..24]),
        "approval_decision".to_string(),
        Some(approval.binding.provider.clone()),
        json!({
            "schema_version": "runwarden.approval-decision.v1",
            "approval_id": approval.approval_id,
            "state": approval.state,
            "provider": approval.binding.provider,
            "action": approval.binding.action,
            "binding_sha256": binding_sha256,
            "record_sha256": record_sha256,
            "reviewer_summary": {
                "bytes": reviewer.len(),
                "sha256": hex_sha256(reviewer.as_bytes())
            },
            "reason_summary": {
                "bytes": reason.len(),
                "sha256": hex_sha256(reason.as_bytes())
            },
            "decision": if approval.state == ApprovalState::Approved { "approved" } else { "denied" },
            "side_effect_executed": false,
            "decided_at_unix_nanos": time::OffsetDateTime::now_utc()
                .unix_timestamp_nanos()
                .to_string()
        }),
        previous_hash,
    );
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    file.sync_all()?;
    fs::File::open(&state.state_dir)?.sync_all()?;
    Ok(event)
}

fn broadcast_approval_event(state: &AppState, approval: &ApprovalRecord, approve: bool) {
    let state_text = if approve { "approved" } else { "denied" };
    let _ = state.event_tx.send(DemoEvent {
        kind: if approve {
            "approval_granted".to_string()
        } else {
            "approval_denied".to_string()
        },
        sequence: None,
        scenario: None,
        provider: Some(approval.binding.provider.clone()),
        action: Some(approval.binding.action.clone()),
        decision: Some(state_text.to_string()),
        error_kind: None,
        reason: approval.reason.clone(),
        obs_ref: approval
            .approval_id
            .strip_prefix("webui-")
            .or_else(|| approval.approval_id.strip_prefix("anomaly-"))
            .map(ToString::to_string),
        approval_id: Some(approval.approval_id.clone()),
        side_effect_executed: Some(false),
        defense_layer: Some("approval".to_string()),
        upstream_status: None,
        risk_score: Some(if approve { 48 } else { 64 }),
        risk_level: Some("high".to_string()),
        threat_family: Some("human_authority".to_string()),
        anomaly_reasons: Vec::new(),
        data: json!(approval),
    });
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
        let approval = serde_json::from_str::<ApprovalRecord>(&body)
            .with_context(|| format!("parse approval record {}", entry.path().display()))?;
        approvals.push(approval);
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
            let unread = &content[last_len..];
            let Some(complete_len) = unread.rfind('\n').map(|offset| offset + 1) else {
                continue;
            };
            let new_content = &unread[..complete_len];
            last_len += complete_len;
            for (line_index, line) in new_content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
            {
                let event = match serde_json::from_str::<Value>(line) {
                    Ok(value) => demo_event_from_value(value, fallback_kind),
                    Err(error) => demo_event_from_value(
                        json!({
                            "kind": "evidence_tampered",
                            "decision": "denied",
                            "reason": format!(
                                "failed to parse {} appended line {}: {error}",
                                path.display(),
                                line_index + 1
                            ),
                            "side_effect_executed": false,
                            "data": {"path": path.to_string_lossy(), "parse_error": error.to_string()}
                        }),
                        "evidence_tampered",
                    ),
                };
                let _ = tx.send(event);
            }
        }
    });
}

fn demo_event_from_value(value: Value, fallback_kind: &str) -> DemoEvent {
    let envelope_payload = value
        .get("payload")
        .or_else(|| value.get("data"))
        .unwrap_or(&value);
    // Provider events carry an inner TraceEvent. Security-relevant console
    // fields are always derived from its sealed payload, never from the
    // mutable outer convenience envelope.
    let sealed_trace = envelope_payload.get("trace_event");
    let payload = sealed_trace
        .and_then(|trace| trace.get("payload"))
        .unwrap_or(envelope_payload);
    let kind = value
        .get("event_type")
        .or_else(|| value.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or(fallback_kind)
        .to_string();
    let provider = value
        .get("payload")
        .and_then(|payload| payload.get("provider"))
        .or_else(|| payload.get("provider"))
        .or_else(|| value.get("provider"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let action = payload
        .get("action")
        .or_else(|| value.get("action"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let decision = payload
        .get("decision")
        .or_else(|| value.get("decision"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let error_kind = payload
        .get("error_kind")
        .or_else(|| value.get("error_kind"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let defense_layer = payload
        .get("defense_layer")
        .or_else(|| value.get("defense_layer"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            payload
                .pointer("/envelope/gate_id")
                .and_then(Value::as_str)
                .filter(|gate| *gate == "behavior_anomaly" || *gate == "behavior_risk")
                .map(|_| "behavior-risk".to_string())
        })
        .or_else(|| match kind.as_str() {
            "model_call"
                if matches!(
                    decision.as_deref(),
                    Some("output_blocked" | "output_flagged")
                ) =>
            {
                Some("output-inspection".to_string())
            }
            "model_call" => Some("input-inspection".to_string()),
            _ => None,
        })
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
    let anomaly = payload.get("anomaly").or_else(|| value.get("anomaly"));
    let anomaly_reasons = anomaly
        .and_then(|anomaly| anomaly.get("reasons"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let filter_risk_count = ["input_risks", "output_risks"]
        .into_iter()
        .filter_map(|key| payload.get(key).and_then(Value::as_array))
        .map(Vec::len)
        .sum::<usize>();
    let inferred_score = match decision.as_deref() {
        Some("input_blocked" | "output_blocked") => 92,
        Some("denied") => 78,
        Some("requires_review") => 56,
        Some("output_flagged") => 72,
        Some("allowed" | "approved") => 8,
        _ if filter_risk_count > 0 => 68,
        _ => 18,
    };
    let risk_score = anomaly
        .and_then(|anomaly| anomaly.get("score"))
        .and_then(Value::as_u64)
        .map(|score| score.min(100) as u8)
        .or(Some(inferred_score));
    let risk_level = anomaly
        .and_then(|anomaly| anomaly.get("risk_level"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| risk_score.map(risk_level_for_score));
    let scenario = payload
        .get("scenario")
        .or_else(|| value.get("scenario"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let threat_family = infer_threat_family(
        scenario.as_deref(),
        provider.as_deref(),
        decision.as_deref(),
        error_kind.as_deref(),
    );
    DemoEvent {
        kind,
        sequence: None,
        scenario,
        provider,
        action,
        decision,
        error_kind,
        reason: payload
            .get("reason")
            .or_else(|| value.get("reason"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        obs_ref: sealed_trace
            .and_then(|trace| trace.get("obs_id"))
            .or_else(|| payload.get("obs_ref"))
            .or_else(|| payload.get("obs_id"))
            .or_else(|| value.get("obs_ref"))
            .or_else(|| value.get("obs_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        approval_id: payload
            .get("approval_id")
            .or_else(|| value.get("approval_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        side_effect_executed: payload
            .get("side_effect_executed")
            .or_else(|| value.get("side_effect_executed"))
            .and_then(Value::as_bool),
        defense_layer,
        upstream_status: payload
            .get("upstream_status")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        risk_score,
        risk_level,
        threat_family,
        anomaly_reasons,
        data: redact_console_value(payload),
    }
}

fn event_argument_preview(event: &DemoEvent) -> Option<Value> {
    [
        "/data/argument_preview",
        "/argument_preview",
        "/payload/argument_preview",
    ]
    .into_iter()
    .find_map(|pointer| event.data.pointer(pointer))
    .cloned()
}

fn risk_level_for_score(score: u8) -> String {
    match score {
        0..=19 => "none",
        20..=39 => "low",
        40..=59 => "medium",
        60..=79 => "high",
        _ => "critical",
    }
    .to_string()
}

fn infer_threat_family(
    scenario: Option<&str>,
    provider: Option<&str>,
    decision: Option<&str>,
    error_kind: Option<&str>,
) -> Option<String> {
    let family = if let Some(scenario) = scenario {
        match scenario {
            "prompt-injection-file-exfil" => "indirect_prompt_injection",
            "tool-hijack-email-api" => "tool_hijack",
            "memory-knowledge-poisoning" => "memory_poisoning",
            "environment-local-web-risk" => "environment_pollution",
            "path-escape-file-boundary" => "path_escape",
            _ => "unknown",
        }
    } else if matches!(
        decision,
        Some("input_blocked" | "output_blocked" | "output_flagged")
    ) {
        "prompt_injection"
    } else if matches!(error_kind, Some("root_escape" | "scope_violation")) {
        "path_escape"
    } else if error_kind == Some("egress_denied") {
        "data_exfiltration"
    } else if provider
        .is_some_and(|provider| provider.contains("memory") || provider.contains("knowledge"))
    {
        "memory_poisoning"
    } else if provider
        .is_some_and(|provider| provider.contains("email") || provider.contains("api"))
    {
        "tool_hijack"
    } else {
        return None;
    };
    Some(family.to_string())
}

fn redact_console_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let normalized = key.to_ascii_lowercase();
                    let value = if [
                        "token",
                        "password",
                        "secret",
                        "api_key",
                        "authorization",
                        "cookie",
                        "credential",
                    ]
                    .iter()
                    .any(|sensitive| normalized.contains(sensitive))
                    {
                        Value::String("[REDACTED]".to_string())
                    } else {
                        redact_console_value(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_console_value).collect()),
        _ => value.clone(),
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

fn static_story_binding_error(
    value: &Value,
    scenario: &str,
    trace_events: &[TraceEvent],
) -> Option<String> {
    let verified = (|| -> anyhow::Result<()> {
        anyhow::ensure!(!trace_events.is_empty(), "scenario trace is empty");
        let story = value
            .get("story")
            .and_then(Value::as_object)
            .context("story is missing or not an object")?;
        let input_sha256 = story
            .get("input_sha256")
            .and_then(Value::as_str)
            .context("story is missing input_sha256")?;
        let attack_prompt = story
            .get("attack_prompt")
            .and_then(Value::as_str)
            .context("story is missing attack_prompt")?;
        anyhow::ensure!(
            hex_sha256(attack_prompt.as_bytes()) == input_sha256,
            "attack prompt does not match story input_sha256"
        );
        let script = story
            .get("agent_script")
            .and_then(Value::as_array)
            .context("story is missing agent_script")?;
        anyhow::ensure!(
            script.len() == trace_events.len(),
            "agent script length does not match trace"
        );

        for (index, (step, event)) in script.iter().zip(trace_events).enumerate() {
            let payload = event
                .payload
                .as_object()
                .with_context(|| format!("trace event {index} payload is not an object"))?;
            anyhow::ensure!(
                payload.get("scenario").and_then(Value::as_str) == Some(scenario),
                "trace event {index} is bound to another scenario"
            );
            anyhow::ensure!(
                payload.get("source_sha256").and_then(Value::as_str) == Some(input_sha256),
                "trace event {index} source hash does not match the story"
            );
            let expected_parent = index
                .checked_sub(1)
                .and_then(|previous| trace_events.get(previous))
                .map(|previous| previous.obs_id.as_str());
            anyhow::ensure!(
                payload.get("parent_obs_id").and_then(Value::as_str) == expected_parent,
                "trace event {index} parent observation is inconsistent"
            );
            let step = step
                .as_object()
                .with_context(|| format!("agent script step {index} is not an object"))?;
            anyhow::ensure!(
                step.get("provider") == payload.get("provider")
                    && step.get("action") == payload.get("action")
                    && step.get("arguments") == payload.get("arguments"),
                "agent script step {index} does not match the sealed trace intent"
            );
            anyhow::ensure!(
                event.provider.as_deref() == payload.get("provider").and_then(Value::as_str),
                "trace event {index} provider envelope differs from its payload"
            );
        }
        Ok(())
    })();
    verified.err().map(|error| format!("{error:#}"))
}

fn render_static_console_from_files(files: Vec<PathBuf>) -> anyhow::Result<String> {
    let mut events: Vec<DemoEvent> = Vec::new();
    let mut scenarios = Vec::new();
    let mut all_verified = true;
    let mut replay_errors = Vec::new();
    let mut scenario_event_count = 0usize;
    for file in files {
        let value = read_json_value(&file)?;
        let scenario = value["scenario"].as_str().unwrap_or("unknown");
        let trace_events: Vec<TraceEvent> = serde_json::from_value(
            value
                .get("trace")
                .cloned()
                .with_context(|| format!("{} is missing trace", file.display()))?,
        )
        .with_context(|| format!("parse scenario trace from {}", file.display()))?;
        let trace_verification = verify_trace_events(trace_events.clone());
        let report: ReportDraft = serde_json::from_value(
            value
                .get("report")
                .cloned()
                .with_context(|| format!("{} is missing report", file.display()))?,
        )
        .with_context(|| format!("parse scenario report from {}", file.display()))?;
        let lint = lint_report_against_trace(&report, &trace_events);
        let story_error = static_story_binding_error(&value, scenario, &trace_events);
        let scenario_verified = trace_verification["verified"].as_bool() == Some(true)
            && lint.ok
            && story_error.is_none();
        if !scenario_verified {
            replay_errors.push(json!({
                "scenario": scenario,
                "trace": &trace_verification,
                "lint": &lint,
                "story_error": &story_error
            }));
        }
        all_verified &= scenario_verified;
        scenario_event_count += trace_events.len();
        let denial_count = trace_events
            .iter()
            .filter(|event| event.payload["decision"] == "denied")
            .count();
        let review_count = trace_events
            .iter()
            .filter(|event| event.payload["decision"] == "requires_review")
            .count();
        scenarios.push(json!({
            "id": scenario,
            "family": infer_threat_family(Some(scenario), None, None, None),
            "story": value.get("story"),
            "metrics": value.get("metrics"),
            "security_metrics": value.get("security_metrics"),
            "trace_verification": trace_verification,
            "lint": lint,
            "replay_verified": scenario_verified,
            "story_binding_error": story_error,
            "denial_count": denial_count,
            "review_count": review_count,
            "call_count": trace_events.len()
        }));
        for trace_event in trace_events {
            events.push(demo_event_from_value(
                json!({
                    "kind": "provider_call",
                    "scenario": scenario,
                    "data": { "trace_event": trace_event }
                }),
                "provider_call",
            ));
        }
    }
    all_verified &= !scenarios.is_empty();
    for (index, event) in events.iter_mut().enumerate() {
        event.sequence = Some((index + 1) as u64);
    }
    let evidence = json!({
        "status": if all_verified { "partial" } else { "tampered" },
        "verified": false,
        "replay_verified": all_verified,
        "scope": "scenario_replay_without_model_trace",
        "scenario_trace": {
            "verified": all_verified,
            "event_count": scenario_event_count,
            "errors": replay_errors
        },
        "model_trace": {
            "verified": false,
            "event_count": 0,
            "status": "not_part_of_scenario_replay"
        },
        "side_effect_executed": events.iter().any(|event| event.side_effect_executed == Some(true))
    });
    let reviews = events
        .iter()
        .filter(|event| event.decision.as_deref() == Some("requires_review"))
        .map(|event| {
            json!({
                "approval_id": event.approval_id,
                "provider": event.provider,
                "action": event.action,
                "risk_level": event.risk_level,
                "reason": event.reason,
                "scenario": event.scenario,
                "obs_ref": event.obs_ref,
                "argument_preview": event_argument_preview(event),
                "anomaly_reasons": event.anomaly_reasons,
                "state": "evidence_replay"
            })
        })
        .collect::<Vec<_>>();
    let snapshot = json!({
        "schema_version": "runwarden.console.v2",
        "mode": "replay",
        "cursor": events.len(),
        "system": {
            "name": "Runwarden Causal Defense Fabric",
            "enforcement": "deterministic_replay",
            "agent_tool_boundary": "runwarden-mcp",
            "model_boundary": "runwarden-llm-proxy"
        },
        "summary": summarize_events(&events, reviews.len(), &evidence),
        "events": events,
        "reviews": reviews,
        "scenarios": scenarios,
        "evidence": evidence,
        "defense_layers": defense_layer_counts(&events)
    });
    let bootstrap = script_safe_json(&snapshot)?;
    Ok(CONSOLE_HTML.replace(
        "window.RUNWARDEN_BOOTSTRAP = null;",
        &format!("window.RUNWARDEN_BOOTSTRAP = {bootstrap};"),
    ))
}

fn script_safe_json(value: &Value) -> anyhow::Result<String> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

fn read_json_value(path: &Path) -> anyhow::Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn read_trace(path: &Path) -> anyhow::Result<Vec<TraceEvent>> {
    anyhow::ensure!(path.exists(), "trace file not found: {}", path.display());
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
    if event_count == 0 {
        return json!({
            "verified": false,
            "error": "no trace events",
            "event_count": 0
        });
    }
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
    fn reviewer_session_requires_capability_host_and_origin() {
        let session = ReviewerSession {
            token: "a".repeat(64),
            reviewer_id: "reviewer-session-test".to_string(),
            expected_host: "127.0.0.1:8088".to_string(),
            expected_origin: "http://127.0.0.1:8088".to_string(),
        };
        let mut valid = HeaderMap::new();
        valid.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8088"));
        valid.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8088"),
        );
        valid.insert(
            "x-runwarden-reviewer-token",
            HeaderValue::from_str(&"a".repeat(64)).expect("token header"),
        );
        valid.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(session.authorize(&valid).is_ok());

        for header_name in [
            "x-runwarden-reviewer-token",
            header::HOST.as_str(),
            header::ORIGIN.as_str(),
        ] {
            let mut invalid = valid.clone();
            invalid.remove(header_name);
            assert!(
                session.authorize(&invalid).is_err(),
                "missing {header_name}"
            );
        }
        let mut cross_site = valid;
        cross_site.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(session.authorize(&cross_site).is_err());
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"different"));
    }

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
        let approval_events =
            read_trace(&dir.path().join("approval-events.jsonl")).expect("approval audit trace");
        assert_eq!(approval_events.len(), 1);
        assert_eq!(verify_trace_events(approval_events)["verified"], true);
        let snapshot = build_live_snapshot(&state).expect("snapshot after approval");
        assert_eq!(snapshot["reviews"][0]["state"], "approved");
        assert_eq!(snapshot["evidence"]["approval_trace"]["verified"], true);
        assert_eq!(snapshot["evidence"]["approval_ledger"]["verified"], true);
    }

    #[test]
    fn approval_ledger_requires_and_matches_authoritative_decision_audit() {
        let dir = tempfile::tempdir().expect("state dir");
        let approvals_dir = dir.path().join("approvals");
        fs::create_dir_all(&approvals_dir).expect("approvals dir");
        let mut approval = ApprovalRecord::new(
            "approval-audit-binding",
            ApprovalBinding {
                session_id: "session-a".to_string(),
                provider: "external.email.send".to_string(),
                action: "send".to_string(),
                argument_hash: "argument-a".to_string(),
                authz_id: None,
                actor_id: Some("actor-a".to_string()),
            },
        );
        approval
            .approve("reviewer-a", "exact call reviewed")
            .expect("approve");
        let record_path = approvals_dir.join("approval-audit-binding.json");
        persist_approval_record(&record_path, &approval).expect("persist approved record");
        let missing = verify_approval_ledger_against_audit(
            dir.path(),
            &[approval.clone()],
            &Default::default(),
        );
        assert_eq!(missing["verified"], false);

        let (tx, _) = broadcast::channel(1);
        let state = AppState {
            event_tx: tx,
            state_dir: dir.path().to_path_buf(),
            trace_path: dir.path().join("model.jsonl"),
        };
        assert_eq!(trace_overview(&state)["status"], "tampered");
        append_approval_decision_event(&state, &approval).expect("append decision audit");
        let matched = verify_approval_ledger_against_audit(
            dir.path(),
            &[approval.clone()],
            &Default::default(),
        );
        assert_eq!(matched["verified"], true);

        approval.reason = Some("hand-edited after review".to_string());
        persist_approval_record(&record_path, &approval).expect("persist tampered record");
        let tampered =
            verify_approval_ledger_against_audit(dir.path(), &[approval], &Default::default());
        assert_eq!(tampered["verified"], false);
        assert!(
            tampered["errors"][0]
                .as_str()
                .is_some_and(|error| error.contains("digest"))
        );
    }

    #[test]
    fn provider_approval_reference_requires_a_ledger_record() {
        let dir = tempfile::tempdir().expect("state dir");
        let events_path = dir.path().join("events.jsonl");
        fs::write(&events_path, "{\"approval_id\":\"approval-deleted\"}\n")
            .expect("provider reference");
        let required = provider_trace_approval_ids(&events_path).expect("approval ids");
        let result = verify_approval_ledger_against_audit(dir.path(), &[], &required);
        assert_eq!(result["verified"], false);
        assert_eq!(result["ledger_required"], true);
        assert_eq!(
            result["missing_provider_approval_records"][0],
            "approval-deleted"
        );
    }

    #[test]
    fn concurrent_approve_and_deny_commit_exactly_one_audited_decision() {
        let dir = tempfile::tempdir().expect("state dir");
        let approvals_dir = dir.path().join("approvals");
        fs::create_dir_all(&approvals_dir).expect("approvals dir");
        let approval = ApprovalRecord::new(
            "webui-obs_race",
            ApprovalBinding {
                session_id: "mcp-inline".to_string(),
                provider: "external.email.send".to_string(),
                action: "call".to_string(),
                argument_hash: "race-hash".to_string(),
                authz_id: None,
                actor_id: Some("mcp-agent".to_string()),
            },
        );
        fs::write(
            approvals_dir.join("webui-obs_race.json"),
            serde_json::to_vec_pretty(&approval).expect("approval json"),
        )
        .expect("write approval");
        let (tx, _) = broadcast::channel(4);
        let state = AppState {
            event_tx: tx,
            state_dir: dir.path().to_path_buf(),
            trace_path: dir.path().join("trace.jsonl"),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let results = std::thread::scope(|scope| {
            let approve_state = state.clone();
            let approve_barrier = barrier.clone();
            let approve = scope.spawn(move || {
                approve_barrier.wait();
                decide_approval_record(
                    &approve_state,
                    "webui-obs_race",
                    true,
                    "reviewer-a",
                    "approve once",
                )
            });
            let deny_state = state.clone();
            let deny_barrier = barrier.clone();
            let deny = scope.spawn(move || {
                deny_barrier.wait();
                decide_approval_record(
                    &deny_state,
                    "webui-obs_race",
                    false,
                    "reviewer-b",
                    "deny once",
                )
            });
            barrier.wait();
            [
                approve.join().expect("approve thread"),
                deny.join().expect("deny thread"),
            ]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let saved: ApprovalRecord = serde_json::from_slice(
            &fs::read(approvals_dir.join("webui-obs_race.json")).expect("saved approval"),
        )
        .expect("saved approval json");
        assert!(matches!(
            saved.state,
            ApprovalState::Approved | ApprovalState::Denied
        ));
        let audit = read_trace(&dir.path().join("approval-events.jsonl")).expect("audit trace");
        assert_eq!(audit.len(), 1);
        assert_eq!(verify_trace_events(audit)["verified"], true);
    }

    #[test]
    fn provider_trace_verification_rejects_event_lines_without_trace_event() {
        let dir = tempfile::tempdir().expect("state dir");
        let path = dir.path().join("events.jsonl");
        let mut valid_event = json!({
            "kind": "provider_call",
            "provider": "external.email.send",
            "action": "call",
            "decision": "allowed",
            "error_kind": null,
            "reason": "completed",
            "obs_ref": "obs_console_trace",
            "approval_id": null,
            "side_effect_executed": true,
            "data": {
                "provider": "external.email.send",
                "action": "call",
                "decision": "allowed",
                "side_effect_executed": true
            }
        });
        let binding = provider_event_binding_digest(&valid_event).expect("event binding");
        let trace_event = TraceEvent::sealed(
            "obs_console_trace".to_string(),
            "provider_completed".to_string(),
            Some("external.email.send".to_string()),
            json!({
                "decision": "allowed",
                "side_effect_executed": true,
                "provider_event_binding": {
                    "schema_version": "runwarden.provider-event-binding.v1",
                    "canonical_event_sha256": binding
                }
            }),
            None,
        );
        valid_event["data"]["trace_event"] =
            serde_json::to_value(trace_event).expect("trace event");
        fs::write(
            &path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&valid_event).expect("valid event"),
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
    fn provider_trace_verification_rejects_tampered_event_wrapper() {
        let dir = tempfile::tempdir().expect("state dir");
        let path = dir.path().join("events.jsonl");
        let mut event = json!({
            "kind": "provider_call",
            "provider": "external.email.send",
            "action": "call",
            "decision": "allowed",
            "error_kind": null,
            "reason": "completed",
            "obs_ref": "obs_bound",
            "approval_id": "webui-obs_bound",
            "side_effect_executed": true,
            "data": {
                "provider": "external.email.send",
                "action": "call",
                "decision": "allowed",
                "output": {
                    "redacted": true,
                    "type": "object",
                    "bytes": 23,
                    "sha256": "mail-output-digest"
                },
                "side_effect_executed": true,
                "execution_reservation_id": "exec-1",
                "approval_id": "webui-obs_bound",
                "argument_preview": {"to": {"redacted": true, "sha256": "recipient"}},
                "anomaly": {"score": 8}
            }
        });
        let binding = provider_event_binding_digest(&event).expect("event binding");
        event["data"]["trace_event"] = serde_json::to_value(TraceEvent::sealed(
            "obs_bound".to_string(),
            "provider_completed".to_string(),
            Some("external.email.send".to_string()),
            json!({
                "provider": "external.email.send",
                "action": "call",
                "decision": "allowed",
                "side_effect_executed": true,
                "provider_event_binding": {
                    "schema_version": "runwarden.provider-event-binding.v1",
                    "canonical_event_sha256": binding
                }
            }),
            None,
        ))
        .expect("trace event");
        fs::write(
            &path,
            format!(
                "{}\n",
                serde_json::to_string(&event).expect("provider event")
            ),
        )
        .expect("provider trace");
        assert_eq!(provider_trace_verify_result(&path)["verified"], true);

        let mut event: Value =
            serde_json::from_str(fs::read_to_string(&path).expect("provider trace").trim())
                .expect("provider event");
        event["decision"] = json!("denied");
        event["side_effect_executed"] = json!(false);
        fs::write(
            &path,
            format!(
                "{}\n",
                serde_json::to_string(&event).expect("tampered event")
            ),
        )
        .expect("tampered trace");

        let result = provider_trace_verify_result(&path);
        assert_eq!(result["verified"], false);
        assert!(
            result["error"]
                .as_str()
                .is_some_and(|error| error.contains("sealed trace binding"))
        );
    }

    #[test]
    fn live_snapshot_correlates_redacted_preview_with_pending_review() {
        let dir = tempfile::tempdir().expect("state dir");
        let approvals_dir = dir.path().join("approvals");
        fs::create_dir_all(&approvals_dir).expect("approvals dir");
        let mut approval = ApprovalRecord::new(
            "anomaly-obs_preview",
            ApprovalBinding {
                session_id: "session-a".to_string(),
                provider: "external.email.send".to_string(),
                action: "call".to_string(),
                argument_hash: "sha256-arguments".to_string(),
                authz_id: None,
                actor_id: Some("agent-a".to_string()),
            },
        );
        approval.reason = Some("dynamic behavior anomaly review".to_string());
        fs::write(
            approvals_dir.join("anomaly-obs_preview.json"),
            serde_json::to_string(&approval).expect("approval"),
        )
        .expect("approval file");

        let provider_event = json!({
            "kind": "provider_call",
            "provider": "external.email.send",
            "action": "call",
            "decision": "requires_review",
            "reason": "behavior-risk requires review",
            "obs_ref": "obs_preview",
            "approval_id": "anomaly-obs_preview",
            "side_effect_executed": false,
            "data": {
                "argument_preview": {
                    "to": "reviewer@example.com",
                    "content": {"redacted": true, "bytes": 42, "sha256": "digest"}
                },
                "anomaly": {
                    "score": 75,
                    "risk_level": "high",
                    "reasons": ["sensitive source reached external sink"]
                }
            }
        });
        fs::write(
            dir.path().join("events.jsonl"),
            format!(
                "{}\n",
                serde_json::to_string(&provider_event).expect("event")
            ),
        )
        .expect("events");
        let (tx, _) = broadcast::channel(1);
        let state = AppState {
            event_tx: tx,
            state_dir: dir.path().to_path_buf(),
            trace_path: dir.path().join("model.jsonl"),
        };

        let snapshot = build_live_snapshot(&state).expect("snapshot");
        let review = &snapshot["reviews"][0];
        assert_eq!(review["approval_id"], "anomaly-obs_preview");
        assert_eq!(review["obs_ref"], "obs_preview");
        assert_eq!(review["risk_score"], 75);
        assert_eq!(review["argument_preview"]["to"], "reviewer@example.com");
        assert_eq!(review["argument_preview"]["content"]["redacted"], true);
    }

    #[test]
    fn console_bootstraps_snapshot_and_reconciles_after_page_load() {
        assert!(CONSOLE_HTML.contains("/api/console/snapshot"));
        assert!(CONSOLE_HTML.contains("setInterval(reconcile,30000)"));
        assert!(CONSOLE_HTML.contains("reconcile().then(renderConnection)"));
        assert!(!CONSOLE_HTML.contains("addLiveEvent(JSON.parse"));
        assert!(CONSOLE_HTML.contains("window.RUNWARDEN_BOOTSTRAP = null;"));
        assert!(!CONSOLE_HTML.contains("innerHTML"));
    }

    #[test]
    fn static_bootstrap_escapes_script_closing_attack_text() {
        let value = json!({
            "story": {"attack_prompt": "</script><img src=x onerror=alert(1)>"}
        });
        let encoded = script_safe_json(&value).expect("safe JSON");
        assert!(!encoded.contains("</script>"));
        assert!(encoded.contains("\\u003c/script>"));
        assert!(encoded.contains("\\u003cimg"));
    }

    #[test]
    fn static_replay_recomputes_trace_lint_and_story_binding() {
        let dir = tempfile::tempdir().expect("replay dir");
        let path = dir.path().join("webui.json");
        let prompt = "adversarial fixture";
        let trace_event = TraceEvent::sealed(
            "obs_replay".to_string(),
            "provider_completed".to_string(),
            Some("runwarden.input.inspect".to_string()),
            json!({
                "scenario": "static-replay",
                "source_sha256": hex_sha256(prompt.as_bytes()),
                "parent_obs_id": null,
                "provider": "runwarden.input.inspect",
                "action": "inspect",
                "arguments": {"input_path": "attacks/prompt.md"},
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false
            }),
            None,
        );
        let mut webui = json!({
            "scenario": "static-replay",
            "story": {
                "input_sha256": hex_sha256(prompt.as_bytes()),
                "attack_prompt": prompt,
                "agent_script": [{
                    "provider": "runwarden.input.inspect",
                    "action": "inspect",
                    "arguments": {"input_path": "attacks/prompt.md"}
                }]
            },
            "trace": [&trace_event],
            "provider_calls": [{"provider": "forged-provider", "decision": "denied"}],
            "trace_verification": {"verified": true},
            "lint": {"ok": true},
            "report": {"claims": [{
                "id": "claim-replay",
                "text": "Input inspection completed.",
                "obs_refs": ["obs_replay"],
                "support": {
                    "provider": "runwarden.input.inspect",
                    "event_type": "provider_completed",
                    "decision": "allowed",
                    "execution_status": "completed",
                    "side_effect_executed": false
                }
            }]}
        });
        fs::write(&path, serde_json::to_vec_pretty(&webui).unwrap()).expect("write replay");

        let verified = render_static_console_from_files(vec![path.clone()]).expect("console");

        assert!(verified.contains("\"status\":\"partial\""));
        assert!(verified.contains("\"replay_verified\":true"));
        assert!(!verified.contains("forged-provider"));

        webui["story"]["attack_prompt"] = json!("tampered fixture");
        fs::write(&path, serde_json::to_vec_pretty(&webui).unwrap()).expect("tamper replay");
        let tampered = render_static_console_from_files(vec![path]).expect("tampered console");
        assert!(tampered.contains("\"status\":\"tampered\""));
        assert!(tampered.contains("\"replay_verified\":false"));
    }

    #[test]
    fn evidence_overview_does_not_treat_one_verified_chain_as_fully_verified() {
        let dir = tempfile::tempdir().expect("state dir");
        let trace_path = dir.path().join("model.jsonl");
        let event = TraceEvent::sealed(
            "obs_model".to_string(),
            "model_call".to_string(),
            None,
            json!({"decision": "allowed"}),
            None,
        );
        fs::write(
            &trace_path,
            format!("{}\n", serde_json::to_string(&event).unwrap()),
        )
        .expect("model trace");
        let (tx, _) = broadcast::channel(1);
        let state = AppState {
            event_tx: tx,
            state_dir: dir.path().join("state"),
            trace_path,
        };
        let overview = trace_overview(&state);
        assert_eq!(overview["status"], "partial");
        assert_eq!(overview["verified"], false);
    }

    #[test]
    fn empty_or_malformed_model_trace_is_never_verified() {
        for (body, expected_status) in [("", "empty"), ("{not-json}\n", "tampered")] {
            let dir = tempfile::tempdir().expect("state dir");
            let trace_path = dir.path().join("model.jsonl");
            fs::write(&trace_path, body).expect("model trace");
            let (tx, _) = broadcast::channel(1);
            let state = AppState {
                event_tx: tx,
                state_dir: dir.path().join("state"),
                trace_path,
            };

            let overview = trace_overview(&state);

            assert_eq!(overview["model_trace"]["verified"], false);
            assert_eq!(overview["verified"], false);
            assert_eq!(overview["status"], expected_status);
        }
    }

    #[test]
    fn snapshot_survives_corrupt_jsonl_and_surfaces_ingestion_error() {
        let dir = tempfile::tempdir().expect("state dir");
        let trace_path = dir.path().join("model.jsonl");
        fs::write(&trace_path, "{not-json}\n").expect("corrupt model trace");
        let (tx, _) = broadcast::channel(1);
        let state = AppState {
            event_tx: tx,
            state_dir: dir.path().join("state"),
            trace_path,
        };

        let snapshot = build_live_snapshot(&state).expect("degraded snapshot");

        assert_eq!(snapshot["ingestion"]["ok"], false);
        assert_eq!(snapshot["evidence"]["status"], "tampered");
        assert!(snapshot["events"].as_array().is_some_and(Vec::is_empty));
    }

    #[test]
    fn console_event_uses_sealed_payload_instead_of_mutable_outer_fields() {
        let trace_event = TraceEvent::sealed(
            "obs_sealed".to_string(),
            "provider_denied".to_string(),
            Some("external.api.request".to_string()),
            json!({
                "provider": "external.api.request",
                "action": "request",
                "decision": "denied",
                "reason": "sealed denial",
                "error_kind": "egress_denied",
                "side_effect_executed": false
            }),
            None,
        );
        let event = demo_event_from_value(
            json!({
                "kind": "provider_call",
                "provider": "forged.provider",
                "action": "forged",
                "decision": "allowed",
                "reason": "forged success",
                "obs_ref": "obs_forged",
                "side_effect_executed": true,
                "data": {"trace_event": trace_event}
            }),
            "provider_call",
        );

        assert_eq!(event.provider.as_deref(), Some("external.api.request"));
        assert_eq!(event.action.as_deref(), Some("request"));
        assert_eq!(event.decision.as_deref(), Some("denied"));
        assert_eq!(event.reason.as_deref(), Some("sealed denial"));
        assert_eq!(event.obs_ref.as_deref(), Some("obs_sealed"));
        assert_eq!(event.side_effect_executed, Some(false));
        assert_eq!(event.data["decision"], "denied");
    }
}
