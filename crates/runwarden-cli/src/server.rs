use std::{
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::Context;
use axum::{
    Json, Router,
    http::{HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use runwarden_cli::web_server::{ReviewerApiState, reviewer_router, reviewer_state_for_listener};
use runwarden_kernel::story::StoryId;
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const CONSOLE_HTML: &str = include_str!("console.html");

pub struct DemoLaunchInfo {
    pub story_id: StoryId,
    pub state_dir: PathBuf,
    pub instance_token: Zeroizing<String>,
    pub sandbox_root: PathBuf,
    pub trusted_runtime_root: PathBuf,
}

pub struct PreparedConsoleServer {
    runtime: tokio::runtime::Runtime,
    listener: tokio::net::TcpListener,
    listen_addr: SocketAddr,
    reviewer_state: ReviewerApiState,
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

pub fn prepare_console_server(
    bind: &str,
    port: u16,
    state_dir: &Path,
) -> anyhow::Result<PreparedConsoleServer> {
    let bind_ip: IpAddr = bind
        .parse()
        .context("reviewer bind must be an IP address")?;
    anyhow::ensure!(
        bind_ip.is_loopback(),
        "reviewer server must bind a loopback address"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind((bind_ip, port)))
        .context("bind reviewer listener")?;
    let listen_addr = listener.local_addr()?;
    let reviewer_state = reviewer_state_for_listener(state_dir, listen_addr)?;
    Ok(PreparedConsoleServer {
        runtime,
        listener,
        listen_addr,
        reviewer_state,
    })
}

pub fn run_console_server(
    prepared: PreparedConsoleServer,
    launch: DemoLaunchInfo,
    json_output: bool,
) -> anyhow::Result<()> {
    let PreparedConsoleServer {
        runtime,
        listener,
        listen_addr: addr,
        reviewer_state,
    } = prepared;
    runtime.block_on(async move {
        let state_dir = launch
            .state_dir
            .to_str()
            .context("interactive state directory is not UTF-8")?;
        let sandbox_root = launch
            .sandbox_root
            .to_str()
            .context("interactive sandbox root is not UTF-8")?;
        let trusted_runtime_root = launch
            .trusted_runtime_root
            .to_str()
            .context("trusted runtime root is not UTF-8")?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "mode": "interactive_demo",
                    "listen_addr": addr.to_string(),
                    "url": format!("http://{addr}"),
                    "events_url": format!(
                        "http://{addr}/events?story_id={}&after_seq=0",
                        launch.story_id
                    ),
                    "story_id": launch.story_id,
                    "trusted_mcp_environment": {
                        "RUNWARDEN_STATE_DIR": state_dir,
                        "RUNWARDEN_INSTANCE_TOKEN": launch.instance_token.as_str(),
                        "RUNWARDEN_SANDBOX_ROOT": sandbox_root,
                        "RUNWARDEN_TRUSTED_RUNTIME_ROOT": trusted_runtime_root
                    },
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
            println!("  # Sensitive trusted launcher values; do not share them with the agent.");
            println!("  export RUNWARDEN_STATE_DIR={}", shell_quote(state_dir));
            println!(
                "  export RUNWARDEN_INSTANCE_TOKEN={}",
                shell_quote(launch.instance_token.as_str())
            );
            println!("  export RUNWARDEN_SANDBOX_ROOT={}", shell_quote(sandbox_root));
            println!(
                "  export RUNWARDEN_TRUSTED_RUNTIME_ROOT={}",
                shell_quote(trusted_runtime_root)
            );
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

        drop(launch);

        let reviewer_routes = reviewer_router(reviewer_state);
        let console_routes = Router::new()
            .route("/", get(|| async { console_response() }))
            .route("/healthz", get(|| async { Json(json!({"ok": true})) }));
        let app = console_routes.merge(reviewer_routes);
        axum::serve(listener, app).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

fn console_response() -> Response {
    let mut response = Html(CONSOLE_HTML).into_response();
    let headers: &mut HeaderMap = response.headers_mut();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "cache-control",
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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
    let events_json = inline_script_json(&events)?;
    Ok(CONSOLE_HTML.replace(
        "window.STATIC_EVENTS = null;",
        &format!("window.STATIC_EVENTS = {events_json};"),
    ))
}

fn inline_script_json(value: &impl Serialize) -> anyhow::Result<String> {
    Ok(serde_json::to_string(value)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

fn read_json_value(path: &Path) -> anyhow::Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_bootstraps_native_api_and_never_calls_legacy_approval_routes() {
        assert!(CONSOLE_HTML.contains("fetch('/api/bootstrap')"));
        assert!(CONSOLE_HTML.contains("addEventListener('story_event'"));
        assert!(CONSOLE_HTML.contains("X-Runwarden-Reviewer-Nonce"));
        assert!(CONSOLE_HTML.contains("expected_approval_version"));
        assert!(CONSOLE_HTML.contains("expected_operation_version"));
        assert!(CONSOLE_HTML.contains("source.readyState === EventSource.CLOSED"));
        assert!(!CONSOLE_HTML.contains("fetch('/api/pending')"));
        assert!(!CONSOLE_HTML.contains("fetch('/api/approve')"));
        assert!(!CONSOLE_HTML.contains("fetch('/api/deny')"));
        assert!(!CONSOLE_HTML.contains("fetch('/api/trace/verify')"));
        assert!(!CONSOLE_HTML.contains("new EventSource('/events')"));
    }

    #[test]
    fn static_console_json_cannot_terminate_its_script_element() {
        let encoded = inline_script_json(&json!({
            "value": "</script><script>alert('&')\u{2028}\u{2029}"
        }))
        .unwrap();
        assert!(!encoded.contains('<'));
        assert!(!encoded.contains('>'));
        assert!(!encoded.contains('&'));
        assert!(!encoded.contains('\u{2028}'));
        assert!(!encoded.contains('\u{2029}'));
        assert!(encoded.contains("\\u003c/script\\u003e"));
    }

    #[test]
    fn shell_quote_keeps_single_quotes_inside_one_argument() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn live_console_cannot_be_framed_or_cached() {
        let response = console_response();
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["cache-control"], "no-store, max-age=0");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }
}
