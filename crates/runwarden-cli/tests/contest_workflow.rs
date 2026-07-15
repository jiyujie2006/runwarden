use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
};

use runwarden_mcp::handle_jsonrpc_body;
use serde_json::Value;
use serde_json::json;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn demo_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn restore_env(key: &str, value: Option<OsString>) {
    unsafe {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }
}

#[test]
fn check_strict_runs_scenario_eval_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["check", "--strict", "--json"])
        .output()
        .expect("run strict check");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""suite": "contest-red-team-scenarios""#));
    assert!(stdout.contains(r#""case_count": 5"#));
    assert!(stdout.contains(r#""passed": true"#));
}

#[test]
fn demo_scenario_writes_real_trace_report_and_webui_json() {
    let workspace = workspace_root();
    let output_dir = PathBuf::from("target/runwarden-contest-test/prompt-injection-file-exfil");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "--scenario",
            "prompt-injection-file-exfil",
            "--output",
        ])
        .arg(&output_dir)
        .arg("--json")
        .output()
        .expect("run demo scenario");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(absolute_output.join("trace.json").exists());
    assert!(absolute_output.join("report.json").exists());
    assert!(absolute_output.join("webui.json").exists());
    let webui: Value = serde_json::from_str(
        &fs::read_to_string(absolute_output.join("webui.json")).expect("webui"),
    )
    .expect("webui json");
    assert_eq!(webui["trace_verification"]["verified"], true);
    assert_eq!(webui["provider_calls"][1]["decision"], "requires_review");
    assert_eq!(webui["provider_calls"][2]["decision"], "denied");
    assert_eq!(webui["provider_calls"][2]["side_effect_executed"], false);
    assert_eq!(webui["story"]["input_path"], "attacks/prompt-injection.md");
    assert!(
        webui["story"]["attack_prompt"]
            .as_str()
            .is_some_and(|prompt| prompt.contains("Ignore policy"))
    );
    assert_eq!(webui["security_metrics"]["attack_success_rate"], 0.0);
    assert_eq!(webui["security_metrics"]["containment_rate"], 1.0);
    assert_eq!(webui["security_metrics"]["passed"], true);
    assert_eq!(webui["security_metrics"]["total"], 2);
    assert_eq!(webui["security_metrics"]["malicious"], 1);
    assert_eq!(webui["security_metrics"]["benign"], 1);
    assert_eq!(
        webui["security_evaluation"]["method"],
        "one_attack_story_plus_independent_benign_control"
    );
    assert_eq!(
        webui["security_evaluation"]["benign_control"]["fixture"],
        "benign/request.md"
    );
    assert_eq!(
        webui["security_evaluation"]["benign_control"]["actual_decision"],
        "allowed"
    );
    assert_eq!(
        webui["security_evaluation"]["benign_control"]["inspection_risk_count"],
        0
    );
    assert_eq!(
        webui["security_evaluation"]["cases"][0]["id"],
        "prompt-injection-file-exfil-attack-story"
    );
    assert_eq!(
        webui["security_evaluation"]["cases"][1]["id"],
        "prompt-injection-file-exfil-benign-control"
    );
    assert_eq!(webui["provider_calls"][2]["anomaly"]["score"], 0);
    assert!(
        webui["provider_calls"][2]["anomaly"]["history"]
            .as_array()
            .is_some_and(|history| history.iter().all(|observation| {
                observation["provider"] != "external.mcp.filesystem.read_file"
            })),
        "a review-blocked read must not poison the committed behavior history"
    );
}

#[test]
fn demo_all_writes_static_reviewer_console() {
    let workspace = workspace_root();
    let output_dir = PathBuf::from("target/runwarden-contest-test/demo-all");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);
    let stale_dir = absolute_output.join("anomalous-provider-sequence");
    fs::create_dir_all(&stale_dir).expect("stale dir");
    fs::write(
        stale_dir.join("webui.json"),
        r#"{"scenario":"anomalous-provider-sequence","provider_calls":[{"provider":"external.api.request","action":"call","decision":"denied","side_effect_executed":false}]}"#,
    )
    .expect("stale webui");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["demo", "--all", "--output"])
        .arg(&output_dir)
        .arg("--json")
        .output()
        .expect("run all demos");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let html = fs::read_to_string(absolute_output.join("reviewer-console.html")).expect("html");
    assert!(html.contains("Runwarden"));
    assert!(html.contains("STATIC_EVENTS"));
    assert!(html.contains("prompt-injection-file-exfil"));
    assert!(html.contains("requires_review"));
    assert!(!html.contains("anomalous-provider-sequence"));
    assert!(!html.contains("insertAdjacentHTML"));
    assert!(!html.contains("innerHTML"));

    let environment: Value = serde_json::from_str(
        &fs::read_to_string(
            absolute_output
                .join("environment-local-web-risk")
                .join("webui.json"),
        )
        .expect("environment webui"),
    )
    .expect("environment webui json");
    assert!(
        environment["provider_calls"][1]["anomaly"]["score"]
            .as_u64()
            .is_some_and(|score| score >= 25),
        "the novel localhost egress attempt should remain explainably anomalous"
    );
}

#[cfg(unix)]
#[test]
fn demo_output_allows_in_workspace_symlink_and_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let workspace = workspace_root();
    let base = workspace.join("target/runwarden-contest-test/symlink-output");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("base dir");

    let inside_target = base.join("inside-target");
    let inside_link = base.join("inside-link");
    fs::create_dir_all(&inside_target).expect("inside target");
    let _ = fs::remove_file(&inside_link);
    symlink(&inside_target, &inside_link).expect("inside symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "--scenario",
            "prompt-injection-file-exfil",
            "--output",
        ])
        .arg(PathBuf::from(
            "target/runwarden-contest-test/symlink-output/inside-link",
        ))
        .arg("--json")
        .output()
        .expect("run demo through in-root symlink");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(inside_target.join("webui.json").exists());

    let outside_target =
        std::env::temp_dir().join(format!("runwarden-output-escape-{}", std::process::id()));
    let _ = fs::remove_dir_all(&outside_target);
    fs::create_dir_all(&outside_target).expect("outside target");
    let escape_link = base.join("escape-link");
    let _ = fs::remove_file(&escape_link);
    symlink(&outside_target, &escape_link).expect("escape symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "--scenario",
            "prompt-injection-file-exfil",
            "--output",
        ])
        .arg(PathBuf::from(
            "target/runwarden-contest-test/symlink-output/escape-link",
        ))
        .arg("--json")
        .output()
        .expect("run demo through escaping symlink");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("workspace"));
}

#[test]
fn output_path_rejections_preserve_command_labels() {
    let workspace = workspace_root();

    let demo = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "--scenario",
            "prompt-injection-file-exfil",
            "--output",
            "../escape",
            "--json",
        ])
        .output()
        .expect("run demo with invalid output");
    assert!(!demo.status.success());
    assert!(
        String::from_utf8_lossy(&demo.stderr)
            .contains("demo output path must be a relative path inside the workspace")
    );

    let report = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "report",
            "render",
            "--scenario-suite",
            "scenarios",
            "--format",
            "markdown",
            "--output",
            "../contest-report.md",
            "--json",
        ])
        .output()
        .expect("run report with invalid output");
    assert!(!report.status.success());
    assert!(
        String::from_utf8_lossy(&report.stderr)
            .contains("report output path must be a relative path inside the workspace")
    );
}

#[test]
fn demo_interactive_serves_console_and_healthz() {
    let _guard = demo_lock().lock().expect("demo lock");
    let workspace = workspace_root();
    let mut child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["demo", "--port", "0", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn demo server");

    let startup = read_startup_json(&mut child);
    let listen_addr = startup["listen_addr"]
        .as_str()
        .expect("listen_addr")
        .to_string();
    let state_dir = PathBuf::from(startup["state_dir"].as_str().expect("run-scoped state_dir"));
    assert_eq!(startup["mode"], "interactive_demo");

    let snapshot = http_json(&listen_addr, "GET", "/api/console/snapshot", None);
    assert_eq!(snapshot["schema_version"], "runwarden.console.v2");
    assert_eq!(snapshot["mode"], "live");
    assert!(snapshot["events"].is_array());
    assert!(
        snapshot["scenarios"]
            .as_array()
            .is_some_and(|items| items.len() == 5)
    );

    let mut stream = TcpStream::connect(&listen_addr).expect("connect demo server");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    child.kill().expect("kill demo server");
    child.wait().expect("wait demo server");
    let _ = fs::remove_dir_all(state_dir);

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains(r#"{"ok":true}"#));
}

#[test]
fn demo_interactive_approval_http_to_mcp_retry_closed_loop() {
    let _guard = demo_lock().lock().expect("demo lock");
    let workspace = workspace_root();
    let sandbox_root = workspace.join("target/runwarden-contest-test/live-console-sandbox");
    let _ = fs::remove_dir_all(&sandbox_root);

    let mut child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["demo", "--port", "0", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn demo server");

    let startup = read_startup_json(&mut child);
    let listen_addr = startup["listen_addr"]
        .as_str()
        .expect("listen_addr")
        .to_string();
    let state_dir = PathBuf::from(startup["state_dir"].as_str().expect("run-scoped state_dir"));
    let reviewer_token = startup["reviewer_url"]
        .as_str()
        .and_then(|url| url.rsplit_once("review_token=").map(|(_, token)| token))
        .expect("reviewer token")
        .to_string();

    let old_state = std::env::var_os("RUNWARDEN_STATE_DIR");
    let old_sandbox = std::env::var_os("RUNWARDEN_SANDBOX_ROOT");
    let old_session = std::env::var_os("RUNWARDEN_SESSION_ID");
    let old_actor = std::env::var_os("RUNWARDEN_ACTOR_ID");
    unsafe {
        std::env::set_var("RUNWARDEN_STATE_DIR", &state_dir);
        std::env::set_var("RUNWARDEN_SANDBOX_ROOT", &sandbox_root);
        std::env::set_var("RUNWARDEN_SESSION_ID", "contest-http-closed-loop");
        std::env::set_var("RUNWARDEN_ACTOR_ID", "contest-integration-agent");
    }

    let arguments = json!({
        "provider": "external.email.send",
        "to": "ops@example.com",
        "subject": "closed loop"
    });
    let first = call_mcp_tool(901, "runwarden.provider.call", arguments.clone());
    let first_payload = mcp_tool_payload(&first);
    assert_eq!(first["result"]["isError"], true);
    assert_eq!(first_payload["decision"], "requires_review");
    assert_eq!(first_payload["side_effect_executed"], false);
    let approval_id = first_payload["approval_id"]
        .as_str()
        .expect("approval id")
        .to_string();

    let pending = http_json(&listen_addr, "GET", "/api/pending", None);
    assert!(
        pending["pending"]
            .as_array()
            .expect("pending array")
            .iter()
            .any(|approval| approval["approval_id"] == approval_id)
    );

    let forged_body = r#"{"decision":"approve","reason":"forged"}"#;
    let unauthorized_request = format!(
        "POST /api/approvals/{approval_id}/decision HTTP/1.1\r\nHost: {listen_addr}\r\nOrigin: http://{listen_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{forged_body}",
        forged_body.len()
    );
    let unauthorized = raw_http_response(&listen_addr, &unauthorized_request);
    assert!(unauthorized.contains("HTTP/1.1 401 Unauthorized"));
    let still_pending = fs::read_to_string(
        state_dir
            .join("approvals")
            .join(format!("{approval_id}.json")),
    )
    .expect("pending approval after unauthorized request");
    assert!(still_pending.contains(r#""state": "pending""#));

    let approved = authenticated_http_json(
        &listen_addr,
        &format!("/api/approvals/{approval_id}/decision"),
        &reviewer_token,
        json!({
            "decision": "approve",
            "reason": "recipient and subject verified"
        }),
    );
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["side_effect_executed"], false);

    let second = call_mcp_tool(902, "runwarden.provider.call", arguments);
    let second_payload = mcp_tool_payload(&second);
    assert_eq!(second["result"]["isError"], false);
    assert_eq!(second_payload["decision"], "allowed");
    assert_eq!(second_payload["side_effect_executed"], true);

    let saved = fs::read_to_string(
        state_dir
            .join("approvals")
            .join(format!("{approval_id}.json")),
    )
    .expect("saved approval");
    assert!(saved.contains(r#""state": "consumed""#));
    assert!(saved.contains(r#""reviewer": "reviewer-session-"#));

    let trace = http_json(&listen_addr, "GET", "/api/trace/verify", None);
    assert_eq!(trace["provider_trace"]["verified"], true);
    assert_eq!(trace["provider_trace"]["event_count"], 2);

    restore_env("RUNWARDEN_STATE_DIR", old_state);
    restore_env("RUNWARDEN_SANDBOX_ROOT", old_sandbox);
    restore_env("RUNWARDEN_SESSION_ID", old_session);
    restore_env("RUNWARDEN_ACTOR_ID", old_actor);
    child.kill().expect("kill demo server");
    child.wait().expect("wait demo server");
    let _ = fs::remove_dir_all(state_dir);
}

#[test]
fn report_render_scenario_suite_outputs_contest_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args([
            "report",
            "render",
            "--scenario-suite",
            "scenarios",
            "--format",
            "markdown",
            "--json",
        ])
        .output()
        .expect("render scenario suite report");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Runwarden Contest Report"));
    assert!(stdout.contains("prompt-injection-file-exfil"));
    assert!(
        stdout.contains("| Provider | Defense | Decision | Status | Side Effect | Obs | Reason |")
    );
    assert!(stdout.contains("scoped-root"));
    assert!(stdout.contains("obs_prompt_file_exfil_denied"));
}

#[test]
fn report_render_scenario_suite_fails_when_eval_fails() {
    let workspace = workspace_root();
    let suite = PathBuf::from("target/runwarden-contest-test/failing-scenario-suite");
    let absolute_suite = workspace.join(&suite);
    let _ = fs::remove_dir_all(&absolute_suite);
    copy_dir(&workspace.join("scenarios"), &absolute_suite);
    fs::write(
        absolute_suite.join("prompt-injection-file-exfil/expected/eval-baseline.json"),
        r#"{
  "expected_pass": true,
  "expected_denials": 99,
  "expected_requires_review": 1,
  "min_trace_completeness": 1.0,
  "min_report_citation_accuracy": 1.0
}
"#,
    )
    .expect("write failing baseline");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["report", "render", "--scenario-suite"])
        .arg(&suite)
        .args(["--format", "markdown", "--json"])
        .output()
        .expect("render scenario suite report");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("scenario suite eval did not pass"));
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).expect("create destination dir");
    for entry in fs::read_dir(from).expect("read source dir") {
        let entry = entry.expect("source entry");
        let destination = to.join(entry.file_name());
        let file_type = entry.file_type().expect("source entry type");
        if file_type.is_dir() {
            copy_dir(&entry.path(), &destination);
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination).expect("copy file");
        }
    }
}

fn read_startup_json(child: &mut Child) -> Value {
    let mut stdout = child.stdout.take().expect("server stdout");
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stdout.read_exact(&mut byte).expect("read startup byte");
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    serde_json::from_slice(&buf).expect("startup JSON")
}

fn call_mcp_tool(id: u64, name: &str, arguments: Value) -> Value {
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
    .expect("mcp response")
}

fn mcp_tool_payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("mcp text content");
    serde_json::from_str(text).expect("mcp payload JSON")
}

fn http_json(addr: &str, method: &str, path: &str, body: Option<Value>) -> Value {
    let body = body.map(|value| value.to_string()).unwrap_or_default();
    let request = if method == "POST" {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    };
    let mut stream = TcpStream::connect(addr).expect("connect demo server");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "unexpected response: {response}"
    );
    let (_, body) = response.split_once("\r\n\r\n").expect("response body");
    serde_json::from_str(body).expect("response JSON")
}

fn authenticated_http_json(addr: &str, path: &str, reviewer_token: &str, body: Value) -> Value {
    let body = body.to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nX-Runwarden-Reviewer-Token: {reviewer_token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut stream = TcpStream::connect(addr).expect("connect demo server");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(
        response.contains("HTTP/1.1 200 OK"),
        "unexpected authenticated response: {response}"
    );
    let (_, body) = response.split_once("\r\n\r\n").expect("response body");
    serde_json::from_str(body).expect("response JSON")
}

fn raw_http_response(addr: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect demo server");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}
