use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
};

use runwarden_kernel::story::{EvidenceStatus, SecurityStory, StoryProvenance};
use runwarden_mcp::handle_jsonrpc_body;
use serde_json::Value;
use serde_json::json;

const CONTEST_SCENARIOS: [&str; 5] = [
    "prompt-injection-file-exfil",
    "tool-hijack-email-api",
    "memory-knowledge-poisoning",
    "environment-local-web-risk",
    "path-escape-file-boundary",
];

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
fn demo_scenario_writes_real_trace_report_webui_and_story_json() {
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
    assert!(absolute_output.join("story.json").exists());
    let webui: Value = serde_json::from_str(
        &fs::read_to_string(absolute_output.join("webui.json")).expect("webui"),
    )
    .expect("webui json");
    assert_eq!(webui["trace_verification"]["verified"], true);
    assert_eq!(webui["provider_calls"][1]["decision"], "requires_review");
    assert_eq!(webui["provider_calls"][2]["decision"], "denied");
    assert_eq!(webui["provider_calls"][2]["side_effect_executed"], false);
    let story: SecurityStory = serde_json::from_str(
        &fs::read_to_string(absolute_output.join("story.json")).expect("story"),
    )
    .expect("security story JSON");
    assert_eq!(story.scenario_id, "prompt-injection-file-exfil");
    assert_eq!(story.provenance, StoryProvenance::LegacyDerived);
    assert_eq!(story.evidence_status, EvidenceStatus::Incomplete);
    assert_eq!(story.stage_statuses.len(), 8);
    assert_eq!(story.identity.agent_id, "legacy-unavailable");
    assert_eq!(story.identity.model_id, "legacy-unavailable");
    assert_eq!(story.identity.actor_id, "demo-agent");
    assert_eq!(story.authority.authz_id, "legacy-not-configured");
    assert_eq!(story.authority.authz_state, "not_configured");
    assert!(story.authority.files.is_empty());
    assert_eq!(
        story.authority.allowed_providers,
        [
            "runwarden.input.inspect".to_string(),
            "external.mcp.filesystem.read_file".to_string(),
        ]
    );
    assert!(story.operations.iter().all(|operation| {
        operation.session_id == story.authority.session_id && operation.observation_refs.is_empty()
    }));
    assert_eq!(story.event_count, 0);
    assert!(story.final_event_hash.is_none());
    assert!(story.report_claims.is_empty());
}

#[test]
fn demo_all_writes_exact_official_stories_and_static_reviewer_console() {
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
    fs::write(stale_dir.join("story.json"), r#"{"stale":true}"#).expect("stale story");
    fs::write(stale_dir.join("keep.txt"), "keep").expect("unrelated stale file");
    let nested_stale = stale_dir.join("nested");
    fs::create_dir_all(&nested_stale).expect("nested stale dir");
    fs::write(nested_stale.join("story.json"), r#"{"nested":true}"#).expect("nested stale story");

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

    let story_directories = fs::read_dir(&absolute_output)
        .expect("demo output directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_dir()))
        .filter(|entry| entry.path().join("story.json").is_file())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        story_directories,
        CONTEST_SCENARIOS
            .into_iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
    );
    assert!(!stale_dir.join("story.json").exists());
    assert!(stale_dir.join("webui.json").exists());
    assert_eq!(
        fs::read_to_string(stale_dir.join("keep.txt")).unwrap(),
        "keep"
    );
    assert!(nested_stale.join("story.json").exists());
    for scenario in CONTEST_SCENARIOS {
        let story: SecurityStory = serde_json::from_str(
            &fs::read_to_string(absolute_output.join(scenario).join("story.json"))
                .expect("story file"),
        )
        .expect("security story JSON");
        assert_eq!(story.scenario_id, scenario);
        assert_eq!(story.provenance, StoryProvenance::LegacyDerived);
        assert_eq!(story.evidence_status, EvidenceStatus::Incomplete);
    }
}

#[cfg(unix)]
#[test]
fn demo_all_story_pruning_does_not_follow_symlink_directories() {
    use std::os::unix::fs::symlink;

    let workspace = workspace_root();
    let output_dir = PathBuf::from("target/runwarden-contest-test/demo-all-prune-symlink");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);
    fs::create_dir_all(&absolute_output).expect("demo output");
    let outside = tempfile::tempdir().expect("outside directory");
    let outside_story = outside.path().join("story.json");
    fs::write(&outside_story, "outside-story").expect("outside story");
    symlink(outside.path(), absolute_output.join("stale-link")).expect("stale directory link");

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
    assert_eq!(fs::read_to_string(outside_story).unwrap(), "outside-story");
    assert!(absolute_output.join("stale-link").is_symlink());
}

#[cfg(unix)]
#[test]
fn demo_all_story_pruning_unlinks_stale_story_leaf_without_touching_target() {
    use std::os::unix::fs::symlink;

    let workspace = workspace_root();
    let output_dir = PathBuf::from("target/runwarden-contest-test/demo-all-prune-leaf-link");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);
    let stale_dir = absolute_output.join("stale-normal-directory");
    fs::create_dir_all(&stale_dir).expect("stale normal directory");
    let outside = tempfile::tempdir().expect("outside directory");
    let outside_story = outside.path().join("story.json");
    fs::write(&outside_story, "outside-story").expect("outside story");
    let stale_story_link = stale_dir.join("story.json");
    symlink(&outside_story, &stale_story_link).expect("stale story leaf link");

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
    assert!(fs::symlink_metadata(&stale_story_link).is_err());
    assert_eq!(fs::read_to_string(outside_story).unwrap(), "outside-story");
    assert!(stale_dir.is_dir());
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
    assert!(inside_target.join("story.json").exists());

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
    assert!(!outside_target.join("story.json").exists());
}

#[cfg(unix)]
#[test]
fn demo_story_leaf_symlink_escape_is_rejected_without_touching_outside_file() {
    use std::os::unix::fs::symlink;

    let workspace = workspace_root();
    let output_dir = PathBuf::from("target/runwarden-contest-test/story-leaf-symlink");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);
    fs::create_dir_all(&absolute_output).expect("demo output");
    let outside = tempfile::tempdir().expect("outside directory");
    let outside_story = outside.path().join("outside-story.json");
    fs::write(&outside_story, "outside-original").expect("outside story");
    symlink(&outside_story, absolute_output.join("story.json")).expect("story leaf symlink");

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
        .expect("run demo with escaping story leaf");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("story output path"));
    assert_eq!(
        fs::read_to_string(outside_story).expect("outside story unchanged"),
        "outside-original"
    );
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
    assert_eq!(startup["mode"], "interactive_demo");

    let mut stream = TcpStream::connect(&listen_addr).expect("connect demo server");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    child.kill().expect("kill demo server");
    child.wait().expect("wait demo server");

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains(r#"{"ok":true}"#));
}

#[test]
fn demo_interactive_approval_retry_fails_closed_until_native_runtime_connects() {
    let _guard = demo_lock().lock().expect("demo lock");
    let workspace = workspace_root();
    let state_dir = workspace.join(".runwarden");
    let sandbox_root = workspace.join("target/runwarden-contest-test/live-console-sandbox");
    let _ = fs::remove_dir_all(&state_dir);
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

    let old_state = std::env::var_os("RUNWARDEN_STATE_DIR");
    let old_sandbox = std::env::var_os("RUNWARDEN_SANDBOX_ROOT");
    unsafe {
        std::env::set_var("RUNWARDEN_STATE_DIR", &state_dir);
        std::env::set_var("RUNWARDEN_SANDBOX_ROOT", &sandbox_root);
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

    let approved = http_json(
        &listen_addr,
        "POST",
        "/api/approve",
        Some(json!({ "approval_id": approval_id })),
    );
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["side_effect_executed"], false);

    let second = call_mcp_tool(902, "runwarden.provider.call", arguments);
    let second_payload = mcp_tool_payload(&second);
    assert_eq!(second["result"]["isError"], true);
    assert_eq!(second_payload["decision"], "allowed");
    assert_eq!(second_payload["execution_status"], "not_executed");
    assert_eq!(second_payload["error_kind"], "native_executor_required");
    assert_eq!(second_payload["side_effect_executed"], false);

    let saved = fs::read_to_string(
        state_dir
            .join("approvals")
            .join(format!("{approval_id}.json")),
    )
    .expect("saved approval");
    assert!(saved.contains(r#""state": "approved""#));
    assert!(!saved.contains(r#""state": "consumed""#));

    let trace = http_json(&listen_addr, "GET", "/api/trace/verify", None);
    assert_eq!(trace["provider_trace"]["verified"], true);
    assert_eq!(trace["provider_trace"]["event_count"], 2);

    restore_env("RUNWARDEN_STATE_DIR", old_state);
    restore_env("RUNWARDEN_SANDBOX_ROOT", old_sandbox);
    child.kill().expect("kill demo server");
    child.wait().expect("wait demo server");
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
