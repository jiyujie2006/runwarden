use std::{
    collections::BTreeSet,
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use runwarden_kernel::{
    story::{EvidenceStatus, SecurityStory, StoryProvenance},
    trace::Sha256Digest,
};
use runwarden_mcp::production_server_from_env;
use runwarden_providers::demo_tools::mailbox_view_for_test;
use runwarden_state::StateStore;
use serde_json::{Value, json};

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

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_failed_child(mut child: Child, context: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll failed child") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            panic!("{context} did not fail during startup");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("failed child stderr")
        .read_to_string(&mut stderr)
        .expect("read failed child stderr");
    assert!(!status.success(), "{context} unexpectedly succeeded");
    stderr
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
fn closed_loop_mcp_worker() {
    let Some(response_path) = env::var_os("RUNWARDEN_CLOSED_LOOP_RESPONSE") else {
        return;
    };
    let server = std::sync::Arc::new(production_server_from_env().expect("production MCP server"));
    let call_server = server.clone();
    let provider_call = thread::spawn(move || {
        call_server
            .handle_jsonrpc(
                &json!({
                    "jsonrpc": "2.0",
                    "id": "closed-loop-provider-call",
                    "method": "tools/call",
                    "params": {
                        "name": "runwarden.provider.call",
                        "arguments": {
                            "provider": "external.email.send",
                            "to": ["test@example.com"],
                            "subject": "Runwarden closed-loop review",
                            "body": "one frozen provider request"
                        }
                    }
                })
                .to_string(),
            )
            .expect("provider call JSON-RPC")
            .expect("provider call response")
    });
    let call = provider_call.join().expect("provider call thread");
    let operation_id = call["result"]["structuredContent"]["operation_id"]
        .as_str()
        .expect("completed operation id");
    let status = server
        .handle_jsonrpc(
            &json!({
                "jsonrpc": "2.0",
                "id": "closed-loop-status",
                "method": "tools/call",
                "params": {
                    "name": "runwarden.operation.status",
                    "arguments": {"operation_id": operation_id}
                }
            })
            .to_string(),
        )
        .expect("status JSON-RPC")
        .expect("status response");
    fs::write(
        response_path,
        serde_json::to_vec(&json!({"provider_call": call, "status": status})).unwrap(),
    )
    .expect("write closed-loop worker response");
}

#[test]
fn demo_interactive_approves_and_completes_one_original_provider_call() {
    let _guard = demo_lock().lock().expect("demo lock");
    let workspace = workspace_root();
    let temp = tempfile::tempdir().expect("closed-loop tempdir");
    let state_dir = temp.path().join("state");
    let mut child = ChildGuard::new(
        Command::new(env!("CARGO_BIN_EXE_runwarden"))
            .current_dir(&workspace)
            .args(["demo", "--port", "0", "--json"])
            .env("RUNWARDEN_STATE_DIR", &state_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn demo server"),
    );

    let startup = read_startup_json(&mut child);
    let listen_addr = startup["listen_addr"]
        .as_str()
        .expect("listen_addr")
        .to_string();
    assert_eq!(startup["mode"], "interactive_demo");
    let story_id = startup["story_id"].as_str().expect("startup story id");
    let trusted_env = startup["trusted_mcp_environment"]
        .as_object()
        .expect("trusted MCP environment");
    let instance_token = trusted_env["RUNWARDEN_INSTANCE_TOKEN"]
        .as_str()
        .expect("instance token")
        .to_owned();
    assert_eq!(instance_token.len(), 43);
    assert!(
        instance_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
    assert_eq!(
        PathBuf::from(trusted_env["RUNWARDEN_STATE_DIR"].as_str().unwrap()),
        state_dir.canonicalize().unwrap()
    );

    let worker_response = temp.path().join("worker-response.json");
    let mut worker = Command::new(env::current_exe().expect("current test binary"));
    worker
        .args(["--exact", "closed_loop_mcp_worker", "--nocapture"])
        .env("RUNWARDEN_CLOSED_LOOP_RESPONSE", &worker_response)
        .env("RUNWARDEN_MCP_APPROVAL_WAIT_MS", "10000")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in trusted_env {
        worker.env(key, value.as_str().expect("trusted environment value"));
    }
    let worker = worker.spawn().expect("spawn closed-loop MCP worker");

    let bootstrap = wait_for_pending_operation(&listen_addr, Duration::from_secs(5));
    assert!(!bootstrap.to_string().contains(&instance_token));
    assert_eq!(bootstrap["active_story_id"], story_id);
    let operation = bootstrap["evidence"]["story"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["state"] == "awaiting_approval")
        .expect("pending native operation");
    let operation_id = operation["operation_id"].as_str().unwrap();
    let approval_id = operation["approval"]["approval_id"].as_str().unwrap();
    let (detail_status, detail) = http_json(
        &listen_addr,
        "GET",
        &format!("/api/stories/{story_id}/operations/{operation_id}"),
        &[],
        None,
    );
    assert_eq!(detail_status, 200);

    let decision_body = json!({
        "decision": "approve",
        "reviewer": "contest-reviewer",
        "reason": "approve the exact frozen live demo operation",
        "expected_approval_version": detail["approval_version"],
        "expected_operation_version": detail["operation"]["version"]
    });
    let nonce = bootstrap["reviewer_nonce"].as_str().unwrap();
    let origin = bootstrap["accepted_origin"].as_str().unwrap();
    let (decision_status, decision) = http_json(
        &listen_addr,
        "POST",
        &format!("/api/approvals/{approval_id}/decision"),
        &[
            ("Origin", origin),
            ("X-Runwarden-Reviewer-Nonce", nonce),
            ("Content-Type", "application/json"),
        ],
        Some(&decision_body),
    );
    assert_eq!(decision_status, 200, "decision response: {decision}");
    assert_eq!(decision["operation_id"], operation_id);
    assert_eq!(decision["approval_state"], "approved");

    let output = worker.wait_with_output().expect("wait for MCP worker");
    assert!(
        output.status.success(),
        "worker stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let worker_response: Value =
        serde_json::from_slice(&fs::read(&worker_response).expect("closed-loop worker response"))
            .unwrap();
    assert!(!worker_response.to_string().contains(&instance_token));
    let completed = &worker_response["provider_call"]["result"]["structuredContent"];
    let status = &worker_response["status"]["result"]["structuredContent"];
    assert_eq!(worker_response["provider_call"]["result"]["isError"], false);
    assert_eq!(completed["disposition"], "completed");
    assert_eq!(completed["operation_id"], operation_id);
    assert_eq!(status["disposition"], "completed");
    assert_eq!(status["operation_id"], operation_id);

    let store = StateStore::open(&state_dir).unwrap();
    let story = store
        .story_snapshot(serde_json::from_value(startup["story_id"].clone()).unwrap())
        .unwrap();
    let active = store.active_demo().unwrap().unwrap();
    assert_eq!(
        active.instance_token_hash,
        Sha256Digest::from_bytes(instance_token.as_bytes()).as_str()
    );
    assert!(
        !serde_json::to_string(&story)
            .unwrap()
            .contains(&instance_token)
    );
    assert_eq!(story.operations.len(), 1);
    assert_eq!(story.operations[0].operation_id.to_string(), operation_id);
    assert_eq!(
        story.operations[0].approval.as_ref().unwrap().state,
        runwarden_kernel::authority::ApprovalState::Consumed
    );
    let sandbox_root = PathBuf::from(trusted_env["RUNWARDEN_SANDBOX_ROOT"].as_str().unwrap());
    let receipts = fs::read_dir(sandbox_root.join("mail/receipts"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].file_name().to_str().unwrap(),
        format!("{operation_id}.json")
    );
    assert_eq!(
        mailbox_view_for_test(&sandbox_root)
            .unwrap()
            .lines()
            .count(),
        1
    );

    let mut second = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["demo", "--port", "0", "--json"])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn conflicting demo");
    let deadline = Instant::now() + Duration::from_secs(3);
    let second_status = loop {
        if let Some(status) = second.try_wait().expect("poll conflicting demo") {
            break status;
        }
        if Instant::now() >= deadline {
            second.kill().ok();
            panic!("second demo did not reject the active state directory");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let mut second_stderr = String::new();
    second
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut second_stderr)
        .unwrap();
    assert!(!second_status.success());
    assert!(second_stderr.contains("already has an active interactive demo"));

    child.stop();
}

#[test]
fn interactive_demo_reviewer_bind_failure_never_activates_state() {
    let _guard = demo_lock().lock().expect("demo lock");
    let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy reviewer port");
    let port = occupied.local_addr().unwrap().port();
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["demo", "--port", &port.to_string(), "--json"])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn reviewer-bind failure demo");

    let stderr = wait_for_failed_child(child, "reviewer-bind failure demo");
    assert!(
        stderr.contains("bind reviewer listener"),
        "stderr: {stderr}"
    );
    assert!(
        StateStore::open(&state_dir)
            .unwrap()
            .active_demo()
            .unwrap()
            .is_none()
    );
}

#[test]
fn interactive_demo_proxy_bind_failure_never_activates_state() {
    let _guard = demo_lock().lock().expect("demo lock");
    let _occupied = TcpListener::bind("127.0.0.1:8787").expect("occupy LLM proxy port");
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let trace_path = state_dir.join("llm-proxy-trace.jsonl");
    fs::write(&trace_path, b"prior-evidence\n").unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["demo", "--port", "0", "--json"])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn proxy-bind failure demo");

    let stderr = wait_for_failed_child(child, "proxy-bind failure demo");
    assert!(
        stderr.contains("preflight interactive demo LLM proxy"),
        "stderr: {stderr}"
    );
    assert!(
        StateStore::open(&state_dir)
            .unwrap()
            .active_demo()
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read(&trace_path).unwrap(), b"prior-evidence\n");
}

#[test]
fn interactive_demo_preserves_stale_trace_and_never_activates_state() {
    let _guard = demo_lock().lock().expect("demo lock");
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let trace_path = state_dir.join("llm-proxy-trace.jsonl");
    fs::write(&trace_path, b"prior-evidence\n").unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["demo", "--port", "0", "--json"])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stale-trace failure demo");

    let stderr = wait_for_failed_child(child, "stale-trace failure demo");
    assert!(
        stderr.contains("LLM proxy trace path already exists"),
        "stderr: {stderr}"
    );
    assert_eq!(fs::read(&trace_path).unwrap(), b"prior-evidence\n");
    assert!(
        StateStore::open(&state_dir)
            .unwrap()
            .active_demo()
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn interactive_demo_rejects_symlinked_trusted_root_before_activation() {
    use std::os::unix::fs::symlink;

    let _guard = demo_lock().lock().expect("demo lock");
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let external = temp.path().join("external-sandbox");
    fs::create_dir_all(&state_dir).unwrap();
    fs::create_dir_all(&external).unwrap();
    symlink(&external, state_dir.join("sandbox")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["demo", "--port", "0", "--json"])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn symlink-root failure demo");

    let stderr = wait_for_failed_child(child, "symlink-root failure demo");
    assert!(
        stderr.contains("interactive sandbox root must be a real directory"),
        "stderr: {stderr}"
    );
    assert!(
        StateStore::open(&state_dir)
            .unwrap()
            .active_demo()
            .unwrap()
            .is_none()
    );
}

#[test]
fn interactive_demo_rejects_control_characters_before_creating_state() {
    let _guard = demo_lock().lock().expect("demo lock");
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state\ninjected");
    let child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["demo", "--port", "0", "--json"])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn control-path failure demo");

    let stderr = wait_for_failed_child(child, "control-path failure demo");
    assert!(
        stderr.contains("interactive demo state directory contains control characters"),
        "stderr: {stderr}"
    );
    assert!(!state_dir.exists());
}

#[test]
fn interactive_demo_rejects_upstream_log_injection_before_activation() {
    let _guard = demo_lock().lock().expect("demo lock");
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args([
            "demo",
            "--port",
            "0",
            "--json",
            "--upstream",
            "https://example.test/v1\nFORGED-LAUNCH-LINE",
        ])
        .env("RUNWARDEN_STATE_DIR", &state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn upstream-injection failure demo");

    let stderr = wait_for_failed_child(child, "upstream-injection failure demo");
    assert!(
        stderr.contains("LLM proxy upstream contains control characters"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("FORGED-LAUNCH-LINE"));
    assert!(
        StateStore::open(&state_dir)
            .unwrap()
            .active_demo()
            .unwrap()
            .is_none()
    );
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

fn wait_for_pending_operation(listen_addr: &str, timeout: Duration) -> Value {
    let deadline = Instant::now() + timeout;
    loop {
        let (status, bootstrap) = http_json(listen_addr, "GET", "/api/bootstrap", &[], None);
        if status == 200
            && bootstrap["evidence"]["story"]["operations"]
                .as_array()
                .is_some_and(|operations| {
                    operations.iter().any(|operation| {
                        operation["state"] == "awaiting_approval"
                            && operation["approval"]["state"] == "pending"
                            && operation["approval"]["approval_id"]
                                .as_str()
                                .is_some_and(|approval_id| !approval_id.is_empty())
                    })
                })
        {
            return bootstrap;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for pending operation; last response: {bootstrap}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn http_json(
    listen_addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> (u16, Value) {
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {listen_addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    request.push_str(&body);

    let mut stream = TcpStream::connect(listen_addr).expect("connect reviewer HTTP server");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read HTTP response");
    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP header boundary");
    let head = std::str::from_utf8(&response[..boundary]).expect("HTTP headers are UTF-8");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .expect("HTTP status");
    let body = &response[boundary + 4..];
    let body = if head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        decode_chunked(body)
    } else {
        body.to_vec()
    };
    let json = serde_json::from_slice(&body).unwrap_or_else(|error| {
        panic!(
            "HTTP response body is not JSON ({error}): {}",
            String::from_utf8_lossy(&body)
        )
    });
    (status, json)
}

fn decode_chunked(mut encoded: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size terminator");
        let size_text = std::str::from_utf8(&encoded[..line_end]).expect("chunk size is ASCII");
        let size = usize::from_str_radix(size_text.split(';').next().unwrap(), 16)
            .expect("hex chunk size");
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            break;
        }
        assert!(encoded.len() >= size + 2, "complete HTTP chunk");
        decoded.extend_from_slice(&encoded[..size]);
        assert_eq!(&encoded[size..size + 2], b"\r\n");
        encoded = &encoded[size + 2..];
    }
    decoded
}
