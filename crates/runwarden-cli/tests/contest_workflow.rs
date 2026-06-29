use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn eval_scenarios_runs_four_contest_scenarios() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["eval", "scenarios", "--json"])
        .output()
        .expect("run eval scenarios");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""suite": "contest-red-team-scenarios""#));
    assert!(stdout.contains(r#""case_count": 4"#));
    assert!(stdout.contains("prompt-injection-file-exfil"));
    assert!(stdout.contains("tool-hijack-email-api"));
    assert!(stdout.contains("memory-knowledge-poisoning"));
    assert!(stdout.contains("environment-local-web-risk"));
    assert!(stdout.contains(r#""passed": true"#));
}

#[test]
fn demo_run_writes_trace_report_and_webui_json() {
    let workspace = workspace_root();
    let output_dir = PathBuf::from("target/runwarden-contest-test/prompt-injection-file-exfil");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "run",
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
    let trace = fs::read_to_string(absolute_output.join("trace.json")).expect("trace");
    assert!(trace.contains("obs_prompt_file_exfil_denied"));
    assert!(trace.contains(r#""side_effect_executed": false"#));
    let webui: Value = serde_json::from_str(
        &fs::read_to_string(absolute_output.join("webui.json")).expect("webui"),
    )
    .expect("webui json");
    assert_eq!(webui["trace_verification"]["verified"], true);
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
    assert!(stdout.contains("obs_prompt_file_exfil_denied"));
}

#[test]
fn ui_build_creates_static_console_without_local_api() {
    let workspace = workspace_root();
    let input_dir = PathBuf::from("target/runwarden-contest-test");
    let output_file = PathBuf::from("target/runwarden-contest-test/reviewer-console.html");
    let _ = fs::remove_file(workspace.join(&output_file));

    let demo = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "run",
            "--scenario",
            "prompt-injection-file-exfil",
            "--output",
            "target/runwarden-contest-test/prompt-injection-file-exfil",
            "--json",
        ])
        .output()
        .expect("run demo scenario");
    assert!(demo.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["ui", "build", "--input"])
        .arg(&input_dir)
        .args(["--output"])
        .arg(&output_file)
        .arg("--json")
        .output()
        .expect("build ui");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""local_api_url": null"#));
    let html = fs::read_to_string(workspace.join(output_file)).expect("html");
    assert!(html.contains("Runwarden Reviewer Console"));
    assert!(html.contains("prompt-injection-file-exfil"));
}

#[test]
fn ui_serve_live_streams_demo_provider_calls_as_sse() {
    let workspace = workspace_root();
    let output_dir =
        PathBuf::from("target/runwarden-contest-test/live-prompt-injection-file-exfil");
    let absolute_output = workspace.join(&output_dir);
    let _ = fs::remove_dir_all(&absolute_output);

    let demo = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "demo",
            "run",
            "--scenario",
            "prompt-injection-file-exfil",
            "--output",
        ])
        .arg(&output_dir)
        .arg("--json")
        .output()
        .expect("run demo scenario");
    assert!(
        demo.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&demo.stderr)
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "ui",
            "serve",
            "--live",
            "--demo",
            output_dir.to_str().expect("utf8 path"),
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live ui server");

    let startup = read_live_startup_json(&mut child);
    let listen_addr = startup["listen_addr"]
        .as_str()
        .expect("listen_addr")
        .to_string();
    assert_eq!(startup["mode"], "live_demo_replay");
    assert_eq!(startup["provider_call_count"], 3);
    assert_eq!(startup["side_effect_executed"], false);

    let mut stream = TcpStream::connect(&listen_addr).expect("connect live server");
    stream
        .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("Content-Type: text/event-stream"));
    assert!(response.contains("event: provider_call"));
    assert!(response.contains("event: replay_complete"));
    assert!(response.contains("obs_prompt_file_exfil_denied"));
    assert!(response.contains("\"provider\":\"external.api.request\""));
    assert!(response.contains("\"side_effect_executed\":false"));

    child.kill().expect("kill live server");
    child.wait().expect("wait live server");
}

#[test]
fn ui_serve_live_rejects_missing_demo_and_unsafe_paths() {
    let workspace = workspace_root();
    let missing = PathBuf::from("target/runwarden-contest-test/missing-live-demo");
    let _ = fs::remove_dir_all(workspace.join(&missing));

    let missing_output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["ui", "serve", "--live", "--demo"])
        .arg(&missing)
        .args(["--port", "0", "--json"])
        .output()
        .expect("serve missing demo");
    assert!(!missing_output.status.success());
    assert!(String::from_utf8_lossy(&missing_output.stderr).contains("live demo data is missing"));

    let absolute_output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["ui", "serve", "--live", "--demo"])
        .arg(workspace.join("scenarios"))
        .args(["--port", "0", "--json"])
        .output()
        .expect("serve absolute demo");
    assert!(!absolute_output.status.success());
    assert!(
        String::from_utf8_lossy(&absolute_output.stderr)
            .contains("path must be a relative path inside the workspace")
    );

    let traversal_output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "ui",
            "serve",
            "--live",
            "--demo",
            "../runwarden/scenarios",
            "--port",
            "0",
            "--json",
        ])
        .output()
        .expect("serve traversal demo");
    assert!(!traversal_output.status.success());
    assert!(
        String::from_utf8_lossy(&traversal_output.stderr)
            .contains("path must be a relative path inside the workspace")
    );
}

#[cfg(unix)]
#[test]
fn ui_serve_live_rejects_symlink_demo_path() {
    use std::os::unix::fs::symlink;

    let workspace = workspace_root();
    let link = workspace.join("target/runwarden-contest-test/live-demo-link");
    let _ = fs::remove_file(&link);
    fs::create_dir_all(link.parent().expect("link parent")).expect("create link parent");
    symlink(workspace.join("scenarios"), &link).expect("create demo symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "ui",
            "serve",
            "--live",
            "--demo",
            "target/runwarden-contest-test/live-demo-link",
            "--port",
            "0",
            "--json",
        ])
        .output()
        .expect("serve symlink demo");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("path must not contain symlink components")
    );
}

fn read_live_startup_json(child: &mut Child) -> Value {
    let stdout = child.stdout.take().expect("live server stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read startup line");
    assert!(!line.is_empty(), "live server did not print startup JSON");
    serde_json::from_str(&line).expect("startup JSON")
}
