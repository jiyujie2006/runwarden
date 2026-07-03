use std::{
    fs,
    io::{Read, Write},
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
