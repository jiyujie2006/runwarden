use std::{fs, path::PathBuf, process::Command};

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
