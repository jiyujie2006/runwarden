use std::{fs, process::Command};

use runwarden_kernel::evidence::TraceEvent;
use serde_json::json;
use tempfile::tempdir;

fn trace_json() -> String {
    let first = TraceEvent::sealed(
        "obs_1".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.evidence.inspect".to_string()),
        json!({"ok": true}),
        None,
    );
    let second = TraceEvent::sealed(
        "obs_2".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.trace.verify".to_string()),
        json!({"ok": true}),
        Some(first.event_hash.clone()),
    );
    serde_json::to_string_pretty(&vec![first, second]).expect("trace json")
}

#[test]
fn report_lint_command_rejects_uncited_claim() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    let report_path = dir.path().join("report.json");
    fs::write(&trace_path, trace_json()).expect("trace");
    fs::write(
        &report_path,
        r#"{"claims":[{"id":"finding-1","text":"Shell denied","obs_refs":[]}]}"#,
    )
    .expect("report");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["report", "lint", "--report"])
        .arg(&report_path)
        .args(["--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run report lint");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""ok": false"#));
    assert!(stdout.contains("UncitedClaim"));
}

#[test]
fn eval_all_command_fails_when_expected_obs_is_missing_from_report() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    let report_path = dir.path().join("report.json");
    fs::write(&trace_path, trace_json()).expect("trace");
    fs::write(
        &report_path,
        r#"{"claims":[{"id":"finding-1","text":"Shell denied","obs_refs":["obs_1"]}]}"#,
    )
    .expect("report");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["eval", "all", "--report"])
        .arg(&report_path)
        .args(["--trace"])
        .arg(&trace_path)
        .args(["--expected-obs", "obs_1"])
        .args(["--expected-obs", "obs_2"])
        .arg("--json")
        .output()
        .expect("run eval all");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": false"#));
    assert!(stdout.contains("trace_completeness"));
}

#[test]
fn eval_agent_native_default_blocks_raw_tool_exposure() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["eval", "agent-native", "--json"])
        .output()
        .expect("run eval agent-native");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": true"#));
    assert!(stdout.contains(r#""raw_tool_block_rate": 1.0"#));
    assert!(stdout.contains("unsafe.raw-shell.json"));
}

#[test]
fn eval_agent_native_fails_when_expected_safe_config_exposes_raw_tool() {
    let dir = tempdir().expect("tempdir");
    let config_path = dir.path().join("safe-bad.json");
    fs::write(
        &config_path,
        r#"{"mcpServers":{"runwarden":{"command":"runwarden-mcp"},"shell":{"command":"bash"}}}"#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["eval", "agent-native", "--config"])
        .arg(&config_path)
        .arg("--json")
        .output()
        .expect("run eval agent-native");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": false"#));
    assert!(stdout.contains("expected_runwarden_only_config_to_pass"));
}

#[test]
fn report_render_command_outputs_sarif_for_cited_report() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    let report_path = dir.path().join("report.json");
    fs::write(&trace_path, trace_json()).expect("trace");
    fs::write(
        &report_path,
        r#"{"claims":[{"id":"finding-1","text":"Shell denied","obs_refs":["obs_1"]}]}"#,
    )
    .expect("report");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["report", "render", "--report"])
        .arg(&report_path)
        .args(["--trace"])
        .arg(&trace_path)
        .args(["--format", "sarif"])
        .arg("--json")
        .output()
        .expect("run report render");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""extension": "sarif.json""#));
    assert!(stdout.contains(r#"\"version\":\"2.1.0\""#));
}

#[test]
fn report_scaffold_command_generates_cited_draft_from_trace() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    fs::write(&trace_path, trace_json()).expect("trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["report", "scaffold", "--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run report scaffold");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""obs_refs": ["#));
    assert!(stdout.contains(r#""obs_1""#));
}
