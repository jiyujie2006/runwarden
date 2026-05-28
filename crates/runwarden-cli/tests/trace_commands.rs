use std::{fs, process::Command};

use runwarden_kernel::evidence::TraceEvent;
use serde_json::json;
use tempfile::tempdir;

fn trace_events() -> Vec<TraceEvent> {
    let first = TraceEvent::sealed(
        "obs_1".to_string(),
        "provider_policy_evaluated".to_string(),
        Some("runwarden.input.inspect".to_string()),
        json!({"decision":"allowed"}),
        None,
    );
    let second = TraceEvent::sealed(
        "obs_2".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.input.inspect".to_string()),
        json!({"status":"completed"}),
        Some(first.event_hash.clone()),
    );
    vec![first, second]
}

#[test]
fn trace_verify_command_accepts_valid_hash_chain() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    fs::write(
        &trace_path,
        serde_json::to_string_pretty(&trace_events()).expect("trace json"),
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["trace", "verify", "--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run trace verify");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""verified": true"#));
    assert!(stdout.contains(r#""event_count": 2"#));
}

#[test]
fn trace_verify_command_rejects_tampered_hash_chain() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    let mut trace = trace_events();
    trace[1].payload = json!({"status":"rewritten"});
    fs::write(
        &trace_path,
        serde_json::to_string_pretty(&trace).expect("trace json"),
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["trace", "verify", "--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run trace verify");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""verified": false"#));
    assert!(stdout.contains("trace_tampered"));
}

#[test]
fn trace_export_command_outputs_only_after_verification() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    fs::write(
        &trace_path,
        serde_json::to_string_pretty(&trace_events()).expect("trace json"),
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["trace", "export", "--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run trace export");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""verified": true"#));
    assert!(stdout.contains(r#""obs_id": "obs_1""#));
    assert!(stdout.contains(r#""obs_id": "obs_2""#));
}

#[test]
fn trace_export_command_supports_paged_provider_filters_and_compact_refs() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.json");
    fs::write(
        &trace_path,
        serde_json::to_string_pretty(&trace_events()).expect("trace json"),
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["trace", "export", "--trace"])
        .arg(&trace_path)
        .args([
            "--provider",
            "runwarden.input.inspect",
            "--offset",
            "1",
            "--limit",
            "1",
            "--compact-refs",
            "--json",
        ])
        .output()
        .expect("run trace export");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""total_matching": 2"#));
    assert!(stdout.contains(r#""obs_id": "obs_2""#));
    assert!(stdout.contains(r#""compact_refs": ["#));
}
