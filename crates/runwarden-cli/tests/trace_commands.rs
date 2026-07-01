use std::{fs, process::Command};

use runwarden_kernel::evidence::{TraceEvent, hex_sha256};
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
fn trace_verify_command_accepts_jsonl_hash_chain() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.jsonl");
    fs::write(
        &trace_path,
        trace_events()
            .into_iter()
            .map(|event| serde_json::to_string(&event).expect("trace event json"))
            .collect::<Vec<_>>()
            .join("\n"),
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
fn trace_verify_command_rejects_malformed_jsonl() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.jsonl");
    fs::write(&trace_path, "{not json}\n").expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["trace", "verify", "--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run trace verify");

    assert!(!output.status.success());
}

#[test]
fn trace_verify_command_rejects_jsonl_missing_event_hash() {
    let dir = tempdir().expect("tempdir");
    let trace_path = dir.path().join("trace.jsonl");
    fs::write(
        &trace_path,
        r#"{"obs_id":"obs_1","event_type":"model_call","provider":"mock","payload":{"decision":"allowed"},"previous_hash":null}"#,
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["trace", "verify", "--trace"])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run trace verify");

    assert!(!output.status.success());
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
fn provider_call_trace_export_rejects_tampered_events_without_returning_events() {
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("assessment.toml");
    let trace_path = dir.path().join("trace.json");
    fs::write(
        &manifest_path,
        r#"
version = "0.1"
name = "trace-export-session"
mode = "offline"
provider_allowlist = ["runwarden.trace.export"]

[[roots]]
name = "workspace"
path = "."

[active_assessment]
enabled = true
"#,
    )
    .expect("write manifest");
    let session = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "create", "--manifest"])
        .arg(&manifest_path)
        .args(["--session", "contest_ops", "--json"])
        .output()
        .expect("create session");
    assert!(
        session.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&session.stderr)
    );
    let mut trace = trace_events();
    trace[1].payload = json!({"status":"rewritten"});
    fs::write(
        &trace_path,
        serde_json::to_string_pretty(&trace).expect("trace json"),
    )
    .expect("write trace");
    let trace_digest = hex_sha256(&fs::read(&trace_path).expect("read trace"));
    let arguments = json!({
        "trace_path": trace_path.to_string_lossy(),
        "trace_path_sha256": trace_digest
    });
    let argument_hash =
        hex_sha256(&serde_json::to_vec(&arguments).expect("provider call arguments serialize"));
    let approval = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "authority",
            "create",
            "--approval",
            "approval-trace-export",
            "--session",
            "contest_ops",
            "--provider",
            "runwarden.trace.export",
            "--action",
            "export",
            "--argument-hash",
            &argument_hash,
            "--json",
        ])
        .output()
        .expect("create approval");
    assert!(
        approval.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&approval.stderr)
    );
    let approved = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "approval",
            "approve",
            "approval-trace-export",
            "--reviewer",
            "reviewer-alice",
            "--reason",
            "trace export regression",
            "--json",
        ])
        .output()
        .expect("approve trace export");
    assert!(
        approved.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&approved.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "provider",
            "call",
            "--session",
            "contest_ops",
            "--provider",
            "runwarden.trace.export",
            "--trace",
        ])
        .arg(&trace_path)
        .arg("--json")
        .output()
        .expect("run trace export provider call");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let response: serde_json::Value =
        serde_json::from_str(&stdout).expect("trace export provider json");
    assert_eq!(response["decision"].as_str(), Some("denied"));
    assert!(
        matches!(
            response["execution_status"].as_str(),
            Some("not_executed") | Some("failed")
        ),
        "tampered trace export must fail closed before returning events: {stdout}"
    );
    assert_eq!(
        response["output"]["verification"]["verified"].as_bool(),
        Some(false)
    );
    assert!(
        response["output"].get("events").is_none(),
        "tampered trace export must not return events: {stdout}"
    );
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
    let export: serde_json::Value = serde_json::from_str(&stdout).expect("trace export json");

    assert!(stdout.contains(r#""total_matching": 2"#));
    assert!(stdout.contains(r#""obs_id": "obs_2""#));
    assert!(stdout.contains(r#""compact_refs": ["#));
    assert_eq!(export["event_count"], 1);
    assert_eq!(
        export["events"]
            .as_array()
            .expect("events array")
            .iter()
            .map(|event| event["obs_id"].as_str().expect("obs id"))
            .collect::<Vec<_>>(),
        vec!["obs_2"]
    );
}
