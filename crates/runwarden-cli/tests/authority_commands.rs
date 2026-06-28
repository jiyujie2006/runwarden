use std::{fs, process::Command};

use runwarden_kernel::{
    authority::{ApprovalBinding, ApprovalRecord, ApprovalState},
    evidence::hex_sha256,
};
use tempfile::tempdir;

fn toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

#[test]
fn authority_create_and_inspect_manage_bound_approval_records() {
    let dir = tempdir().expect("tempdir");

    let create = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "authority",
            "create",
            "--approval",
            "approval-api-1",
            "--session",
            "contest_ops",
            "--provider",
            "external.api.request",
            "--action",
            "request",
            "--arguments",
            r#"{"url":"https://api.example.com/upload"}"#,
            "--authz",
            "authz-1",
            "--actor",
            "agent-1",
            "--json",
        ])
        .output()
        .expect("authority create");

    assert!(
        create.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&create.stderr)
    );
    let create_stdout = String::from_utf8(create.stdout).expect("utf8 stdout");
    assert!(create_stdout.contains(r#""approval_id": "approval-api-1""#));
    assert!(create_stdout.contains(r#""state": "pending""#));
    assert!(create_stdout.contains("external.api.request"));
    assert!(
        dir.path()
            .join(".runwarden/approvals/approval-api-1.json")
            .exists()
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["authority", "inspect", "approval-api-1", "--json"])
        .output()
        .expect("authority inspect");

    assert!(inspect.status.success());
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("utf8 stdout");
    assert!(inspect_stdout.contains(r#""provider": "external.api.request""#));
    assert!(inspect_stdout.contains(r#""action": "request""#));
    assert!(inspect_stdout.contains(r#""authz_id": "authz-1""#));
    assert!(inspect_stdout.contains(r#""actor_id": "agent-1""#));
}

#[test]
fn authority_create_rejects_path_traversal_approval_ids() {
    let dir = tempdir().expect("tempdir");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "authority",
            "create",
            "--approval",
            "../approval-1",
            "--session",
            "contest_ops",
            "--provider",
            "runwarden.report.render",
            "--action",
            "render",
            "--arguments",
            "{}",
        ])
        .output()
        .expect("authority create invalid id");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("invalid record id"));
    assert!(!dir.path().join(".runwarden/approvals").exists());
}

#[test]
fn provider_call_consumes_matching_external_provider_approval_after_policy_allow() {
    let dir = tempdir().expect("tempdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let session_manifest_path = dir.path().join("assessment.toml");
    fs::write(
        &session_manifest_path,
        format!(
            r#"
version = "1"
name = "contest external session"
mode = "audit"
provider_allowlist = ["external.api.request"]

[[roots]]
name = "workspace"
path = {}

[active_assessment]
enabled = true
"#,
            toml_basic_string(&workspace.to_string_lossy())
        ),
    )
    .expect("write session manifest");
    let input_path = workspace.join("api-request.json");
    fs::write(
        &input_path,
        serde_json::json!({"url": "https://api.example.com/upload"}).to_string(),
    )
    .expect("write request");
    let create_session = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "create", "--manifest"])
        .arg(&session_manifest_path)
        .args(["--session", "contest_ops", "--json"])
        .output()
        .expect("session create");
    assert!(create_session.status.success());

    let request_bytes = fs::read(&input_path).expect("request bytes");
    let arguments = serde_json::json!({
        "input_path": input_path.to_string_lossy(),
        "root": "workspace",
        "input_path_sha256": hex_sha256(&request_bytes)
    });
    let mut approval = ApprovalRecord::new(
        "approval-1",
        ApprovalBinding {
            session_id: "contest_ops".to_string(),
            provider: "external.api.request".to_string(),
            action: "request".to_string(),
            argument_hash: hex_sha256(
                &serde_json::to_vec(&arguments).expect("arguments serialize"),
            ),
            authz_id: None,
            actor_id: None,
        },
    );
    approval
        .approve("reviewer-alice", "reviewed external API demo call")
        .expect("approval can be approved");
    let mut stale_approval = ApprovalRecord::new("approval-0", approval.binding.clone());
    stale_approval.state = ApprovalState::Consumed;
    let approval_dir = dir.path().join(".runwarden/approvals");
    fs::create_dir_all(&approval_dir).expect("approval dir");
    fs::write(
        approval_dir.join("approval-0.json"),
        serde_json::to_string_pretty(&stale_approval).expect("stale approval json"),
    )
    .expect("write stale approval");
    fs::write(
        approval_dir.join("approval-1.json"),
        serde_json::to_string_pretty(&approval).expect("approval json"),
    )
    .expect("write approval");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "provider",
            "call",
            "--session",
            "contest_ops",
            "--provider",
            "external.api.request",
            "--input",
        ])
        .arg(&input_path)
        .arg("--root")
        .arg("workspace")
        .arg("--json")
        .output()
        .expect("external provider call");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""provider": "external.api.request""#));
    assert!(stdout.contains(r#""simulated": true"#));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
    let saved_approval =
        fs::read_to_string(approval_dir.join("approval-1.json")).expect("saved approval");
    assert!(saved_approval.contains(r#""state": "consumed""#));
}

#[test]
fn provider_call_verifies_bound_files_before_persisting_consumed_approval() {
    let source = include_str!("../src/main.rs");
    let verify_index = source
        .find("verify_cli_file_digests(&call)?;")
        .expect("provider call digest verification");
    let persist_index = source
        .find("persist_consumed_cli_approval(")
        .expect("approval persistence");

    assert!(
        verify_index < persist_index,
        "bound file digests must be verified before approval consumption is persisted"
    );
}
