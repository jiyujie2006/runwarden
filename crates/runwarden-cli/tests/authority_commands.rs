use std::{fs, process::Command};

use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::evidence::hex_sha256;
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
            "approval-stdio-1",
            "--session",
            "enterprise_ops",
            "--provider",
            "external.mcp.browser.open_page",
            "--action",
            "open_page",
            "--arguments",
            r#"{"url":"https://example.com"}"#,
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
    assert!(create_stdout.contains(r#""approval_id": "approval-stdio-1""#));
    assert!(create_stdout.contains(r#""state": "pending""#));
    assert!(create_stdout.contains("external.mcp.browser.open_page"));
    assert!(
        dir.path()
            .join(".runwarden/approvals/approval-stdio-1.json")
            .exists()
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["authority", "inspect", "approval-stdio-1", "--json"])
        .output()
        .expect("authority inspect");

    assert!(
        inspect.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("utf8 stdout");
    assert!(inspect_stdout.contains(r#""provider": "external.mcp.browser.open_page""#));
    assert!(inspect_stdout.contains(r#""action": "open_page""#));
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
            "enterprise_ops",
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
fn authority_create_reports_invalid_approval_id_before_malformed_arguments() {
    let dir = tempdir().expect("tempdir");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "authority",
            "create",
            "--approval",
            "../approval-1",
            "--session",
            "enterprise_ops",
            "--provider",
            "runwarden.report.render",
            "--action",
            "render",
            "--arguments",
            "{",
        ])
        .output()
        .expect("authority create invalid id and malformed arguments");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("invalid record id: ../approval-1"));
    assert!(!stderr.contains("EOF while parsing"));
    assert!(!dir.path().join(".runwarden/approvals").exists());
}

#[cfg(unix)]
#[test]
fn provider_call_executes_external_mcp_stdio_adapter_from_manifest() {
    let dir = tempdir().expect("tempdir");
    let session_manifest_path = dir.path().join("assessment.toml");
    fs::write(
        &session_manifest_path,
        format!(
            r#"
version = "1"
name = "external mcp session"
mode = "audit"
provider_allowlist = ["external.mcp.browser.open_page"]

[[roots]]
name = "workspace"
path = {}

[active_assessment]
enabled = true
"#,
            toml_basic_string(&dir.path().to_string_lossy())
        ),
    )
    .expect("write session manifest");
    let manifest_path = dir.path().join("external-mcp.json");
    fs::write(
        &manifest_path,
        format!(
            r#"{{
              "schema_version": "1",
              "provider_id": "external.mcp.browser.open_page",
              "provider_class": "external",
              "kind": "mcp",
              "risk": "high",
              "side_effects": ["process_spawn"],
              "transport": "stdio",
              "downstream_identity": "browser-mcp",
              "tool_identity": "open_page",
              "declared_permissions": ["process_spawn"],
              "allowed_origins": [],
              "command_allowlist": ["cat"],
              "working_root": "{}",
              "schema_pin": {{
                "algorithm": "sha256",
                "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
                "schema": {{"type": "object"}}
              }},
              "observed_schema": {{"type": "object"}}
            }}"#,
            dir.path().display()
        ),
    )
    .expect("write manifest");
    let input_path = dir.path().join("adapter-request.json");
    fs::write(
        &input_path,
        serde_json::json!({
            "manifest_path": manifest_path,
            "transport": "stdio",
            "command": "cat",
            "cwd": dir.path(),
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "open_page",
                "params": {"url": "https://example.com"}
            }
        })
        .to_string(),
    )
    .expect("write request");
    let create_session = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "create", "--manifest"])
        .arg(&session_manifest_path)
        .args(["--session", "enterprise_ops", "--json"])
        .output()
        .expect("session create");
    assert!(
        create_session.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&create_session.stderr)
    );
    let request_bytes = fs::read(&input_path).expect("request bytes");
    let manifest_bytes = fs::read(&manifest_path).expect("manifest bytes");
    let arguments = serde_json::json!({
        "input_path": input_path.to_string_lossy(),
        "input_path_sha256": hex_sha256(&request_bytes),
        "manifest_path": manifest_path.to_string_lossy(),
        "manifest_path_sha256": hex_sha256(&manifest_bytes),
        "root": "workspace"
    });
    let mut approval = ApprovalRecord::new(
        "approval-1",
        ApprovalBinding {
            session_id: "enterprise_ops".to_string(),
            provider: "external.mcp.browser.open_page".to_string(),
            action: "open_page".to_string(),
            argument_hash: hex_sha256(
                &serde_json::to_vec(&arguments).expect("arguments serialize"),
            ),
            authz_id: None,
            actor_id: None,
        },
    );
    approval
        .approve("reviewer-alice", "reviewed stdio adapter execution")
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
            "enterprise_ops",
            "--provider",
            "external.mcp.browser.open_page",
            "--input",
        ])
        .arg(&input_path)
        .arg("--root")
        .arg("workspace")
        .arg("--json")
        .output()
        .expect("external mcp provider call");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""provider": "external.mcp.browser.open_page""#));
    assert!(stdout.contains(r#""transport": "stdio""#));
    assert!(stdout.contains(r#""execution_status": "completed""#));
    assert!(stdout.contains(r#""side_effect_executed": true"#));
    assert!(stdout.contains("Content-Length:"));
    let saved_approval =
        fs::read_to_string(approval_dir.join("approval-1.json")).expect("saved approval");
    assert!(saved_approval.contains(r#""state": "consumed""#));
}

#[test]
fn provider_call_denies_external_mcp_manifest_path_outside_session_root() {
    let dir = tempdir().expect("tempdir");
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let session_manifest_path = dir.path().join("assessment.toml");
    fs::write(
        &session_manifest_path,
        format!(
            r#"
version = "1"
name = "external mcp session"
mode = "audit"
provider_allowlist = ["external.mcp.browser.open_page"]

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
    let outside_manifest = dir.path().join("external-mcp-manifest-dir");
    fs::create_dir(&outside_manifest).expect("outside manifest dir");
    let input_path = workspace.join("adapter-request.json");
    fs::write(
        &input_path,
        serde_json::json!({
            "manifest_path": outside_manifest,
            "transport": "stdio",
            "command": "cat",
            "cwd": workspace,
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "open_page",
                "params": {"url": "https://example.com"}
            }
        })
        .to_string(),
    )
    .expect("write request");
    let create_session = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "create", "--manifest"])
        .arg(&session_manifest_path)
        .args(["--session", "enterprise_ops", "--json"])
        .output()
        .expect("session create");
    assert!(
        create_session.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&create_session.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "provider",
            "call",
            "--session",
            "enterprise_ops",
            "--provider",
            "external.mcp.browser.open_page",
            "--input",
        ])
        .arg(&input_path)
        .arg("--root")
        .arg("workspace")
        .arg("--json")
        .output()
        .expect("external mcp provider call");

    assert!(
        output.status.success(),
        "stderr should not expose a pre-gate manifest read: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""decision": "denied""#));
    assert!(stdout.contains(r#""error_kind": "root_escape""#));
    assert!(stdout.contains(r#""gate_id": "root""#));
    assert!(!stdout.contains("No such file"));
    assert!(!stdout.contains(r#""side_effect_executed": true"#));
}

#[test]
fn provider_call_verifies_bound_files_before_persisting_consumed_approval() {
    let source = include_str!("../../runwarden-platform/src/executor.rs");
    let verify_index = source
        .find("verify_file_digests(&call)")
        .expect("provider call digest verification");
    let persist_index = source
        .find("persist_consumed_approval(self,")
        .expect("approval persistence");

    assert!(
        verify_index < persist_index,
        "bound file digests must be verified before approval consumption is persisted"
    );
}
