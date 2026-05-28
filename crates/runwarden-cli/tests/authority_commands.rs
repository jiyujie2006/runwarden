use std::{fs, process::Command};

use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::evidence::hex_sha256;
use tempfile::tempdir;

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
path = "{}"

[active_assessment]
enabled = true
"#,
            dir.path().display()
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
    let arguments = serde_json::json!({
        "input_path": input_path.to_string_lossy(),
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
}
