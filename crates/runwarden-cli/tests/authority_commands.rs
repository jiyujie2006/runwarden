use std::{fs, process::Command};

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

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "provider",
            "call",
            "--provider",
            "external.mcp.browser.open_page",
            "--input",
        ])
        .arg(&input_path)
        .arg("--root")
        .arg(dir.path())
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
