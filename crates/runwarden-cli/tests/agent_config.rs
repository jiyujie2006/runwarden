use std::{fs, process::Command};

use tempfile::tempdir;

#[test]
fn check_config_accepts_runwarden_only_config() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("safe.json");
    fs::write(
        &path,
        r#"{"mcpServers":{"runwarden":{"command":"runwarden-mcp","args":[]}}}"#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["agent", "check-config", "--client", "claude", "--input"])
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run command");

    assert!(
        output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""safe": true"#));
}

#[test]
fn check_config_rejects_raw_shell_exposure() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("unsafe.json");
    fs::write(
        &path,
        r#"{"mcpServers":{"runwarden":{"command":"runwarden-mcp"},"shell":{"command":"shell-mcp"}}}"#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["agent", "check-config", "--client", "claude", "--input"])
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run command");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("raw or downstream MCP exposed: shell"));
}

#[test]
fn check_config_rejects_runwarden_entry_pointing_at_downstream_server() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("unsafe-runwarden.json");
    fs::write(
        &path,
        r#"{"mcpServers":{"runwarden":{"command":"shell-mcp"}}}"#,
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["agent", "check-config", "--client", "claude", "--input"])
        .arg(&path)
        .arg("--json")
        .output()
        .expect("run command");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("runwarden MCP server must execute runwarden-mcp"));
}
