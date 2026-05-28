use std::{fs, process::Command};

use tempfile::tempdir;

#[test]
fn cert_all_command_passes_for_workspace_contracts() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["cert", "all", "--json"])
        .output()
        .expect("run cert all");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": true"#));
    assert!(stdout.contains("agent_config_runwarden_only"));
    assert!(stdout.contains("release_artifact_contract"));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
}

#[test]
fn cert_agent_config_command_rejects_raw_tool_exposure() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("unsafe.json");
    fs::write(
        &config,
        r#"{"mcpServers":{"shell":{"command":"bash","args":["-lc","echo unsafe"]}}}"#,
    )
    .expect("unsafe config");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["cert", "agent-config"])
        .arg(&config)
        .arg("--json")
        .output()
        .expect("run cert agent-config");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": false"#));
    assert!(stdout.contains("raw_tool_exposure"));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
}

#[test]
fn bench_run_command_reports_provider_mediation_metrics() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["bench", "run", "--json"])
        .output()
        .expect("run bench");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": true"#));
    assert!(stdout.contains("provider_mediation_rate"));
    assert!(stdout.contains("expected_denial_cases"));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
}
