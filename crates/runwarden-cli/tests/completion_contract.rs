use std::{fs, path::PathBuf, process::Command};

use tempfile::tempdir;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn eval_all_json_runs_default_fixture_suite_without_report_args() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["eval", "all", "--json"])
        .output()
        .expect("run eval all");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": true"#));
    assert!(stdout.contains("trace_completeness"));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
}

#[test]
fn cert_matrix_subcommands_return_stable_json_contracts() {
    for subcommand in [
        "provider-manifest",
        "mcp",
        "skill",
        "workflow",
        "script",
        "package",
        "release-artifact",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
            .current_dir(workspace_root())
            .args(["cert", subcommand, "--json"])
            .output()
            .unwrap_or_else(|err| panic!("run cert {subcommand}: {err}"));

        assert!(
            output.status.success(),
            "cert {subcommand} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert!(
            stdout.contains(r#""passed": true"#),
            "{subcommand}: {stdout}"
        );
        assert!(stdout.contains(r#""side_effect_executed": false"#));
        assert!(stdout.contains(subcommand));
    }
}

#[test]
fn cert_provider_manifest_rejects_schema_rug_pull() {
    let dir = tempdir().expect("tempdir");
    let manifest = dir.path().join("provider-manifest.json");
    fs::write(
        &manifest,
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["https://example.com"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:expected",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object", "properties": {"url": {"type": "string"}}}
        }"#,
    )
    .expect("manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["cert", "provider-manifest", "--manifest"])
        .arg(&manifest)
        .arg("--json")
        .output()
        .expect("run cert provider-manifest");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": false"#));
    assert!(stdout.contains("schema_rug_pull"));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
}

#[test]
fn artifact_verify_json_uses_default_artifact_paths() {
    let dir = tempdir().expect("tempdir");
    let artifact_root = dir.path().join("artifacts");
    let submission = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["artifact", "submission", "--full", "--output"])
        .arg(&artifact_root)
        .arg("--json")
        .output()
        .expect("write submission bundle");
    assert!(
        submission.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&submission.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["artifact", "verify", "--json"])
        .output()
        .expect("run artifact verify");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""status": "verified""#));
}

#[test]
fn api_serve_dry_run_exposes_local_api_server_entrypoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args([
            "api",
            "serve",
            "--bind",
            "127.0.0.1",
            "--port",
            "0",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run api serve dry-run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""mode": "local_api_server""#));
    assert!(stdout.contains(r#""launch_token_generated": true"#));
    assert!(!stdout.contains("runwarden-local-dev"));
    assert!(stdout.contains("/providers"));
    assert!(stdout.contains("/provider-calls"));
    assert!(stdout.contains("/trace/export"));
    assert!(stdout.contains("/artifacts/submission"));
    assert!(stdout.contains("/eval/agent-native"));
    assert!(stdout.contains("/agent/config/check"));
    assert!(stdout.contains(r#""side_effect_executed": false"#));
}
