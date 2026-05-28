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
fn release_install_smoke_validates_cli_cert_bench_and_provider_mediation() {
    for args in [
        &["check", "--strict"][..],
        &["cert", "all", "--json"][..],
        &["bench", "run", "--json"][..],
        &[
            "provider",
            "call",
            "--provider",
            "runwarden.cert.all",
            "--json",
        ][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
            .args(args)
            .output()
            .expect("run smoke command");

        assert!(
            output.status.success(),
            "command {:?} failed\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn release_smoke_command_runs_release_evidence_checks() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["release", "smoke", "--json"])
        .output()
        .expect("run release smoke");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""passed": true"#));
    assert!(stdout.contains("agent_native"));
    assert!(stdout.contains("release_artifact_contract"));
}

#[test]
fn ui_command_writes_reviewer_console_launch_bundle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["ui", "--bind", "127.0.0.1", "--port", "8088", "--artifacts"])
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run ui command");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""bind": "127.0.0.1""#));
    assert!(stdout.contains(r#""port": 8088"#));
    assert!(dir.path().join("reviewer-console.html").exists());
}

#[test]
fn ui_launch_bundle_contains_responsive_accessibility_contract() {
    let dir = tempdir().expect("tempdir");
    let artifacts = dir.path().join("artifacts");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace_root())
        .args(["ui", "--bind", "127.0.0.1", "--port", "8088", "--artifacts"])
        .arg(&artifacts)
        .arg("--json")
        .output()
        .expect("run ui command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let html = fs::read_to_string(artifacts.join("reviewer-console.html")).expect("read ui bundle");
    assert!(html.contains("name=\"viewport\""));
    assert!(html.contains("aria-label=\"Runwarden sections\""));
    assert!(html.contains("aria-label=\"Approval details\""));
    assert!(html.contains("@media (max-width: 980px)"));
    assert!(html.contains("min-height: 44px"));
    assert!(html.contains(":focus-visible"));
    assert!(!html.contains("<script"));
}
