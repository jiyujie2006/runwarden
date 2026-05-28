use std::{fs, process::Command};

use runwarden_assurance::artifact::seal_artifact;
use tempfile::tempdir;

#[test]
fn artifact_verify_command_accepts_valid_manifest() {
    let dir = tempdir().expect("tempdir");
    let manifest = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect("seal artifact");
    let manifest_path = dir.path().join("artifact-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["artifact", "verify", "--artifacts"])
        .arg(dir.path())
        .args(["--manifest"])
        .arg(&manifest_path)
        .arg("--json")
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
fn artifact_verify_command_fails_on_sidecar_mismatch() {
    let dir = tempdir().expect("tempdir");
    let manifest = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect("seal artifact");
    fs::write(
        dir.path().join("reports/report.md.redaction.json"),
        "{\"tampered\":true}\n",
    )
    .expect("tamper sidecar");
    let manifest_path = dir.path().join("artifact-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["artifact", "verify", "--artifacts"])
        .arg(dir.path())
        .args(["--manifest"])
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .expect("run artifact verify");

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("RedactionSidecarMismatch"));
}

#[test]
fn artifact_submission_command_generates_verifiable_release_bundle() {
    let dir = tempdir().expect("tempdir");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["artifact", "submission", "--full", "--output"])
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run artifact submission");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""artifact_count":"#) || stdout.contains(r#""artifact_count": "#));
    assert!(stdout.contains("sbom.spdx.json"));
    assert!(stdout.contains("provenance.json"));

    let manifest_path = dir.path().join("artifact-manifest.json");
    let verify = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["artifact", "verify", "--artifacts"])
        .arg(dir.path())
        .args(["--manifest"])
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .expect("run artifact verify");

    assert!(
        verify.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let stdout = String::from_utf8(verify.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""status": "verified""#));
}
