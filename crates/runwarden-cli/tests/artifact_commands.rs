use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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
    let workspace = workspace_root();
    let target = workspace.join("target");
    fs::create_dir_all(&target).expect("target dir");
    let dir = tempfile::Builder::new()
        .prefix("runwarden-artifact-submission-")
        .tempdir_in(&target)
        .expect("tempdir in workspace target");
    let output_arg = dir
        .path()
        .strip_prefix(&workspace)
        .expect("relative output")
        .to_path_buf();

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["artifact", "submission", "--full", "--output"])
        .arg(&output_arg)
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

#[test]
fn artifact_submission_command_rejects_absolute_parent_and_symlink_output_paths() {
    let workspace = workspace_root();
    let outside = tempdir().expect("outside");

    let absolute = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args(["artifact", "submission", "--output"])
        .arg(outside.path().join("absolute-artifacts"))
        .arg("--json")
        .output()
        .expect("run absolute output case");
    assert!(!absolute.status.success());
    assert!(!outside.path().join("absolute-artifacts").exists());

    let traversal = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(&workspace)
        .args([
            "artifact",
            "submission",
            "--output",
            "../artifact-traversal",
            "--json",
        ])
        .output()
        .expect("run traversal output case");
    assert!(!traversal.status.success());
    assert!(!workspace.join("../artifact-traversal").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link_path = workspace.join("target/runwarden-artifact-output-link");
        let _ = fs::remove_file(&link_path);
        symlink(outside.path(), &link_path).expect("symlink");
        let symlink_arg = link_path
            .strip_prefix(&workspace)
            .expect("relative symlink")
            .to_path_buf();
        let symlinked = Command::new(env!("CARGO_BIN_EXE_runwarden"))
            .current_dir(&workspace)
            .args(["artifact", "submission", "--output"])
            .arg(&symlink_arg)
            .arg("--json")
            .output()
            .expect("run symlink output case");
        let _ = fs::remove_file(&link_path);
        assert!(!symlinked.status.success());
        assert!(!outside.path().join("artifact-manifest.json").exists());
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}
