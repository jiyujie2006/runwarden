use std::{fs, path::Path, process::Command};

use runwarden_kernel::artifact::{ArtifactManifest, ArtifactManifestEntry};
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord};
use tempfile::tempdir;

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
    let dir = tempdir().expect("tempdir");
    write_workspace_markers(dir.path());
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["ui", "--bind", "127.0.0.1", "--port", "8088", "--artifacts"])
        .arg("artifacts")
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
    assert!(stdout.contains(r#""launch_url": "file://"#));
    assert!(stdout.contains(r#""script_path": "#));
    assert!(dir.path().join("artifacts/reviewer-console.html").exists());
    assert!(dir.path().join("artifacts/reviewer-console.js").exists());
}

#[test]
fn ui_launch_bundle_contains_responsive_accessibility_contract() {
    let dir = tempdir().expect("tempdir");
    write_workspace_markers(dir.path());

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["ui", "--bind", "127.0.0.1", "--port", "8088", "--artifacts"])
        .arg("artifacts")
        .arg("--json")
        .output()
        .expect("run ui command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let html = fs::read_to_string(dir.path().join("artifacts/reviewer-console.html"))
        .expect("read ui bundle");
    assert!(html.contains("data-local-api-url=\"http://127.0.0.1:8088\""));
    assert!(html.contains("name=\"viewport\""));
    assert!(html.contains("aria-label=\"Runwarden sections\""));
    assert!(html.contains("aria-label=\"Approval details\""));
    assert!(html.contains("class=\"nav-brand\""));
    assert!(html.contains("class=\"command-bar\""));
    assert!(html.contains("Trusted side effects"));
    assert!(html.contains("role=\"status\""));
    assert!(html.contains("Agent Boundary"));
    assert!(html.contains("Provider Registry"));
    assert!(html.contains("Accountability"));
    assert!(html.contains("Assurance"));
    assert!(html.contains("href=\"#assurance\""));
    assert!(html.contains("Settings"));
    assert!(html.contains("@media (max-width: 768px)"));
    assert!(html.contains("<script src=\"reviewer-console.js\" defer></script>"));
    assert!(html.contains("class=\"state-badge\""));
    assert!(html.contains("class=\"module-head\""));
    assert!(html.contains("0 pending"));
    assert_eq!(html.matches("No actions waiting for review").count(), 1);
    assert!(html.contains("repeating-linear-gradient"));
    assert!(!html.contains("radial-gradient"));
    assert!(!html.contains("4vw"));
    assert!(html.contains("position: fixed"));
    assert!(html.contains("min-height: 44px"));
    assert!(html.contains(":focus-visible"));
    assert!(!html.contains("data-action=\"approve\""));
    assert!(!html.contains("data-action=\"deny\""));
    assert!(!html.contains("<script>"));
}

#[test]
fn ui_launch_bundle_escapes_bind_in_generated_html() {
    let dir = tempdir().expect("tempdir");
    write_workspace_markers(dir.path());

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "ui",
            "--bind",
            "<img src=x onerror=alert(1)>",
            "--port",
            "8088",
            "--artifacts",
        ])
        .arg("artifacts")
        .arg("--json")
        .output()
        .expect("run ui command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let html = fs::read_to_string(dir.path().join("artifacts/reviewer-console.html"))
        .expect("read ui bundle");
    assert!(!html.contains("<img src=x onerror=alert(1)>"));
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
}

#[test]
fn ui_command_rejects_absolute_parent_and_symlink_artifacts_paths() {
    let workspace = tempdir().expect("workspace");
    write_workspace_markers(workspace.path());
    let outside = tempdir().expect("outside");

    let absolute = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace.path())
        .args(["ui", "--artifacts"])
        .arg(outside.path().join("ui-absolute"))
        .arg("--json")
        .output()
        .expect("run absolute path case");
    assert!(!absolute.status.success());
    assert!(
        !outside
            .path()
            .join("ui-absolute/reviewer-console.html")
            .exists()
    );

    let traversal = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(workspace.path())
        .args(["ui", "--artifacts", "../ui-traversal", "--json"])
        .output()
        .expect("run traversal path case");
    assert!(!traversal.status.success());
    assert!(
        !workspace
            .path()
            .join("../ui-traversal/reviewer-console.html")
            .exists()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        symlink(outside.path(), workspace.path().join("ui-link")).expect("symlink");
        let symlinked = Command::new(env!("CARGO_BIN_EXE_runwarden"))
            .current_dir(workspace.path())
            .args(["ui", "--artifacts", "ui-link", "--json"])
            .output()
            .expect("run symlink path case");
        assert!(!symlinked.status.success());
        assert!(!outside.path().join("reviewer-console.html").exists());
    }
}

#[test]
fn ui_command_renders_pending_approvals_with_reviewer_controls() {
    let dir = tempdir().expect("tempdir");
    write_workspace_markers(dir.path());
    write_pending_approval(dir.path(), "approval-1");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["ui", "--artifacts", "artifacts", "--json"])
        .output()
        .expect("run ui command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let html = fs::read_to_string(dir.path().join("artifacts/reviewer-console.html"))
        .expect("read ui bundle");
    assert!(html.contains("approval-1"));
    assert!(html.contains("runwarden.report.render"));
    assert!(html.contains("render"));
    assert!(html.contains("arg_hash_1"));
    assert!(html.contains("agent-1"));
    assert!(html.contains("authz-1"));
    assert!(html.contains("class=\"risk-chip\""));
    assert!(html.contains("1 pending"));
    assert!(html.contains("class=\"approval-decision-form\""));
    assert!(html.contains("id=\"local-api-token\""));
    assert!(html.contains("data-action=\"approve\""));
    assert!(html.contains("data-action=\"deny\""));
    assert!(html.contains("<textarea"));
    assert!(!html.contains("No actions waiting for review"));
}

#[test]
fn ui_command_summarizes_existing_reports_artifacts_and_assurance_files() {
    let dir = tempdir().expect("tempdir");
    write_workspace_markers(dir.path());
    let artifacts = dir.path().join("artifacts");
    fs::create_dir_all(artifacts.join("reports")).expect("reports dir");
    fs::create_dir_all(artifacts.join("release")).expect("release dir");
    fs::write(artifacts.join("reports/submission.md"), "report").expect("report");
    fs::write(artifacts.join("release/agent-native-eval.json"), "{}").expect("eval");
    fs::write(artifacts.join("release/bench-report.json"), "{}").expect("bench");
    let manifest = ArtifactManifest {
        schema_version: "0.1".to_string(),
        artifacts: vec![ArtifactManifestEntry {
            artifact_id: "submission-report".to_string(),
            relative_path: "reports/submission.md".to_string(),
            sha256: None,
            redaction_sidecar_path: None,
            redaction_sidecar_sha256: None,
            obs_refs: vec!["obs_1".to_string()],
        }],
    };
    fs::write(
        artifacts.join("artifact-manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest json"),
    )
    .expect("manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["ui", "--artifacts", "artifacts", "--json"])
        .output()
        .expect("run ui command");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let html = fs::read_to_string(artifacts.join("reviewer-console.html")).expect("read ui bundle");
    assert!(html.contains("1 report file"));
    assert!(html.contains("1 sealed artifact"));
    assert!(html.contains("2 assurance result"));
    assert!(html.contains("submission-report"));
    assert!(html.contains("module-success"));
    assert!(!html.contains("No report rendered"));
    assert!(!html.contains("No artifacts generated"));
    assert!(!html.contains("No eval run yet"));
}

fn write_workspace_markers(dir: &Path) {
    fs::write(dir.join("Cargo.toml"), "[workspace]\n").expect("Cargo.toml");
    fs::write(dir.join("package.json"), "{}\n").expect("package.json");
}

fn write_pending_approval(dir: &Path, id: &str) {
    let approval = ApprovalRecord::new(
        id.to_string(),
        ApprovalBinding {
            session_id: "session-1".to_string(),
            provider: "runwarden.report.render".to_string(),
            action: "render".to_string(),
            argument_hash: "arg_hash_1".to_string(),
            authz_id: Some("authz-1".to_string()),
            actor_id: Some("agent-1".to_string()),
        },
    );
    let approvals = dir.join(".runwarden/approvals");
    fs::create_dir_all(&approvals).expect("approvals dir");
    fs::write(
        approvals.join(format!("{id}.json")),
        serde_json::to_string_pretty(&approval).expect("approval json"),
    )
    .expect("approval file");
}
