use std::fs;

use runwarden_assurance::artifact::{
    ArtifactErrorKind, ArtifactVerificationStatus, seal_artifact, verify_artifact_manifest,
};
use tempfile::tempdir;

#[test]
fn artifact_seal_rejects_unredacted_secret_before_write() {
    let dir = tempdir().expect("tempdir");
    let error = seal_artifact(
        dir.path(),
        "report-md",
        "report.md",
        "finding\nTOKEN=secret\n",
    )
    .expect_err("unredacted secret must fail closed");

    assert_eq!(error.kind, ArtifactErrorKind::RedactionFailed);
    assert!(!error.side_effect_executed);
    assert!(!dir.path().join("report.md").exists());
}

#[test]
fn artifact_seal_rejects_common_secret_formats() {
    let secret_examples = [
        "password=redacted\n",
        "api_key=redacted\n",
        "Authorization: Bearer redacted\n",
        "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n",
    ];

    for (index, contents) in secret_examples.iter().enumerate() {
        let dir = tempdir().expect("tempdir");
        let error = seal_artifact(
            dir.path(),
            format!("report-md-{index}"),
            format!("reports/report-{index}.md"),
            contents,
        )
        .expect_err("common secret format must fail closed");

        assert_eq!(error.kind, ArtifactErrorKind::RedactionFailed);
        assert!(!error.side_effect_executed);
        assert!(
            !dir.path()
                .join(format!("reports/report-{index}.md"))
                .exists()
        );
    }
}

#[test]
fn artifact_seal_writes_manifest_entry_and_redaction_sidecar_hashes() {
    let dir = tempdir().expect("tempdir");
    let manifest = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect("artifact sealed");

    let entry = &manifest.artifacts[0];
    assert_eq!(entry.artifact_id, "report-md");
    assert_eq!(entry.relative_path, "reports/report.md");
    assert!(entry.sha256.is_some());
    assert!(entry.redaction_sidecar_sha256.is_some());
    assert!(dir.path().join("reports/report.md").exists());
    assert!(dir.path().join("reports/report.md.redaction.json").exists());

    let verification = verify_artifact_manifest(dir.path(), &manifest);
    assert_eq!(verification.status, ArtifactVerificationStatus::Verified);
}

#[test]
fn artifact_verify_rejects_redaction_sidecar_mismatch() {
    let dir = tempdir().expect("tempdir");
    let manifest = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect("artifact sealed");
    fs::write(
        dir.path().join("reports/report.md.redaction.json"),
        "{\"tampered\":true}\n",
    )
    .expect("tamper sidecar");

    let verification = verify_artifact_manifest(dir.path(), &manifest);

    assert_eq!(verification.status, ArtifactVerificationStatus::Failed);
    assert!(
        verification
            .findings
            .iter()
            .any(|finding| finding.kind == ArtifactErrorKind::RedactionSidecarMismatch)
    );
}

#[test]
fn artifact_verify_rejects_semantically_mismatched_redaction_sidecar() {
    let dir = tempdir().expect("tempdir");
    let mut manifest = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect("artifact sealed");
    let sidecar_path = dir.path().join("reports/report.md.redaction.json");
    let sidecar_body = serde_json::json!({
        "artifact_id": "other-artifact",
        "redaction_applied": false,
        "redacted_patterns": [],
        "original_sha256": "wrong",
        "redacted_sha256": "wrong"
    })
    .to_string()
        + "\n";
    fs::write(&sidecar_path, &sidecar_body).expect("write semantic mismatch sidecar");
    manifest.artifacts[0].redaction_sidecar_sha256 = Some(runwarden_kernel::evidence::hex_sha256(
        sidecar_body.as_bytes(),
    ));

    let verification = verify_artifact_manifest(dir.path(), &manifest);

    assert_eq!(verification.status, ArtifactVerificationStatus::Failed);
    assert!(
        verification
            .findings
            .iter()
            .any(|finding| finding.kind == ArtifactErrorKind::RedactionSidecarMismatch)
    );
}

#[cfg(unix)]
#[test]
fn artifact_verify_rejects_redaction_sidecar_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("tempdir");
    let outside = tempdir().expect("outside");
    let manifest = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect("artifact sealed");
    fs::write(outside.path().join("sidecar.json"), "{\"outside\":true}\n")
        .expect("outside sidecar");
    let sidecar_path = dir.path().join("reports/report.md.redaction.json");
    fs::remove_file(&sidecar_path).expect("remove sidecar");
    symlink(outside.path().join("sidecar.json"), sidecar_path).expect("symlink");

    let verification = verify_artifact_manifest(dir.path(), &manifest);

    assert_eq!(verification.status, ArtifactVerificationStatus::Failed);
    assert!(
        verification
            .findings
            .iter()
            .any(|finding| finding.kind == ArtifactErrorKind::SymlinkEscape)
    );
}

#[test]
fn artifact_seal_rejects_path_escape() {
    let dir = tempdir().expect("tempdir");
    let error = seal_artifact(dir.path(), "escape", "../escape.md", "safe\n")
        .expect_err("path escape fails");

    assert_eq!(error.kind, ArtifactErrorKind::PathEscape);
    assert!(!error.side_effect_executed);
}

#[cfg(unix)]
#[test]
fn artifact_verify_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("tempdir");
    let outside = tempdir().expect("outside");
    fs::create_dir_all(dir.path().join("reports")).expect("reports dir");
    fs::write(outside.path().join("report.md"), "outside\n").expect("outside file");
    symlink(
        outside.path().join("report.md"),
        dir.path().join("reports/report.md"),
    )
    .expect("symlink");
    let manifest = seal_artifact(
        outside.path(),
        "report-md",
        "report.md",
        "finding cites obs_1\n",
    )
    .expect("outside artifact sealed");
    let mut manifest = manifest;
    manifest.artifacts[0].relative_path = "reports/report.md".to_string();

    let verification = verify_artifact_manifest(dir.path(), &manifest);

    assert_eq!(verification.status, ArtifactVerificationStatus::Failed);
    assert!(
        verification
            .findings
            .iter()
            .any(|finding| finding.kind == ArtifactErrorKind::SymlinkEscape)
    );
}

#[cfg(unix)]
#[test]
fn artifact_seal_rejects_symlink_target_before_write() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("tempdir");
    let outside = tempdir().expect("outside");
    fs::create_dir_all(dir.path().join("reports")).expect("reports dir");
    fs::write(outside.path().join("report.md"), "outside\n").expect("outside file");
    symlink(
        outside.path().join("report.md"),
        dir.path().join("reports/report.md"),
    )
    .expect("symlink");

    let error = seal_artifact(
        dir.path(),
        "report-md",
        "reports/report.md",
        "finding cites obs_1\n",
    )
    .expect_err("symlink target fails closed");

    assert_eq!(error.kind, ArtifactErrorKind::SymlinkEscape);
    assert!(!error.side_effect_executed);
    assert_eq!(
        fs::read_to_string(outside.path().join("report.md")).expect("outside unchanged"),
        "outside\n"
    );
}
