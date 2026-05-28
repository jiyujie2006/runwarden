use std::fs;

use runwarden_providers::evidence::{
    EvidenceInspectPolicy, EvidenceViolationKind, inspect_evidence_root,
};
use tempfile::tempdir;

#[test]
fn evidence_inspect_indexes_allowed_files_with_hashes() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("finding.txt"), "evidence").expect("write");
    fs::write(dir.path().join("ignore.bin"), "binary").expect("write");

    let result = inspect_evidence_root(
        dir.path(),
        EvidenceInspectPolicy {
            allowed_extensions: ["txt".to_string()].into(),
            ..EvidenceInspectPolicy::default()
        },
    )
    .expect("inspect evidence");

    assert_eq!(result.files.len(), 1);
    assert_eq!(result.files[0].relative_path, "finding.txt");
    assert_eq!(result.files[0].size_bytes, 8);
    assert!(result.files[0].sha256.is_some());
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.kind == EvidenceViolationKind::ExtensionDenied)
    );
}

#[test]
fn evidence_inspect_enforces_file_count_and_size_limits() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), "small").expect("write");
    fs::write(dir.path().join("b.txt"), "large file").expect("write");

    let result = inspect_evidence_root(
        dir.path(),
        EvidenceInspectPolicy {
            max_files: 1,
            max_file_bytes: 5,
            allowed_extensions: ["txt".to_string()].into(),
        },
    )
    .expect("inspect evidence");

    assert!(result.truncated);
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.kind == EvidenceViolationKind::FileCountLimit)
    );
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.kind == EvidenceViolationKind::FileTooLarge)
    );
}

#[cfg(unix)]
#[test]
fn evidence_inspect_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().expect("tempdir");
    let outside = tempdir().expect("outside");
    fs::write(outside.path().join("secret.txt"), "secret").expect("write outside");
    symlink(
        outside.path().join("secret.txt"),
        dir.path().join("link.txt"),
    )
    .expect("symlink");

    let result = inspect_evidence_root(
        dir.path(),
        EvidenceInspectPolicy {
            allowed_extensions: ["txt".to_string()].into(),
            ..EvidenceInspectPolicy::default()
        },
    )
    .expect("inspect evidence");

    assert!(result.files.is_empty());
    assert!(
        result
            .violations
            .iter()
            .any(|violation| violation.kind == EvidenceViolationKind::SymlinkEscape)
    );
}
