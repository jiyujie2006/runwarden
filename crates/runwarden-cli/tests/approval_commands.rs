use std::{fs, process::Command};

use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord};
use tempfile::tempdir;

fn approval_record(id: &str) -> ApprovalRecord {
    ApprovalRecord::new(
        id,
        ApprovalBinding {
            session_id: "enterprise_ops".to_string(),
            provider: "runwarden.report.render".to_string(),
            action: "render".to_string(),
            argument_hash: "arg_hash_1".to_string(),
            authz_id: Some("authz-1".to_string()),
            actor_id: Some("agent-1".to_string()),
        },
    )
}

fn write_approval(dir: &std::path::Path, approval: &ApprovalRecord) {
    let approvals_dir = dir.join(".runwarden/approvals");
    fs::create_dir_all(&approvals_dir).expect("approvals dir");
    fs::write(
        approvals_dir.join(format!("{}.json", approval.approval_id)),
        serde_json::to_string_pretty(approval).expect("approval json"),
    )
    .expect("write approval");
}

#[test]
fn approval_pending_lists_only_pending_records() {
    let dir = tempdir().expect("tempdir");
    let pending = approval_record("approval-1");
    let mut approved = approval_record("approval-2");
    approved
        .approve("reviewer_alice", "reviewed scope and risk")
        .expect("approve");
    write_approval(dir.path(), &pending);
    write_approval(dir.path(), &approved);

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["approval", "pending", "--json"])
        .output()
        .expect("approval pending");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("approval-1"));
    assert!(!stdout.contains("approval-2"));
    assert!(stdout.contains("runwarden.report.render"));
    assert!(stdout.contains("arg_hash_1"));
}

#[test]
fn approval_commands_reject_path_traversal_record_ids() {
    let dir = tempdir().expect("tempdir");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "approval",
            "approve",
            "../approval-1",
            "--reviewer",
            "reviewer_alice",
            "--reason",
            "reviewed scope and risk",
        ])
        .output()
        .expect("approval approve invalid id");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("invalid record id"));
}

#[test]
fn approval_approve_requires_reason_and_updates_record() {
    let dir = tempdir().expect("tempdir");
    write_approval(dir.path(), &approval_record("approval-1"));

    let missing_reason = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "approval",
            "approve",
            "approval-1",
            "--reviewer",
            "reviewer_alice",
        ])
        .output()
        .expect("approval approve missing reason");
    assert!(!missing_reason.status.success());

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "approval",
            "approve",
            "approval-1",
            "--reviewer",
            "reviewer_alice",
            "--reason",
            "reviewed scope and risk",
            "--json",
        ])
        .output()
        .expect("approval approve");
    assert!(output.status.success());

    let saved = fs::read_to_string(dir.path().join(".runwarden/approvals/approval-1.json"))
        .expect("saved approval");
    assert!(saved.contains(r#""state": "approved""#));
    assert!(saved.contains("reviewer_alice"));
    assert!(saved.contains("reviewed scope and risk"));
}

#[test]
fn approval_deny_requires_reason_and_updates_record() {
    let dir = tempdir().expect("tempdir");
    write_approval(dir.path(), &approval_record("approval-1"));

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args([
            "approval",
            "deny",
            "approval-1",
            "--reviewer",
            "reviewer_alice",
            "--reason",
            "out of scope",
            "--json",
        ])
        .output()
        .expect("approval deny");
    assert!(output.status.success());

    let saved = fs::read_to_string(dir.path().join(".runwarden/approvals/approval-1.json"))
        .expect("saved approval");
    assert!(saved.contains(r#""state": "denied""#));
    assert!(saved.contains("out of scope"));
}
