mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration as StdDuration;

use common::{
    FailingJournal, FailurePoint, INSTANCE_TOKEN, ManualClock, PostExecutionFailureMode,
    PostExecutionJournal, RecordingExecutor, RuntimeFixture, default_counting_executor,
    email_request, input_request,
};
use runwarden_kernel::operation::OperationState;
use runwarden_providers::executor::{DefaultProviderExecutor, ExecutorConfig, PermitAuthority};
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeError,
    SystemClock,
};
use runwarden_state::{ApprovalDecisionInput, ReviewerDecision, StateStore};
use time::format_description::well_known::Rfc3339;

fn approve_email(
    fixture: &RuntimeFixture,
    invocation_byte: u8,
) -> runwarden_kernel::story::OperationId {
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let runtime = OperationRuntime::new(
        fixture.store.clone(),
        RecordingExecutor::new(verifier),
        SystemClock,
        context,
        issuer,
        format!("reconciliation-prepare-{invocation_byte}"),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let pending = RuntimeApi::invoke(&runtime, email_request(invocation_byte)).unwrap();
    let approval = fixture
        .store
        .approval_for_operation(pending.operation_id)
        .unwrap()
        .unwrap();
    fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id: approval.approval_id,
            expected_version: approval.version,
            expected_operation_version: pending.operation_version,
            reviewer: "reconciliation-reviewer".to_owned(),
            reason: "approve exact operation for recovery test".to_owned(),
            decision: ReviewerDecision::Approve,
            now: time::OffsetDateTime::now_utc(),
        })
        .unwrap();
    pending.operation_id
}

fn directory_has_entry(path: &Path) -> bool {
    std::fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

#[test]
fn retained_email_evidence_reconciles_without_a_second_execution() {
    let fixture = RuntimeFixture::new();
    let operation_id = approve_email(&fixture, 140);
    let failing = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::ResultAndUnknown,
    );
    let context = RuntimeContextLoader::load(&failing, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        failing,
        executor,
        SystemClock,
        context,
        issuer,
        "email-before-reconcile".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    assert!(matches!(
        RuntimeApi::resume(&runtime, operation_id),
        Err(RuntimeError::JournalAfterExecution { .. })
    ));
    let execution = fixture
        .store
        .execution_runtime_snapshot(operation_id)
        .unwrap();
    assert_eq!(execution.operation.state, OperationState::Executing);
    assert!(directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
    drop(runtime);

    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let recovery_clock = ManualClock::new(execution.lease.expires_at);
    let (recovery_issuer, _) = PermitAuthority::generate().unwrap();
    let recovery_runtime = OperationRuntime::new(
        fixture.store.clone(),
        executor_probe.clone(),
        recovery_clock,
        context,
        recovery_issuer,
        "email-after-reconcile".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let recovered = RuntimeApi::resume(&recovery_runtime, operation_id).unwrap();
    assert_eq!(recovered.operation_state, OperationState::Completed);
    assert_eq!(executor_probe.call_count(), 1);
    assert_eq!(executor_probe.reconcile_count(), 1);
    assert!(!directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}

#[test]
fn process_cache_loss_reconciliation_worker() {
    if std::env::var_os("RUNWARDEN_RECONCILIATION_WORKER").is_none() {
        return;
    }
    let store =
        StateStore::open(std::env::var_os("RUNWARDEN_RECONCILIATION_STATE_DIR").unwrap()).unwrap();
    let operation_id = serde_json::from_value(serde_json::Value::String(
        std::env::var("RUNWARDEN_RECONCILIATION_OPERATION_ID").unwrap(),
    ))
    .unwrap();
    let lease_expiry = time::OffsetDateTime::parse(
        &std::env::var("RUNWARDEN_RECONCILIATION_LEASE_EXPIRY").unwrap(),
        &Rfc3339,
    )
    .unwrap();
    let sandbox_root =
        PathBuf::from(std::env::var_os("RUNWARDEN_RECONCILIATION_SANDBOX_ROOT").unwrap());
    let trusted_runtime_root =
        PathBuf::from(std::env::var_os("RUNWARDEN_RECONCILIATION_RUNTIME_ROOT").unwrap());
    let context =
        RuntimeContextLoader::load(&store, INSTANCE_TOKEN, time::OffsetDateTime::now_utc())
            .unwrap();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let executor = DefaultProviderExecutor::new(
        ExecutorConfig::new(
            sandbox_root,
            trusted_runtime_root,
            4_096,
            StdDuration::from_secs(2),
            verifier,
        )
        .unwrap(),
    );
    let runtime = OperationRuntime::new(
        store,
        executor,
        ManualClock::new(lease_expiry),
        context,
        issuer,
        "fresh-process-reconciliation".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let recovered = RuntimeApi::resume(&runtime, operation_id).unwrap();
    assert_eq!(recovered.operation_state, OperationState::Completed);
}

#[test]
fn retained_email_evidence_reconciles_after_real_process_cache_loss() {
    let fixture = RuntimeFixture::new();
    let operation_id = approve_email(&fixture, 145);
    let failing = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::ResultAndUnknown,
    );
    let context = RuntimeContextLoader::load(&failing, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        failing,
        executor,
        SystemClock,
        context,
        issuer,
        "parent-process-before-reconcile".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    assert!(matches!(
        RuntimeApi::resume(&runtime, operation_id),
        Err(RuntimeError::JournalAfterExecution { .. })
    ));
    let execution = fixture
        .store
        .execution_runtime_snapshot(operation_id)
        .unwrap();
    assert_eq!(execution.operation.state, OperationState::Executing);
    assert_eq!(executor_probe.call_count(), 1);
    assert!(directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
    drop(runtime);

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_cache_loss_reconciliation_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RUNWARDEN_RECONCILIATION_WORKER", "1")
        .env(
            "RUNWARDEN_RECONCILIATION_STATE_DIR",
            fixture._temp.path().join("state"),
        )
        .env(
            "RUNWARDEN_RECONCILIATION_OPERATION_ID",
            operation_id.to_string(),
        )
        .env(
            "RUNWARDEN_RECONCILIATION_LEASE_EXPIRY",
            execution.lease.expires_at.format(&Rfc3339).unwrap(),
        )
        .env(
            "RUNWARDEN_RECONCILIATION_SANDBOX_ROOT",
            executor_root.path().join("sandbox"),
        )
        .env(
            "RUNWARDEN_RECONCILIATION_RUNTIME_ROOT",
            executor_root.path().join("runtime"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fresh reconciliation process failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Completed
    );
    assert_eq!(executor_probe.call_count(), 1);
    assert!(!directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}

#[test]
fn start_commit_loss_for_non_email_is_live_then_recovers_as_unknown() {
    let fixture = RuntimeFixture::new();
    let journal = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::StartAfterCommit,
    );
    let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        journal,
        executor,
        SystemClock,
        context,
        issuer,
        "non-email-start-loss".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let executing = RuntimeApi::invoke(&runtime, input_request(141)).unwrap();
    assert_eq!(executing.operation_state, OperationState::Executing);
    assert_eq!(executor_probe.call_count(), 0);
    let still_live = RuntimeApi::resume(&runtime, executing.operation_id).unwrap();
    assert_eq!(still_live.operation_state, OperationState::Executing);
    assert_eq!(executor_probe.reconcile_count(), 0);
    let execution = fixture
        .store
        .execution_runtime_snapshot(executing.operation_id)
        .unwrap();
    drop(runtime);

    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (recovery_issuer, _) = PermitAuthority::generate().unwrap();
    let recovery_runtime = OperationRuntime::new(
        fixture.store.clone(),
        executor_probe.clone(),
        ManualClock::new(execution.lease.expires_at),
        context,
        recovery_issuer,
        "non-email-recovery".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let recovered = RuntimeApi::resume(&recovery_runtime, executing.operation_id).unwrap();
    assert_eq!(recovered.operation_state, OperationState::OutcomeUnknown);
    assert_eq!(executor_probe.call_count(), 0);
    assert_eq!(executor_probe.reconcile_count(), 1);
}

#[test]
fn live_prestart_lease_is_reused_only_by_its_owner() {
    let fixture = RuntimeFixture::new();
    let operation_id = approve_email(&fixture, 142);
    let failing = FailingJournal::new(fixture.store.clone(), FailurePoint::MarkExecutionStarted);
    let context = RuntimeContextLoader::load(&failing, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let recovery_issuer = issuer.clone();
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        failing,
        executor,
        SystemClock,
        context,
        issuer,
        "same-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    assert!(matches!(
        RuntimeApi::resume(&runtime, operation_id),
        Err(RuntimeError::JournalBeforeExecution(ref point))
            if point == "mark_execution_started"
    ));
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::ExecutionLeased
    );
    drop(runtime);

    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let recovery = OperationRuntime::new(
        fixture.store.clone(),
        executor_probe.clone(),
        SystemClock,
        context,
        recovery_issuer,
        "same-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let completed = RuntimeApi::resume(&recovery, operation_id).unwrap();
    assert_eq!(completed.operation_state, OperationState::Completed);
    assert_eq!(executor_probe.call_count(), 1);
}

#[test]
fn foreign_owner_cannot_take_a_live_prestart_lease() {
    let fixture = RuntimeFixture::new();
    let operation_id = approve_email(&fixture, 143);
    let failing = FailingJournal::new(fixture.store.clone(), FailurePoint::MarkExecutionStarted);
    let context = RuntimeContextLoader::load(&failing, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let recovery_issuer = issuer.clone();
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        failing,
        executor,
        SystemClock,
        context,
        issuer,
        "original-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    assert!(RuntimeApi::resume(&runtime, operation_id).is_err());
    drop(runtime);

    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let foreign = OperationRuntime::new(
        fixture.store.clone(),
        executor_probe.clone(),
        SystemClock,
        context,
        recovery_issuer,
        "foreign-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let error = RuntimeApi::resume(&foreign, operation_id).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::OperationConflict { operation_id: conflicted }
            if conflicted == operation_id
    ));
    assert_eq!(executor_probe.call_count(), 0);
}

#[test]
fn expired_prestart_lease_is_released_reacquired_and_executed_once() {
    let fixture = RuntimeFixture::new();
    let operation_id = approve_email(&fixture, 144);
    let start_failure =
        FailingJournal::new(fixture.store.clone(), FailurePoint::MarkExecutionStarted);
    let context = RuntimeContextLoader::load(&start_failure, INSTANCE_TOKEN, fixture.now).unwrap();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let executor = RecordingExecutor::new(verifier);
    let probe = executor.clone();
    let runtime = OperationRuntime::new(
        start_failure,
        executor,
        SystemClock,
        context,
        issuer,
        "expired-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    assert!(RuntimeApi::resume(&runtime, operation_id).is_err());
    let leased = fixture
        .store
        .execution_runtime_snapshot(operation_id)
        .unwrap();
    drop(runtime);

    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_recovery_root, issuer, recovery_executor) = default_counting_executor();
    let recovery_probe = recovery_executor.clone();
    let recovery = OperationRuntime::new(
        fixture.store.clone(),
        recovery_executor,
        ManualClock::new(leased.lease.expires_at),
        context,
        issuer,
        "expired-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let completed = RuntimeApi::resume(&recovery, operation_id).unwrap();
    assert_eq!(completed.operation_state, OperationState::Completed);
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Completed
    );
    assert_eq!(probe.call_count(), 0);
    assert_eq!(recovery_probe.call_count(), 1);
}
