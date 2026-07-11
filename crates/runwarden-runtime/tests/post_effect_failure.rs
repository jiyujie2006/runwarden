mod common;

use std::path::Path;

use common::{
    CleanupFailingExecutor, INSTANCE_TOKEN, PostExecutionFailureMode, PostExecutionJournal,
    RecordingExecutor, RuntimeFixture, default_counting_executor, email_request,
};
use runwarden_kernel::operation::OperationState;
use runwarden_providers::executor::PermitAuthority;
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeError,
    SystemClock,
};
use runwarden_state::{ApprovalDecisionInput, ReviewerDecision};

fn approved_operation(
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
        format!("post-effect-prepare-{invocation_byte}"),
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
            reviewer: "post-effect-reviewer".to_owned(),
            reason: "approve the exact frozen operation".to_owned(),
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
fn result_write_failure_falls_back_to_durable_outcome_unknown() {
    let fixture = RuntimeFixture::new();
    let operation_id = approved_operation(&fixture, 130);
    let journal = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::ResultBeforeWrite,
    );
    let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let probe = executor.clone();
    let runtime = OperationRuntime::new(
        journal,
        executor,
        SystemClock,
        context,
        issuer,
        "post-effect-result-failure".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let error = RuntimeApi::resume(&runtime, operation_id).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::JournalAfterExecution { operation_id: failed, .. }
            if failed == operation_id
    ));
    assert_eq!(probe.call_count(), 1);
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::OutcomeUnknown
    );
    assert!(!directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}

#[test]
fn lost_result_commit_response_never_overwrites_the_completed_result() {
    let fixture = RuntimeFixture::new();
    let operation_id = approved_operation(&fixture, 131);
    let journal = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::ResultAfterCommit,
    );
    let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let probe = executor.clone();
    let runtime = OperationRuntime::new(
        journal,
        executor,
        SystemClock,
        context,
        issuer,
        "post-effect-lost-response".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let error = RuntimeApi::resume(&runtime, operation_id).unwrap_err();
    assert!(matches!(error, RuntimeError::JournalAfterExecution { .. }));
    let stored = fixture.store.operation(operation_id).unwrap();
    assert_eq!(stored.state, OperationState::Completed);
    assert!(stored.provider_result.is_some());
    let resumed = RuntimeApi::resume(&runtime, operation_id).unwrap();
    assert_eq!(resumed.operation_state, OperationState::Completed);
    assert_eq!(probe.call_count(), 1);
    assert!(!directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}

#[test]
fn lost_result_response_and_cleanup_failure_are_both_reported() {
    let fixture = RuntimeFixture::new();
    let operation_id = approved_operation(&fixture, 134);
    let journal = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::ResultAfterCommit,
    );
    let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let probe = executor.clone();
    let runtime = OperationRuntime::new(
        journal,
        CleanupFailingExecutor::new(executor),
        SystemClock,
        context,
        issuer,
        "post-effect-compound-failure".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let error = RuntimeApi::resume(&runtime, operation_id).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::JournalAndCleanupAfterExecution {
            operation_id: failed,
            ..
        } if failed == operation_id
    ));
    assert_eq!(probe.call_count(), 1);
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Completed
    );
    assert!(directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}

#[test]
fn double_journal_failure_retains_evidence_for_later_reconciliation() {
    let fixture = RuntimeFixture::new();
    let operation_id = approved_operation(&fixture, 132);
    let journal = PostExecutionJournal::new(
        fixture.store.clone(),
        PostExecutionFailureMode::ResultAndUnknown,
    );
    let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let probe = executor.clone();
    let runtime = OperationRuntime::new(
        journal,
        executor,
        SystemClock,
        context,
        issuer,
        "post-effect-double-failure".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let error = RuntimeApi::resume(&runtime, operation_id).unwrap_err();
    assert!(matches!(error, RuntimeError::JournalAfterExecution { .. }));
    assert_eq!(probe.call_count(), 1);
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Executing
    );
    assert!(directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}

#[test]
fn cleanup_failure_surfaces_after_the_truthful_result_commit() {
    let fixture = RuntimeFixture::new();
    let operation_id = approved_operation(&fixture, 133);
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (executor_root, issuer, executor) = default_counting_executor();
    let probe = executor.clone();
    let runtime = OperationRuntime::new(
        fixture.store.clone(),
        CleanupFailingExecutor::new(executor),
        SystemClock,
        context,
        issuer,
        "post-effect-cleanup-failure".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let error = RuntimeApi::resume(&runtime, operation_id).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::CleanupAfterCommit { operation_id: failed, .. }
            if failed == operation_id
    ));
    assert_eq!(probe.call_count(), 1);
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Completed
    );
    assert!(directory_has_entry(
        &executor_root.path().join("sandbox/mail/tmp")
    ));
}
