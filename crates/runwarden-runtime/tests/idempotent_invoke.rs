mod common;

use common::{
    FailingJournal, FailurePoint, FixedClock, INSTANCE_TOKEN, LostApprovalResponseJournal,
    RecordingExecutor, RuntimeFixture, email_request,
};
use runwarden_providers::executor::PermitAuthority;
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeError,
};
use serde_json::json;

#[test]
fn duplicate_invocation_reuses_one_operation_and_changed_arguments_conflict() {
    let fixture = RuntimeFixture::new();
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (permit_issuer, permit_verifier) = PermitAuthority::generate().unwrap();
    let executor = RecordingExecutor::new(permit_verifier);
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        fixture.store.clone(),
        executor,
        FixedClock::new(fixture.now),
        context,
        permit_issuer,
        "runtime-idempotency-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let request = email_request(71);

    let first = RuntimeApi::invoke(&runtime, request.clone()).unwrap();
    let retry = RuntimeApi::invoke(&runtime, request.clone()).unwrap();

    assert_eq!(retry.operation_id, first.operation_id);
    assert_eq!(retry.operation_version, first.operation_version);
    let approval = fixture
        .store
        .approval_for_operation(first.operation_id)
        .unwrap()
        .expect("one durable approval");
    assert_eq!(approval.operation_id, first.operation_id);

    let mut changed = request;
    changed.arguments["subject"] = json!("changed after the first proposal");
    let error = RuntimeApi::invoke(&runtime, changed).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::OperationConflict { operation_id }
            if operation_id == first.operation_id
    ));
    assert_eq!(executor_probe.call_count(), 0);
    assert_eq!(
        fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap()
            .operations
            .len(),
        1
    );
}

#[test]
fn retry_recovers_when_approval_commit_response_was_lost() {
    let fixture = RuntimeFixture::new();
    let journal = LostApprovalResponseJournal::new(fixture.store.clone());
    let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
    let (permit_issuer, permit_verifier) = PermitAuthority::generate().unwrap();
    let executor = RecordingExecutor::new(permit_verifier);
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        journal,
        executor,
        FixedClock::new(fixture.now),
        context,
        permit_issuer,
        "runtime-lost-response-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let request = email_request(72);

    let error = RuntimeApi::invoke(&runtime, request.clone()).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::JournalBeforeExecution(ref point) if point == "create_approval"
    ));
    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    assert_eq!(snapshot.operations.len(), 1);
    let operation_id = snapshot.operations[0].operation_id;
    let approval_before_retry = fixture
        .store
        .approval_for_operation(operation_id)
        .unwrap()
        .expect("approval commit survived the lost response");

    let retry = RuntimeApi::invoke(&runtime, request).unwrap();
    assert_eq!(retry.operation_id, operation_id);
    assert_eq!(
        fixture
            .store
            .approval_for_operation(operation_id)
            .unwrap()
            .unwrap()
            .approval_id,
        approval_before_retry.approval_id
    );
    assert_eq!(
        fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap()
            .operations
            .len(),
        1
    );
    assert_eq!(executor_probe.call_count(), 0);
}

#[test]
fn retry_repairs_policy_commit_when_approval_was_never_written() {
    let fixture = RuntimeFixture::new();
    let failing = FailingJournal::new(fixture.store.clone(), FailurePoint::CreateApproval);
    let context = RuntimeContextLoader::load(&failing, INSTANCE_TOKEN, fixture.now).unwrap();
    let (first_issuer, first_verifier) = PermitAuthority::generate().unwrap();
    let first_executor = RecordingExecutor::new(first_verifier);
    let first_probe = first_executor.clone();
    let first_runtime = OperationRuntime::new(
        failing,
        first_executor,
        FixedClock::new(fixture.now),
        context,
        first_issuer,
        "runtime-before-approval-crash".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();
    let request = email_request(73);

    let error = RuntimeApi::invoke(&first_runtime, request.clone()).unwrap_err();
    assert!(matches!(
        error,
        RuntimeError::JournalBeforeExecution(ref point) if point == "create_approval"
    ));
    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    assert_eq!(snapshot.operations.len(), 1);
    let operation_id = snapshot.operations[0].operation_id;
    assert!(
        fixture
            .store
            .approval_for_operation(operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(first_probe.call_count(), 0);
    drop(first_runtime);

    let recovered_context =
        RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (recovered_issuer, recovered_verifier) = PermitAuthority::generate().unwrap();
    let recovered_executor = RecordingExecutor::new(recovered_verifier);
    let recovered_probe = recovered_executor.clone();
    let recovered_runtime = OperationRuntime::new(
        fixture.store.clone(),
        recovered_executor,
        FixedClock::new(fixture.now),
        recovered_context,
        recovered_issuer,
        "runtime-after-approval-crash".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let retry = RuntimeApi::invoke(&recovered_runtime, request).unwrap();
    assert_eq!(retry.operation_id, operation_id);
    assert_eq!(
        fixture
            .store
            .approval_for_operation(operation_id)
            .unwrap()
            .expect("retry repaired the missing approval")
            .operation_id,
        operation_id
    );
    assert_eq!(
        fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap()
            .operations
            .len(),
        1
    );
    assert_eq!(recovered_probe.call_count(), 0);
}
