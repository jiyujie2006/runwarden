mod common;

use common::{
    FailingJournal, FailurePoint, FixedClock, INSTANCE_TOKEN, RecordingExecutor, RuntimeFixture,
    email_request,
};
use runwarden_providers::executor::PermitAuthority;
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeError,
    SystemClock,
};
use runwarden_state::{ApprovalDecisionInput, ReviewerDecision};

#[test]
fn every_pre_execution_journal_failure_prevents_executor_dispatch() {
    for (index, failure_point) in [
        FailurePoint::CreateOperation,
        FailurePoint::RecordPolicy,
        FailurePoint::CreateApproval,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = RuntimeFixture::new();
        let journal = FailingJournal::new(fixture.store.clone(), failure_point);
        let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now)
            .expect("load the trusted active context before injecting a write failure");
        let (permit_issuer, permit_verifier) =
            PermitAuthority::generate().expect("create one process-local permit authority");
        let executor = RecordingExecutor::new(permit_verifier);
        let executor_probe = executor.clone();
        let runtime = OperationRuntime::new(
            journal,
            executor,
            FixedClock::new(fixture.now),
            context,
            permit_issuer,
            format!("runtime-test-lease-owner-{index}"),
            ApprovalWaitPolicy::immediate(),
        )
        .expect("construct runtime from trusted dependencies");

        let error = RuntimeApi::invoke(&runtime, email_request(index as u8 + 1))
            .expect_err("an injected journal failure must fail closed");

        assert!(
            matches!(
                error,
                RuntimeError::JournalBeforeExecution(ref point)
                    if point == failure_point.name()
            ),
            "failure at {} returned {error:?}",
            failure_point.name()
        );
        assert_eq!(
            executor_probe.call_count(),
            0,
            "executor ran after {} failed",
            failure_point.name()
        );
    }
}

#[test]
fn lease_and_execution_start_failures_never_dispatch_the_executor() {
    for (index, failure_point) in [
        FailurePoint::AcquireExecutionLease,
        FailurePoint::MarkExecutionStarted,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = RuntimeFixture::new();
        let initial_context =
            RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
        let (initial_issuer, initial_verifier) = PermitAuthority::generate().unwrap();
        let initial_runtime = OperationRuntime::new(
            fixture.store.clone(),
            RecordingExecutor::new(initial_verifier),
            SystemClock,
            initial_context,
            initial_issuer,
            format!("pre-approval-runtime-{index}"),
            ApprovalWaitPolicy::immediate(),
        )
        .unwrap();
        let pending =
            RuntimeApi::invoke(&initial_runtime, email_request(index as u8 + 40)).unwrap();
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
                reviewer: "fail-closed-reviewer".to_owned(),
                reason: "approve only to test the next durable gate".to_owned(),
                decision: ReviewerDecision::Approve,
                now: time::OffsetDateTime::now_utc(),
            })
            .unwrap();
        drop(initial_runtime);

        let journal = FailingJournal::new(fixture.store.clone(), failure_point);
        let context = RuntimeContextLoader::load(&journal, INSTANCE_TOKEN, fixture.now).unwrap();
        let (issuer, verifier) = PermitAuthority::generate().unwrap();
        let executor = RecordingExecutor::new(verifier);
        let probe = executor.clone();
        let runtime = OperationRuntime::new(
            journal,
            executor,
            SystemClock,
            context,
            issuer,
            format!("failed-gate-runtime-{index}"),
            ApprovalWaitPolicy::immediate(),
        )
        .unwrap();

        let error = RuntimeApi::resume(&runtime, pending.operation_id).unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::JournalBeforeExecution(ref point)
                if point == failure_point.name()
        ));
        assert_eq!(probe.call_count(), 0);
    }
}
