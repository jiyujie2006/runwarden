mod common;

use common::{
    FailingJournal, FailurePoint, FixedClock, INSTANCE_TOKEN, RecordingExecutor, RuntimeFixture,
    email_request,
};
use runwarden_providers::executor::PermitAuthority;
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeError,
};

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
