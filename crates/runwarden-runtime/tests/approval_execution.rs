mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use common::{
    INSTANCE_TOKEN, ManualClock, RuntimeFixture, default_counting_executor, email_request,
    input_request,
};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::OperationState;
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeDisposition,
    SystemClock,
};
use runwarden_state::{ApprovalDecisionInput, ApprovalRecordV1, ReviewerDecision, StateStore};

fn pending_approval(
    store: &StateStore,
    story_id: runwarden_kernel::story::StoryId,
) -> ApprovalRecordV1 {
    let deadline = Instant::now() + StdDuration::from_secs(2);
    loop {
        let story = store.story_snapshot(story_id).unwrap();
        if let Some(operation) = story.operations.first()
            && let Some(approval) = store
                .approval_for_operation(operation.operation_id)
                .unwrap()
        {
            return approval;
        }
        assert!(
            Instant::now() < deadline,
            "pending approval was not created"
        );
        thread::sleep(StdDuration::from_millis(5));
    }
}

fn decide(store: &StateStore, approval: &ApprovalRecordV1, decision: ReviewerDecision) {
    let operation = store.operation(approval.operation_id).unwrap();
    store
        .decide_approval(ApprovalDecisionInput {
            approval_id: approval.approval_id,
            expected_version: approval.version,
            expected_operation_version: operation.version,
            reviewer: "contest-reviewer".to_owned(),
            reason: "reviewed against the frozen operation".to_owned(),
            decision,
            now: time::OffsetDateTime::now_utc(),
        })
        .unwrap();
}

#[test]
fn waiting_invoke_uses_the_same_operation_after_reviewer_approval() {
    let fixture = RuntimeFixture::new();
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_executor_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = Arc::new(
        OperationRuntime::new(
            fixture.store.clone(),
            executor,
            SystemClock,
            context,
            issuer,
            "approval-wait-runtime".to_owned(),
            ApprovalWaitPolicy {
                timeout: StdDuration::from_secs(2),
                poll_interval: StdDuration::from_millis(5),
            },
        )
        .unwrap(),
    );
    let worker = {
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || RuntimeApi::invoke(&*runtime, email_request(120)))
    };

    let approval = pending_approval(&fixture.store, fixture.story.story_id);
    let operation_id = approval.operation_id;
    decide(&fixture.store, &approval, ReviewerDecision::Approve);
    let response = worker.join().unwrap().unwrap();

    assert_eq!(response.operation_id, operation_id);
    assert!(matches!(
        response.disposition,
        RuntimeDisposition::Completed
    ));
    assert_eq!(executor_probe.call_count(), 1);
    assert_eq!(
        fixture.store.approval(approval.approval_id).unwrap().state,
        ApprovalState::Consumed
    );
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Completed
    );
}

#[test]
fn approval_timeout_and_denial_return_the_same_operation_without_execution() {
    let timeout_fixture = RuntimeFixture::new();
    let timeout_context =
        RuntimeContextLoader::load(&timeout_fixture.store, INSTANCE_TOKEN, timeout_fixture.now)
            .unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let timeout_probe = executor.clone();
    let timeout_runtime = OperationRuntime::new(
        timeout_fixture.store.clone(),
        executor,
        SystemClock,
        timeout_context,
        issuer,
        "approval-timeout-runtime".to_owned(),
        ApprovalWaitPolicy {
            timeout: StdDuration::from_millis(40),
            poll_interval: StdDuration::from_millis(5),
        },
    )
    .unwrap();
    let timed_out = RuntimeApi::invoke(&timeout_runtime, email_request(121)).unwrap();
    assert_eq!(timed_out.operation_state, OperationState::AwaitingApproval);
    assert_eq!(timeout_probe.call_count(), 0);
    assert_eq!(
        timeout_fixture
            .store
            .story_snapshot(timeout_fixture.story.story_id)
            .unwrap()
            .operations
            .len(),
        1
    );

    let deny_fixture = RuntimeFixture::new();
    let deny_context =
        RuntimeContextLoader::load(&deny_fixture.store, INSTANCE_TOKEN, deny_fixture.now).unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let deny_probe = executor.clone();
    let deny_runtime = Arc::new(
        OperationRuntime::new(
            deny_fixture.store.clone(),
            executor,
            SystemClock,
            deny_context,
            issuer,
            "approval-deny-runtime".to_owned(),
            ApprovalWaitPolicy {
                timeout: StdDuration::from_secs(2),
                poll_interval: StdDuration::from_millis(5),
            },
        )
        .unwrap(),
    );
    let worker = {
        let runtime = Arc::clone(&deny_runtime);
        thread::spawn(move || RuntimeApi::invoke(&*runtime, email_request(122)))
    };
    let approval = pending_approval(&deny_fixture.store, deny_fixture.story.story_id);
    decide(&deny_fixture.store, &approval, ReviewerDecision::Deny);
    let denied = worker.join().unwrap().unwrap();
    assert_eq!(denied.operation_id, approval.operation_id);
    assert_eq!(denied.operation_state, OperationState::DeniedByReviewer);
    assert_eq!(deny_probe.call_count(), 0);
}

#[test]
fn pending_approval_is_expired_by_the_runtime_clock() {
    let fixture = RuntimeFixture::new();
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let clock = ManualClock::new(fixture.now);
    let clock_control = clock.clone();
    let (_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = Arc::new(
        OperationRuntime::new(
            fixture.store.clone(),
            executor,
            clock,
            context,
            issuer,
            "approval-expiry-runtime".to_owned(),
            ApprovalWaitPolicy {
                timeout: StdDuration::from_secs(2),
                poll_interval: StdDuration::from_millis(5),
            },
        )
        .unwrap(),
    );
    let worker = {
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || RuntimeApi::invoke(&*runtime, email_request(123)))
    };
    let approval = pending_approval(&fixture.store, fixture.story.story_id);
    clock_control.set(approval.expires_at);
    let expired = worker.join().unwrap().unwrap();
    assert_eq!(expired.operation_id, approval.operation_id);
    assert_eq!(expired.operation_state, OperationState::Expired);
    assert_eq!(executor_probe.call_count(), 0);
}

#[test]
fn direct_policy_allow_crosses_the_durable_start_gate_once() {
    let fixture = RuntimeFixture::new();
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        fixture.store.clone(),
        executor,
        SystemClock,
        context,
        issuer,
        "direct-allow-runtime".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let response = RuntimeApi::invoke(&runtime, input_request(124)).unwrap();
    assert_eq!(response.policy_decision, Some(PolicyDecision::Allowed));
    assert_eq!(response.operation_state, OperationState::Failed);
    assert_eq!(executor_probe.call_count(), 1);
    assert!(
        fixture
            .store
            .approval_for_operation(response.operation_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn concurrent_resume_calls_execute_an_approved_operation_at_most_once() {
    let fixture = RuntimeFixture::new();
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now).unwrap();
    let (_root, issuer, executor) = default_counting_executor();
    let executor_probe = executor.clone();
    let runtime = Arc::new(
        OperationRuntime::new(
            fixture.store.clone(),
            executor,
            SystemClock,
            context,
            issuer,
            "concurrent-resume-runtime".to_owned(),
            ApprovalWaitPolicy::immediate(),
        )
        .unwrap(),
    );
    let pending = RuntimeApi::invoke(&*runtime, email_request(125)).unwrap();
    let approval = fixture
        .store
        .approval_for_operation(pending.operation_id)
        .unwrap()
        .unwrap();
    decide(&fixture.store, &approval, ReviewerDecision::Approve);

    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let runtime = Arc::clone(&runtime);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            RuntimeApi::resume(&*runtime, pending.operation_id)
        }));
    }
    barrier.wait();
    for worker in workers {
        let response = worker.join().unwrap().unwrap();
        assert_eq!(response.operation_id, pending.operation_id);
    }
    assert_eq!(executor_probe.call_count(), 1);
    assert_eq!(
        fixture.store.operation(pending.operation_id).unwrap().state,
        OperationState::Completed
    );
}
