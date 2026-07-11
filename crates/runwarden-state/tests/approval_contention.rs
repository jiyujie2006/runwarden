mod common;

use std::sync::{Arc, Barrier};
use std::{
    process::{Command, Stdio},
    time::Duration as StdDuration,
};

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, ProviderExecutionStatus, ProviderResultView,
    SafeProviderOutput, SideEffectState,
};
use runwarden_kernel::resource::DataClass;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ApprovalId, ExecutionLeaseId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_state::{
    ApprovalDecisionInput, DemoActivation, DurableApprovalBinding, ExecutionResultInput,
    JournalError, LeaseAuthorization, LeaseRequest, NewApproval, OneShotConsumption,
    RecordPolicyInput, ReviewerDecision,
};
use rusqlite::{Connection, params};

const INSTANCE_ID: &str = "active-instance";
const LEASE_OWNER: &str = "mcp-runtime";

fn token_hash() -> String {
    Sha256Digest::from_bytes(b"trusted-instance-token")
        .as_str()
        .to_owned()
}

fn activate(fixture: &JournalFixture) {
    fixture
        .store
        .activate_demo(&DemoActivation {
            instance_id: INSTANCE_ID.to_owned(),
            story_id: fixture.story.story_id,
            session_id: fixture.story.authority.session_id,
            process_id: 77,
            host_id: "judge-host".to_owned(),
            instance_token_hash: token_hash(),
            now: mutation_time(&fixture.story, 0),
        })
        .unwrap();
}

fn policy_operation(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
) -> runwarden_kernel::operation::SecurityOperation {
    policy_operation_at(fixture, suffix, decision, 1, 2)
}

fn policy_operation_at(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
    create_seconds: i64,
    policy_seconds: i64,
) -> runwarden_kernel::operation::SecurityOperation {
    let mut input = fixture.operation(suffix, "send");
    input.now = mutation_time(&fixture.story, create_seconds);
    let operation = fixture.store.create_operation(input).unwrap().operation;
    let (next_state, status) = match decision {
        PolicyDecision::Allowed => (OperationState::PolicyEvaluated, PolicyCheckStatus::Passed),
        PolicyDecision::RequiresReview => (
            OperationState::AwaitingApproval,
            PolicyCheckStatus::RequiresReview,
        ),
        PolicyDecision::Denied => (OperationState::Denied, PolicyCheckStatus::Failed),
    };
    fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision,
            reason: "lease policy".to_owned(),
            next_state,
            checks: vec![PolicyCheck {
                check_id: "lease-policy".to_owned(),
                layer: "authority".to_owned(),
                status,
                reason: "typed lease policy".to_owned(),
                observation_ref: None,
            }],
            now: mutation_time(&fixture.story, policy_seconds),
        })
        .unwrap()
}

fn binding(
    fixture: &JournalFixture,
    operation: &runwarden_kernel::operation::SecurityOperation,
) -> DurableApprovalBinding {
    DurableApprovalBinding {
        story_id: operation.story_id,
        session_id: operation.session_id,
        operation_id: operation.operation_id,
        actor_id: fixture.story.authority.actor_id.clone(),
        authz_id: fixture.story.authority.authz_id.clone(),
        provider: operation.provider.clone(),
        action: operation.action.clone(),
        resource_claim_hash: operation.resource_claim.digest(),
        argument_hash: operation.argument_hash.clone(),
        data_classification: Some(DataClass::Internal),
        risk_tags: vec!["email_send".to_owned(), "network_egress".to_owned()],
        policy_snapshot_hash: operation.policy_snapshot_hash.clone(),
        maximum_consumptions: OneShotConsumption::new(),
    }
}

fn approve_operation(
    fixture: &JournalFixture,
    operation: &runwarden_kernel::operation::SecurityOperation,
) -> runwarden_state::ApprovalRecordV1 {
    let approval_id = ApprovalId::new();
    fixture
        .store
        .create_approval(NewApproval {
            approval_id,
            operation_id: operation.operation_id,
            binding: binding(fixture, operation),
            expires_at: mutation_time(&fixture.story, 200),
            now: mutation_time(&fixture.story, 3),
        })
        .unwrap();
    fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "reviewer-lease".to_owned(),
            reason: "bounded approval".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap()
}

fn charge(calls: u64) -> BudgetCharge {
    BudgetCharge {
        calls,
        file_bytes: 0,
        network_bytes: 0,
    }
}

fn direct_lease_request(
    fixture: &JournalFixture,
    operation_id: runwarden_kernel::story::OperationId,
    lease_id: ExecutionLeaseId,
) -> LeaseRequest {
    LeaseRequest {
        operation_id,
        expected_operation_version: 1,
        authorization: LeaseAuthorization::StoredPolicyAllow,
        lease_id,
        lease_owner: LEASE_OWNER.to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        instance_token_hash: token_hash(),
        expected_budget_version: 0,
        budget_charge: charge(1),
        expires_at: mutation_time(&fixture.story, 120),
        now: mutation_time(&fixture.story, 3),
    }
}

fn direct_request_from_story(
    story: &runwarden_kernel::story::SecurityStory,
    operation_id: runwarden_kernel::story::OperationId,
    lease_id: ExecutionLeaseId,
    budget_charge: BudgetCharge,
) -> LeaseRequest {
    LeaseRequest {
        operation_id,
        expected_operation_version: 1,
        authorization: LeaseAuthorization::StoredPolicyAllow,
        lease_id,
        lease_owner: LEASE_OWNER.to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        instance_token_hash: token_hash(),
        expected_budget_version: 0,
        budget_charge,
        expires_at: mutation_time(story, 120),
        now: mutation_time(story, 5),
    }
}

fn reviewed_lease_request(
    fixture: &JournalFixture,
    operation_id: runwarden_kernel::story::OperationId,
    approval_id: ApprovalId,
    lease_id: ExecutionLeaseId,
) -> LeaseRequest {
    LeaseRequest {
        operation_id,
        expected_operation_version: 2,
        authorization: LeaseAuthorization::ReviewerApproval {
            approval_id,
            expected_approval_version: 1,
        },
        lease_id,
        lease_owner: LEASE_OWNER.to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        instance_token_hash: token_hash(),
        expected_budget_version: 0,
        budget_charge: charge(1),
        expires_at: mutation_time(&fixture.story, 120),
        now: mutation_time(&fixture.story, 5),
    }
}

fn completed_result(
    lease: &runwarden_state::ExecutionLease,
    expected_operation_version: u64,
    now: time::OffsetDateTime,
) -> ExecutionResultInput {
    ExecutionResultInput {
        operation_id: lease.operation_id,
        expected_operation_version,
        lease_id: lease.lease_id,
        lease_owner: lease.lease_owner.clone(),
        next_state: OperationState::Completed,
        side_effect_state: SideEffectState::Completed,
        provider_result: ProviderResultView {
            execution_status: ProviderExecutionStatus::Completed,
            output: SafeProviderOutput::Email {
                receipt_hash: Sha256Digest::from_bytes(b"receipt"),
            },
            output_hash: Some(Sha256Digest::from_bytes(b"safe output")),
            error_kind: None,
            reason_code: Some("completed".to_owned()),
        },
        actual_budget_charge: charge(1),
        now,
    }
}

#[test]
fn direct_allow_leases_starts_and_records_a_budgeted_result() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 80, PolicyDecision::Allowed);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_lease_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
        ))
        .unwrap();
    assert_eq!(lease.pre_lease_state, OperationState::PolicyEvaluated);
    assert!(lease.approval_id.is_none());
    assert_eq!(
        fixture
            .store
            .execution_lease(operation.operation_id)
            .unwrap(),
        Some(lease.clone())
    );
    assert!(
        !fixture
            .store
            .has_execution_started(operation.operation_id)
            .unwrap()
    );
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    assert_eq!(started.operation_version, 3);
    assert!(started.approval_version.is_none());
    assert!(
        fixture
            .store
            .has_execution_started(operation.operation_id)
            .unwrap()
    );
    match fixture.store.mark_execution_started(&lease) {
        Err(JournalError::Conflict {
            entity: "operation",
            expected,
            actual,
            ..
        }) => assert_eq!((expected, actual), (2, 3)),
        other => panic!("unexpected second-start result: {other:?}"),
    }

    fixture
        .store
        .record_execution_result(completed_result(
            &lease,
            started.operation_version,
            time::OffsetDateTime::now_utc(),
        ))
        .unwrap();
    let terminal = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(terminal.state, OperationState::Completed);
    assert_eq!(terminal.side_effect_state, SideEffectState::Completed);
    assert!(
        fixture
            .store
            .execution_lease(operation.operation_id)
            .unwrap()
            .is_none()
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(budget.calls_committed, 1);
    assert_eq!(budget.version, 2);
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 5);
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}

#[test]
fn reviewed_lease_is_one_shot_and_start_consumes_the_approval() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 81, PolicyDecision::RequiresReview);
    let approval = approve_operation(&fixture, &operation);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(reviewed_lease_request(
            &fixture,
            operation.operation_id,
            approval.approval_id,
            ExecutionLeaseId::new(),
        ))
        .unwrap();
    assert_eq!(lease.pre_lease_state, OperationState::Approved);
    assert_eq!(lease.approval_id, Some(approval.approval_id));
    let leased_approval = fixture.store.approval(approval.approval_id).unwrap();
    assert_eq!(
        leased_approval.state,
        runwarden_kernel::authority::ApprovalState::Leased
    );
    assert_eq!(leased_approval.version, 2);

    let started = fixture.store.mark_execution_started(&lease).unwrap();
    assert_eq!(started.operation_version, 4);
    assert_eq!(started.approval_version, Some(3));
    let consumed = fixture.store.approval(approval.approval_id).unwrap();
    assert_eq!(
        consumed.state,
        runwarden_kernel::authority::ApprovalState::Consumed
    );
    assert_eq!(consumed.version, 3);
}

#[test]
fn reviewed_lease_contention_has_one_winner_and_one_approval_conflict() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 82, PolicyDecision::RequiresReview);
    let approval = approve_operation(&fixture, &operation);
    activate(&fixture);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let state_dir = fixture.state_dir.clone();
        let story = fixture.story.clone();
        let barrier = Arc::clone(&barrier);
        let operation_id = operation.operation_id;
        let approval_id = approval.approval_id;
        handles.push(std::thread::spawn(move || {
            let store = runwarden_state::StateStore::open(state_dir).unwrap();
            let request = reviewed_request_from_story(
                &story,
                operation_id,
                approval_id,
                ExecutionLeaseId::new(),
            );
            barrier.wait();
            store.acquire_execution_lease(request)
        }));
    }
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(JournalError::Conflict {
                    entity: "approval",
                    ..
                })
            ))
            .count(),
        1
    );
}

#[test]
fn aggregate_budget_contention_commits_exactly_one_reservation() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let first = policy_operation_at(&fixture, 86, PolicyDecision::Allowed, 1, 2);
    let second = policy_operation_at(&fixture, 87, PolicyDecision::Allowed, 3, 4);
    activate(&fixture);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for operation_id in [first.operation_id, second.operation_id] {
        let state_dir = fixture.state_dir.clone();
        let story = fixture.story.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let store = runwarden_state::StateStore::open(state_dir).unwrap();
            let request =
                direct_request_from_story(&story, operation_id, ExecutionLeaseId::new(), charge(3));
            barrier.wait();
            (operation_id, store.acquire_execution_lease(request))
        }));
    }
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(
                result,
                Err(JournalError::Conflict {
                    entity: "budget",
                    ..
                })
            ))
            .count(),
        1
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.calls_reserved, 3);
    assert_eq!(budget.calls_committed, 0);
    assert_eq!(budget.version, 1);
    let states = results
        .iter()
        .map(|(operation_id, _)| fixture.store.operation(*operation_id).unwrap().state)
        .collect::<Vec<_>>();
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == OperationState::ExecutionLeased)
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == OperationState::PolicyEvaluated)
            .count(),
        1
    );
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        5
    );
}

fn reviewed_request_from_story(
    story: &runwarden_kernel::story::SecurityStory,
    operation_id: runwarden_kernel::story::OperationId,
    approval_id: ApprovalId,
    lease_id: ExecutionLeaseId,
) -> LeaseRequest {
    LeaseRequest {
        operation_id,
        expected_operation_version: 2,
        authorization: LeaseAuthorization::ReviewerApproval {
            approval_id,
            expected_approval_version: 1,
        },
        lease_id,
        lease_owner: LEASE_OWNER.to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        instance_token_hash: token_hash(),
        expected_budget_version: 0,
        budget_charge: charge(1),
        expires_at: mutation_time(story, 120),
        now: mutation_time(story, 5),
    }
}

#[test]
fn cross_process_lease_worker() {
    if std::env::var_os("RUNWARDEN_TEST_LEASE_WORKER").is_none() {
        return;
    }
    let state_dir = std::env::var_os("RUNWARDEN_TEST_STATE_DIR").unwrap();
    let gate = std::path::PathBuf::from(std::env::var_os("RUNWARDEN_TEST_GATE").unwrap());
    let operation_id = serde_json::from_value(serde_json::Value::String(
        std::env::var("RUNWARDEN_TEST_OPERATION_ID").unwrap(),
    ))
    .unwrap();
    let approval_id = serde_json::from_value(serde_json::Value::String(
        std::env::var("RUNWARDEN_TEST_APPROVAL_ID").unwrap(),
    ))
    .unwrap();
    let lease_id = serde_json::from_value(serde_json::Value::String(
        std::env::var("RUNWARDEN_TEST_LEASE_ID").unwrap(),
    ))
    .unwrap();
    let store = runwarden_state::StateStore::open(state_dir).unwrap();
    let operation = store.operation(operation_id).unwrap();
    let story = store.story_snapshot(operation.story_id).unwrap();
    for _ in 0..500 {
        if gate.exists() {
            break;
        }
        std::thread::sleep(StdDuration::from_millis(10));
    }
    assert!(gate.exists(), "parent did not release the process gate");
    let result = store.acquire_execution_lease(reviewed_request_from_story(
        &story,
        operation_id,
        approval_id,
        lease_id,
    ));
    match result {
        Ok(_) => println!("RUNWARDEN_WORKER_ACQUIRED"),
        Err(JournalError::Conflict {
            entity: "approval", ..
        }) => println!("RUNWARDEN_WORKER_APPROVAL_CONFLICT"),
        Err(error) => panic!("unexpected cross-process lease result: {error}"),
    }
}

#[test]
fn reviewed_lease_contention_is_atomic_across_processes() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 88, PolicyDecision::RequiresReview);
    let approval = approve_operation(&fixture, &operation);
    activate(&fixture);
    let gate = fixture._temp.path().join("process-lease-gate");
    let executable = std::env::current_exe().unwrap();
    let spawn_worker = |lease_id: ExecutionLeaseId| {
        Command::new(&executable)
            .args([
                "--exact",
                "cross_process_lease_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RUNWARDEN_TEST_LEASE_WORKER", "1")
            .env("RUNWARDEN_TEST_STATE_DIR", &fixture.state_dir)
            .env("RUNWARDEN_TEST_GATE", &gate)
            .env(
                "RUNWARDEN_TEST_OPERATION_ID",
                operation.operation_id.to_string(),
            )
            .env(
                "RUNWARDEN_TEST_APPROVAL_ID",
                approval.approval_id.to_string(),
            )
            .env("RUNWARDEN_TEST_LEASE_ID", lease_id.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn_worker(ExecutionLeaseId::new());
    let second = spawn_worker(ExecutionLeaseId::new());
    std::fs::write(&gate, b"go").unwrap();
    let outputs = [
        first.wait_with_output().unwrap(),
        second.wait_with_output().unwrap(),
    ];
    assert!(outputs.iter().all(|output| output.status.success()));
    let output = outputs
        .iter()
        .map(|output| String::from_utf8_lossy(&output.stdout))
        .collect::<Vec<_>>();
    assert_eq!(
        output
            .iter()
            .filter(|text| text.contains("RUNWARDEN_WORKER_ACQUIRED"))
            .count(),
        1
    );
    assert_eq!(
        output
            .iter()
            .filter(|text| text.contains("RUNWARDEN_WORKER_APPROVAL_CONFLICT"))
            .count(),
        1
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.calls_reserved, 1);
    assert_eq!(budget.version, 1);
}

#[test]
fn active_context_change_blocks_start_and_preserves_the_reservation() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 83, PolicyDecision::Allowed);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_lease_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
        ))
        .unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE active_instances SET instance_token_hash = ?1 WHERE singleton = 1",
            params![Sha256Digest::from_bytes(b"replacement").as_str()],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.mark_execution_started(&lease),
        Err(JournalError::Integrity(_)) | Err(JournalError::InvalidTransition { .. })
    ));
    assert_eq!(
        fixture
            .store
            .operation(operation.operation_id)
            .unwrap()
            .state,
        OperationState::ExecutionLeased
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.calls_reserved, 1);
    assert_eq!(budget.calls_committed, 0);
}

#[test]
fn budget_overrun_and_actual_over_reservation_roll_back() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 84, PolicyDecision::Allowed);
    activate(&fixture);
    let mut oversized =
        direct_lease_request(&fixture, operation.operation_id, ExecutionLeaseId::new());
    oversized.budget_charge = charge(5);
    assert!(matches!(
        fixture.store.acquire_execution_lease(oversized),
        Err(JournalError::Integrity(_))
    ));
    assert_eq!(
        fixture
            .store
            .operation(operation.operation_id)
            .unwrap()
            .state,
        OperationState::PolicyEvaluated
    );
    assert_eq!(
        fixture
            .store
            .budget_snapshot(fixture.story.authority.session_id)
            .unwrap()
            .version,
        0
    );

    let lease = fixture
        .store
        .acquire_execution_lease(direct_lease_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    let mut too_much = completed_result(
        &lease,
        started.operation_version,
        time::OffsetDateTime::now_utc(),
    );
    too_much.actual_budget_charge = charge(2);
    assert!(matches!(
        fixture.store.record_execution_result(too_much),
        Err(JournalError::Integrity(_))
    ));
    assert_eq!(
        fixture
            .store
            .operation(operation.operation_id)
            .unwrap()
            .state,
        OperationState::Executing
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.calls_reserved, 1);
    assert_eq!(budget.calls_committed, 0);
}

#[test]
fn result_persistence_survives_post_start_session_deactivation() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 85, PolicyDecision::Allowed);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_lease_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE sessions SET active = 0 WHERE session_id = ?1",
            params![fixture.story.authority.session_id.to_string()],
        )
        .unwrap();
    fixture
        .store
        .record_execution_result(completed_result(
            &lease,
            started.operation_version,
            time::OffsetDateTime::now_utc(),
        ))
        .unwrap();
    assert_eq!(
        fixture
            .store
            .operation(operation.operation_id)
            .unwrap()
            .state,
        OperationState::Completed
    );
}
