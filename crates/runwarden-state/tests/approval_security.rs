mod common;

use common::{JournalFixture, mutation_time};
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, ProviderExecutionStatus, ProviderResultView,
    SafeProviderOutput, SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::DataClass;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ApprovalId, EnforcementMode, ExecutionLeaseId, OperationId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_state::{
    ApprovalDecisionInput, DemoActivation, DurableApprovalBinding, ExecutionLease,
    ExecutionResultInput, JournalError, LeaseAuthorization, LeaseRequest, NewApproval,
    OneShotConsumption, RecordPolicyInput, ReviewerDecision,
};
use rusqlite::{Connection, params};
use serde_json::Value;

const INSTANCE_ID: &str = "security-test-instance";
const LEASE_OWNER: &str = "security-test-runtime";

fn token_hash() -> String {
    Sha256Digest::from_bytes(b"security-test-token")
        .as_str()
        .to_owned()
}

fn charge(calls: u64) -> BudgetCharge {
    BudgetCharge {
        calls,
        file_bytes: 0,
        network_bytes: 0,
    }
}

fn activate(fixture: &JournalFixture) {
    fixture
        .store
        .activate_demo(&DemoActivation {
            instance_id: INSTANCE_ID.to_owned(),
            story_id: fixture.story.story_id,
            session_id: fixture.story.authority.session_id,
            process_id: 91,
            host_id: "security-test-host".to_owned(),
            instance_token_hash: token_hash(),
            now: mutation_time(&fixture.story, 0),
        })
        .unwrap();
}

fn policy_operation(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
    create_second: i64,
) -> SecurityOperation {
    policy_operation_with_charge(fixture, suffix, decision, create_second, charge(1))
}

fn policy_operation_with_charge(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
    create_second: i64,
    budget_charge: BudgetCharge,
) -> SecurityOperation {
    let mut input = fixture.operation(suffix, "send");
    let frozen = common::fixture_frozen_proposal_with_budget("send", budget_charge);
    input.proposal_commitment = frozen.proposal_commitment;
    input.provider_contract_hash = frozen.provider_contract_hash;
    input.budget_charge = frozen.budget_charge;
    input.now = mutation_time(&fixture.story, create_second);
    let operation = fixture.store.create_operation(input).unwrap().operation;
    let (next_state, status) = match decision {
        PolicyDecision::Allowed => (OperationState::PolicyEvaluated, PolicyCheckStatus::Passed),
        PolicyDecision::Denied => (OperationState::Denied, PolicyCheckStatus::Failed),
        PolicyDecision::RequiresReview => (
            OperationState::AwaitingApproval,
            PolicyCheckStatus::RequiresReview,
        ),
    };
    let next_state = if fixture.story.enforcement_mode == EnforcementMode::MonitorOnly {
        OperationState::PolicyEvaluated
    } else {
        next_state
    };
    fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision,
            reason: "security lease policy".to_owned(),
            next_state,
            checks: vec![PolicyCheck {
                check_id: format!("security-policy-{suffix}"),
                layer: "authority".to_owned(),
                status,
                reason: "durable security decision".to_owned(),
                observation_ref: None,
            }],
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
                .proposal_commitment,
            now: mutation_time(&fixture.story, create_second + 1),
        })
        .unwrap()
}

fn direct_request(
    fixture: &JournalFixture,
    operation_id: OperationId,
    lease_id: ExecutionLeaseId,
    expected_budget_version: u64,
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
        expected_budget_version,
        budget_charge,
        proposal_commitment: common::frozen_proposal(&fixture.store, operation_id)
            .proposal_commitment,
        provider_contract_hash: common::frozen_proposal(&fixture.store, operation_id)
            .provider_contract_hash,
        expires_at: mutation_time(&fixture.story, 120),
        now: mutation_time(&fixture.story, 10),
    }
}

fn approval_binding(
    fixture: &JournalFixture,
    operation: &SecurityOperation,
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
        proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
            .proposal_commitment,
        maximum_consumptions: OneShotConsumption::new(),
    }
}

fn approve_operation(
    fixture: &JournalFixture,
    operation: &SecurityOperation,
) -> runwarden_state::ApprovalRecordV1 {
    let approval_id = ApprovalId::new();
    fixture
        .store
        .create_approval(NewApproval {
            approval_id,
            operation_id: operation.operation_id,
            binding: approval_binding(fixture, operation),
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
            reviewer: "security-reviewer".to_owned(),
            reason: "approved only for the durable binding".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap()
}

fn reviewed_request(
    fixture: &JournalFixture,
    operation_id: OperationId,
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
        proposal_commitment: common::frozen_proposal(&fixture.store, operation_id)
            .proposal_commitment,
        provider_contract_hash: common::frozen_proposal(&fixture.store, operation_id)
            .provider_contract_hash,
        expires_at: mutation_time(&fixture.story, 120),
        now: mutation_time(&fixture.story, 10),
    }
}

fn completed_result(
    lease: &ExecutionLease,
    expected_operation_version: u64,
    lease_id: ExecutionLeaseId,
    lease_owner: &str,
) -> ExecutionResultInput {
    ExecutionResultInput {
        operation_id: lease.operation_id,
        expected_operation_version,
        lease_id,
        lease_owner: lease_owner.to_owned(),
        next_state: OperationState::Completed,
        side_effect_state: SideEffectState::Completed,
        provider_result: ProviderResultView {
            execution_status: ProviderExecutionStatus::Completed,
            output: SafeProviderOutput::Email {
                receipt_hash: Sha256Digest::from_bytes(b"security-test-receipt"),
            },
            output_hash: Some(Sha256Digest::from_bytes(b"security-test-output")),
            error_kind: None,
            reason_code: Some("completed".to_owned()),
        },
        actual_budget_charge: charge(1),
        now: time::OffsetDateTime::now_utc(),
    }
}

fn assert_unleased(
    fixture: &JournalFixture,
    operation_id: OperationId,
    expected_state: OperationState,
    expected_events: usize,
) {
    let operation = fixture.store.operation(operation_id).unwrap();
    assert_eq!(operation.state, expected_state);
    assert_eq!(operation.version, 1);
    assert!(
        fixture
            .store
            .execution_lease(operation_id)
            .unwrap()
            .is_none()
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 0);
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(budget.calls_committed, 0);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let reservations: i64 = connection
        .query_row("SELECT count(*) FROM budget_reservations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(reservations, 0);
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(evidence.events.len(), expected_events);
}

#[test]
fn acquisition_requires_exact_active_context_and_rolls_back_atomically() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 101, PolicyDecision::Allowed, 1);

    let missing = fixture.store.acquire_execution_lease(direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    ));
    assert!(matches!(
        missing,
        Err(JournalError::InvalidTransition {
            entity: "active_instance",
            ..
        })
    ));
    assert_unleased(
        &fixture,
        operation.operation_id,
        OperationState::PolicyEvaluated,
        2,
    );

    activate(&fixture);
    let mut wrong_instance = direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    );
    wrong_instance.instance_id = "different-instance".to_owned();
    assert!(matches!(
        fixture.store.acquire_execution_lease(wrong_instance),
        Err(JournalError::Integrity(_))
    ));
    assert_unleased(
        &fixture,
        operation.operation_id,
        OperationState::PolicyEvaluated,
        2,
    );

    let mut wrong_token = direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    );
    wrong_token.instance_token_hash = Sha256Digest::from_bytes(b"different-token")
        .as_str()
        .to_owned();
    assert!(matches!(
        fixture.store.acquire_execution_lease(wrong_token),
        Err(JournalError::Integrity(_))
    ));
    assert_unleased(
        &fixture,
        operation.operation_id,
        OperationState::PolicyEvaluated,
        2,
    );
}

#[test]
fn lease_rejects_contract_commitment_and_budget_drift_atomically() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 111, PolicyDecision::Allowed, 1);
    activate(&fixture);

    let mut changed_contract = direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    );
    changed_contract.provider_contract_hash = Sha256Digest::from_bytes(b"changed-contract");
    assert!(matches!(
        fixture.store.acquire_execution_lease(changed_contract),
        Err(JournalError::Integrity(_))
    ));

    let mut changed_commitment = direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    );
    changed_commitment.proposal_commitment = Sha256Digest::from_bytes(b"changed-proposal");
    assert!(matches!(
        fixture.store.acquire_execution_lease(changed_commitment),
        Err(JournalError::Integrity(_))
    ));

    let changed_budget = direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(0),
    );
    assert!(matches!(
        fixture.store.acquire_execution_lease(changed_budget),
        Err(JournalError::Integrity(_))
    ));
    assert_unleased(
        &fixture,
        operation.operation_id,
        OperationState::PolicyEvaluated,
        2,
    );
}

#[test]
fn monitor_only_story_cannot_acquire_an_execution_lease() {
    let fixture = JournalFixture::new(EnforcementMode::MonitorOnly);
    let operation = policy_operation(&fixture, 102, PolicyDecision::Allowed, 1);
    activate(&fixture);

    let error = fixture.store.acquire_execution_lease(direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    ));
    assert!(matches!(
        error,
        Err(JournalError::InvalidTransition {
            entity: "enforcement_mode",
            ..
        })
    ));
    assert_unleased(
        &fixture,
        operation.operation_id,
        OperationState::PolicyEvaluated,
        2,
    );
}

#[test]
fn expired_lease_cannot_cross_the_execution_start_boundary() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 108, PolicyDecision::Allowed, 1);
    activate(&fixture);
    let mut request = direct_request(
        &fixture,
        operation.operation_id,
        ExecutionLeaseId::new(),
        0,
        charge(1),
    );
    request.now = mutation_time(&fixture.story, 3);
    request.expires_at = mutation_time(&fixture.story, 4);
    let lease = fixture.store.acquire_execution_lease(request).unwrap();

    assert!(matches!(
        fixture.store.mark_execution_started(&lease),
        Err(JournalError::InvalidTransition {
            entity: "lease_expiry",
            ..
        })
    ));
    assert!(
        !fixture
            .store
            .has_execution_started(operation.operation_id)
            .unwrap()
    );
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
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        3
    );
}

#[test]
fn execution_runtime_snapshot_is_exact_before_and_after_start() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 109, PolicyDecision::Allowed, 1);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            charge(1),
        ))
        .unwrap();

    let leased = fixture
        .store
        .execution_runtime_snapshot(operation.operation_id)
        .unwrap();
    assert_eq!(leased.operation.state, OperationState::ExecutionLeased);
    assert_eq!(leased.policy_decision, PolicyDecision::Allowed);
    assert_eq!(leased.lease, lease);
    assert!(!leased.execution_started);

    let started = fixture.store.mark_execution_started(&lease).unwrap();
    let executing = fixture
        .store
        .execution_runtime_snapshot(operation.operation_id)
        .unwrap();
    assert_eq!(executing.operation.state, OperationState::Executing);
    assert_eq!(executing.operation.version, started.operation_version);
    assert_eq!(executing.policy_decision, PolicyDecision::Allowed);
    assert_eq!(executing.lease, lease);
    assert!(executing.execution_started);
}

#[test]
fn execution_runtime_snapshot_rejects_an_operation_without_a_lease() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 110, PolicyDecision::Allowed, 1);

    assert!(matches!(
        fixture
            .store
            .execution_runtime_snapshot(operation.operation_id),
        Err(JournalError::InvalidTransition {
            entity: "operation",
            ..
        })
    ));
}

#[test]
fn execution_runtime_snapshot_rejects_torn_state_and_start_evidence() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 111, PolicyDecision::Allowed, 1);
    activate(&fixture);
    fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            charge(1),
        ))
        .unwrap();

    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE operations SET state = 'executing' WHERE operation_id = ?1",
            params![operation.operation_id.to_string()],
        )
        .unwrap();

    assert!(matches!(
        fixture
            .store
            .execution_runtime_snapshot(operation.operation_id),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn reviewed_lease_rejects_binding_hash_tamper_without_partial_transition() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 103, PolicyDecision::RequiresReview, 1);
    let approval = approve_operation(&fixture, &operation);
    activate(&fixture);
    let request = reviewed_request(
        &fixture,
        operation.operation_id,
        approval.approval_id,
        ExecutionLeaseId::new(),
    );

    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE approvals SET binding_hash = ?1 WHERE approval_id = ?2",
            params![
                Sha256Digest::from_bytes(b"tampered-binding").as_str(),
                approval.approval_id.to_string(),
            ],
        )
        .unwrap();
    let error = fixture.store.acquire_execution_lease(request);
    assert!(matches!(error, Err(JournalError::Integrity(_))));

    let (operation_state, operation_version, operation_lease): (String, i64, Option<String>) =
        connection
            .query_row(
                "SELECT state, version, lease_id FROM operations WHERE operation_id = ?1",
                params![operation.operation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(operation_state, "approved");
    assert_eq!(operation_version, 2);
    assert!(operation_lease.is_none());
    let (approval_state, approval_version, approval_lease): (String, i64, Option<String>) =
        connection
            .query_row(
                "SELECT state, version, lease_id FROM approvals WHERE approval_id = ?1",
                params![approval.approval_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(approval_state, "approved");
    assert_eq!(approval_version, 1);
    assert!(approval_lease.is_none());
    let (budget_version, reserved): (i64, i64) = connection
        .query_row(
            "SELECT version, calls_reserved FROM budget_usage WHERE session_id = ?1",
            params![fixture.story.authority.session_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((budget_version, reserved), (0, 0));
    let reservations: i64 = connection
        .query_row("SELECT count(*) FROM budget_reservations", [], |row| {
            row.get(0)
        })
        .unwrap();
    let events: i64 = connection
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reservations, 0);
    assert_eq!(events, 4);
}

#[test]
fn duplicate_lease_id_rolls_back_the_second_operation_and_budget() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let first = policy_operation(&fixture, 104, PolicyDecision::Allowed, 1);
    let second = policy_operation(&fixture, 105, PolicyDecision::Allowed, 3);
    activate(&fixture);
    let lease_id = ExecutionLeaseId::new();
    let first_lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            first.operation_id,
            lease_id,
            0,
            charge(1),
        ))
        .unwrap();

    let duplicate = fixture.store.acquire_execution_lease(direct_request(
        &fixture,
        second.operation_id,
        lease_id,
        1,
        charge(1),
    ));
    assert!(matches!(
        duplicate,
        Err(JournalError::Conflict {
            entity: "lease",
            ..
        })
    ));
    assert_eq!(
        fixture.store.execution_lease(first.operation_id).unwrap(),
        Some(first_lease)
    );
    let second = fixture.store.operation(second.operation_id).unwrap();
    assert_eq!(second.state, OperationState::PolicyEvaluated);
    assert_eq!(second.version, 1);
    assert!(
        fixture
            .store
            .execution_lease(second.operation_id)
            .unwrap()
            .is_none()
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 1);
    assert_eq!(budget.calls_reserved, 1);
    assert_eq!(budget.calls_committed, 0);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let reservations: i64 = connection
        .query_row("SELECT count(*) FROM budget_reservations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(reservations, 1);
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(evidence.events.len(), 5);
}

#[test]
fn execution_result_identity_and_matrix_failures_are_atomic() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 106, PolicyDecision::Allowed, 1);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            charge(1),
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();

    let wrong_owner = completed_result(
        &lease,
        started.operation_version,
        lease.lease_id,
        "different-owner",
    );
    assert!(matches!(
        fixture.store.record_execution_result(wrong_owner),
        Err(JournalError::Integrity(_))
    ));
    let wrong_id = completed_result(
        &lease,
        started.operation_version,
        ExecutionLeaseId::new(),
        &lease.lease_owner,
    );
    assert!(matches!(
        fixture.store.record_execution_result(wrong_id),
        Err(JournalError::Integrity(_))
    ));
    let mut invalid_matrix = completed_result(
        &lease,
        started.operation_version,
        lease.lease_id,
        &lease.lease_owner,
    );
    invalid_matrix.provider_result.execution_status =
        ProviderExecutionStatus::FailedBeforeSideEffect;
    invalid_matrix.provider_result.output = SafeProviderOutput::None;
    invalid_matrix.provider_result.output_hash = None;
    invalid_matrix.provider_result.error_kind = Some("preflight_failed".to_owned());
    invalid_matrix.provider_result.reason_code = Some("blocked_before_side_effect".to_owned());
    invalid_matrix.side_effect_state = SideEffectState::BlockedBeforeExecution;
    invalid_matrix.actual_budget_charge = charge(0);
    assert!(matches!(
        fixture.store.record_execution_result(invalid_matrix),
        Err(JournalError::InvalidTransition {
            entity: "execution_result",
            ..
        })
    ));

    let operation = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(operation.state, OperationState::Executing);
    assert_eq!(operation.version, started.operation_version);
    assert!(operation.provider_result.is_none());
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 1);
    assert_eq!(budget.calls_reserved, 1);
    assert_eq!(budget.calls_committed, 0);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let reservation_state: String = connection
        .query_row(
            "SELECT state FROM budget_reservations WHERE lease_id = ?1",
            params![lease.lease_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reservation_state, "reserved");
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(evidence.events.len(), 4);
}

#[test]
fn pre_side_effect_failure_releases_the_unused_reservation() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation =
        policy_operation_with_charge(&fixture, 107, PolicyDecision::Allowed, 1, charge(3));
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            charge(3),
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    fixture
        .store
        .record_execution_result(ExecutionResultInput {
            operation_id: operation.operation_id,
            expected_operation_version: started.operation_version,
            lease_id: lease.lease_id,
            lease_owner: lease.lease_owner.clone(),
            next_state: OperationState::Failed,
            side_effect_state: SideEffectState::BlockedBeforeExecution,
            provider_result: ProviderResultView {
                execution_status: ProviderExecutionStatus::FailedBeforeSideEffect,
                output: SafeProviderOutput::None,
                output_hash: None,
                error_kind: Some("provider_preflight_failed".to_owned()),
                reason_code: Some("blocked_before_side_effect".to_owned()),
            },
            actual_budget_charge: charge(0),
            now: time::OffsetDateTime::now_utc(),
        })
        .unwrap();

    let failed = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(failed.state, OperationState::Failed);
    assert_eq!(
        failed.side_effect_state,
        SideEffectState::BlockedBeforeExecution
    );
    assert_eq!(
        failed.provider_result.as_ref().unwrap().execution_status,
        ProviderExecutionStatus::FailedBeforeSideEffect
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 2);
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(budget.calls_committed, 0);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    let (reservation_state, charge_json): (String, String) = connection
        .query_row(
            "SELECT state, charge_json FROM budget_reservations WHERE lease_id = ?1",
            params![lease.lease_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(reservation_state, "committed");
    let settled: Value = serde_json::from_str(&charge_json).unwrap();
    assert_eq!(settled["reserved"]["calls"], 3);
    assert_eq!(settled["actual"]["calls"], 0);
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(evidence.events.len(), 5);
}
