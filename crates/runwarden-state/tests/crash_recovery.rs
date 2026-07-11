mod common;

use std::sync::{Arc, Barrier};

use common::{JournalFixture, mutation_time};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, ProviderExecutionStatus, ProviderResultView,
    SafeProviderOutput, SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::DataClass;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{
    ApprovalId, EnforcementMode, EvidenceStatus, ExecutionLeaseId, OperationId, StoryReplayFrame,
};
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use runwarden_state::{
    ApprovalDecisionInput, DemoActivation, DurableApprovalBinding, ExecutionLease,
    ExecutionResultInput, JournalError, LeaseAuthorization, LeaseRequest, MarkOutcomeUnknownInput,
    NewApproval, OneShotConsumption, RecordPolicyInput, RecoveryCandidate, ReleaseLeaseInput,
    ReviewerDecision,
};
use rusqlite::{Connection, params};
use time::format_description::well_known::Rfc3339;

const INSTANCE_ID: &str = "recovery-instance";
const LEASE_OWNER: &str = "recovery-runtime";

fn token_hash() -> String {
    Sha256Digest::from_bytes(b"recovery-instance-token")
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
            process_id: 93,
            host_id: "recovery-host".to_owned(),
            instance_token_hash: token_hash(),
            now: mutation_time(&fixture.story, 0),
        })
        .unwrap();
}

fn policy_operation_at(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
    create_second: i64,
    policy_second: i64,
) -> SecurityOperation {
    policy_operation_at_with_charge(
        fixture,
        suffix,
        decision,
        create_second,
        policy_second,
        charge(1),
    )
}

fn policy_operation_at_with_charge(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
    create_second: i64,
    policy_second: i64,
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
    fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision,
            reason: "recovery policy".to_owned(),
            next_state,
            checks: vec![PolicyCheck {
                check_id: format!("recovery-policy-{suffix}"),
                layer: "authority".to_owned(),
                status,
                reason: "durable recovery decision".to_owned(),
                observation_ref: None,
            }],
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
                .proposal_commitment,
            now: mutation_time(&fixture.story, policy_second),
        })
        .unwrap()
}

fn policy_operation(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
) -> SecurityOperation {
    policy_operation_at(fixture, suffix, decision, 1, 2)
}

fn policy_operation_with_charge(
    fixture: &JournalFixture,
    suffix: u8,
    decision: PolicyDecision,
    budget_charge: BudgetCharge,
) -> SecurityOperation {
    policy_operation_at_with_charge(fixture, suffix, decision, 1, 2, budget_charge)
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
    expires_second: i64,
) -> runwarden_state::ApprovalRecordV1 {
    let approval_id = ApprovalId::new();
    fixture
        .store
        .create_approval(NewApproval {
            approval_id,
            operation_id: operation.operation_id,
            binding: approval_binding(fixture, operation),
            expires_at: mutation_time(&fixture.story, expires_second),
            now: mutation_time(&fixture.story, 3),
        })
        .unwrap();
    fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "recovery-reviewer".to_owned(),
            reason: "bounded recovery approval".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap()
}

fn direct_request(
    fixture: &JournalFixture,
    operation_id: OperationId,
    lease_id: ExecutionLeaseId,
    expected_budget_version: u64,
    calls: u64,
    now_second: i64,
    expires_second: i64,
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
        budget_charge: charge(calls),
        proposal_commitment: common::frozen_proposal(&fixture.store, operation_id)
            .proposal_commitment,
        provider_contract_hash: common::frozen_proposal(&fixture.store, operation_id)
            .provider_contract_hash,
        expires_at: mutation_time(&fixture.story, expires_second),
        now: mutation_time(&fixture.story, now_second),
    }
}

fn reviewed_request(
    fixture: &JournalFixture,
    operation_id: OperationId,
    approval_id: ApprovalId,
    lease_id: ExecutionLeaseId,
    expires_second: i64,
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
        expires_at: mutation_time(&fixture.story, expires_second),
        now: mutation_time(&fixture.story, 5),
    }
}

fn completed_result(
    lease: &ExecutionLease,
    expected_operation_version: u64,
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
                receipt_hash: Sha256Digest::from_bytes(b"recovered-receipt"),
            },
            output_hash: Some(Sha256Digest::from_bytes(b"recovered-output")),
            error_kind: None,
            reason_code: Some("completed".to_owned()),
        },
        actual_budget_charge: charge(1),
        now: time::OffsetDateTime::now_utc(),
    }
}

fn failed_before_side_effect_result(
    lease: &ExecutionLease,
    expected_operation_version: u64,
) -> ExecutionResultInput {
    ExecutionResultInput {
        operation_id: lease.operation_id,
        expected_operation_version,
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
    }
}

fn candidate_for(operation: &SecurityOperation, lease: &ExecutionLease) -> RecoveryCandidate {
    RecoveryCandidate {
        operation_id: operation.operation_id,
        operation_version: operation.version,
        lease_id: lease.lease_id,
        lease_owner: lease.lease_owner.clone(),
        lease_expires_at: lease.expires_at,
    }
}

fn reservation_state(fixture: &JournalFixture, lease_id: ExecutionLeaseId) -> String {
    Connection::open(fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .query_row(
            "SELECT state FROM budget_reservations WHERE lease_id = ?1",
            params![lease_id.to_string()],
            |row| row.get(0),
        )
        .unwrap()
}

fn reservation_charge_json(fixture: &JournalFixture, lease_id: ExecutionLeaseId) -> String {
    Connection::open(fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .query_row(
            "SELECT charge_json FROM budget_reservations WHERE lease_id = ?1",
            params![lease_id.to_string()],
            |row| row.get(0),
        )
        .unwrap()
}

fn freeze_story_evidence(fixture: &JournalFixture) {
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    let old_frame = evidence.replay_frames.last().unwrap();
    let mut frozen_story = evidence.story;
    frozen_story.evidence_status = EvidenceStatus::Verified;
    let frozen_frame = StoryReplayFrame::seal(
        old_frame.sequence,
        old_frame.story_version,
        old_frame.event_hash.clone(),
        old_frame.previous_frame_hash.clone(),
        old_frame.recorded_at,
        frozen_story.clone(),
    )
    .unwrap();
    let frozen_json = String::from_utf8(canonical_json_v1(
        &serde_json::to_value(&frozen_story).unwrap(),
    ))
    .unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            r#"UPDATE story_frames
               SET snapshot_hash = ?1, frame_hash = ?2, safe_story_json = ?3
               WHERE story_id = ?4 AND sequence = ?5"#,
            params![
                frozen_frame.snapshot_hash,
                frozen_frame.frame_hash,
                frozen_json,
                fixture.story.story_id.to_string(),
                i64::try_from(old_frame.sequence).unwrap(),
            ],
        )
        .unwrap();
    connection
        .execute(
            r#"UPDATE stories
               SET evidence_status = 'verified', safe_story_json = ?1
               WHERE story_id = ?2"#,
            params![frozen_json, fixture.story.story_id.to_string()],
        )
        .unwrap();
}

#[test]
fn recovery_candidates_include_only_expired_executing_operations_in_deterministic_order() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    activate(&fixture);
    let first = policy_operation_at(&fixture, 121, PolicyDecision::Allowed, 1, 2);
    let first_lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            first.operation_id,
            ExecutionLeaseId::new(),
            0,
            1,
            3,
            80,
        ))
        .unwrap();
    let second = policy_operation_at(&fixture, 122, PolicyDecision::Allowed, 4, 5);
    let second_lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            second.operation_id,
            ExecutionLeaseId::new(),
            1,
            1,
            6,
            120,
        ))
        .unwrap();
    let third = policy_operation_at(&fixture, 123, PolicyDecision::Allowed, 7, 8);
    let third_lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            third.operation_id,
            ExecutionLeaseId::new(),
            2,
            1,
            9,
            120,
        ))
        .unwrap();
    fixture.store.mark_execution_started(&first_lease).unwrap();
    fixture.store.mark_execution_started(&second_lease).unwrap();
    fixture.store.mark_execution_started(&third_lease).unwrap();

    assert!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 79))
            .unwrap()
            .is_empty()
    );
    let first_state = fixture.store.operation(first.operation_id).unwrap();
    let second_state = fixture.store.operation(second.operation_id).unwrap();
    let third_state = fixture.store.operation(third.operation_id).unwrap();
    let mut tied = vec![
        candidate_for(&second_state, &second_lease),
        candidate_for(&third_state, &third_lease),
    ];
    tied.sort_by_key(|candidate| candidate.operation_id);
    let mut expected = vec![candidate_for(&first_state, &first_lease)];
    expected.extend(tied);
    assert_eq!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 121))
            .unwrap(),
        expected
    );
}

#[test]
fn direct_unstarted_release_cas_restores_policy_and_releases_budget() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation_with_charge(&fixture, 124, PolicyDecision::Allowed, charge(2));
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            2,
            3,
            120,
        ))
        .unwrap();
    let leased = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(leased.state, OperationState::ExecutionLeased);
    assert!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 121))
            .unwrap()
            .is_empty()
    );

    let wrong_lease = fixture.store.release_unstarted_lease(ReleaseLeaseInput {
        operation_id: operation.operation_id,
        expected_operation_version: leased.version,
        lease_id: ExecutionLeaseId::new(),
        now: mutation_time(&fixture.story, 121),
    });
    assert!(matches!(wrong_lease, Err(JournalError::Integrity(_))));
    let stale_version = fixture.store.release_unstarted_lease(ReleaseLeaseInput {
        operation_id: operation.operation_id,
        expected_operation_version: leased.version - 1,
        lease_id: lease.lease_id,
        now: mutation_time(&fixture.story, 121),
    });
    assert!(matches!(
        stale_version,
        Err(JournalError::Conflict {
            entity: "operation",
            ..
        })
    ));
    assert_eq!(
        fixture.store.operation(operation.operation_id).unwrap(),
        leased
    );
    assert_eq!(reservation_state(&fixture, lease.lease_id), "reserved");

    let before_expiry = fixture.store.release_unstarted_lease(ReleaseLeaseInput {
        operation_id: operation.operation_id,
        expected_operation_version: leased.version,
        lease_id: lease.lease_id,
        now: mutation_time(&fixture.story, 119),
    });
    assert!(matches!(
        before_expiry,
        Err(JournalError::InvalidTransition {
            entity: "lease_expiry",
            ..
        })
    ));

    let released = fixture
        .store
        .release_unstarted_lease(ReleaseLeaseInput {
            operation_id: operation.operation_id,
            expected_operation_version: leased.version,
            lease_id: lease.lease_id,
            now: mutation_time(&fixture.story, 121),
        })
        .unwrap();
    assert_eq!(released.state, OperationState::PolicyEvaluated);
    assert_eq!(released.side_effect_state, SideEffectState::NotAttempted);
    assert!(
        fixture
            .store
            .approval_for_operation(operation.operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        fixture
            .store
            .execution_lease(operation.operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        !fixture
            .store
            .has_execution_started(operation.operation_id)
            .unwrap()
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 2);
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(budget.calls_committed, 0);
    assert_eq!(reservation_state(&fixture, lease.lease_id), "released");
    assert_eq!(
        serde_json::from_str::<BudgetCharge>(&reservation_charge_json(&fixture, lease.lease_id))
            .unwrap(),
        charge(2)
    );
    assert!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 121))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn recovery_write_rejects_a_verified_story_without_partial_release() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation_with_charge(&fixture, 133, PolicyDecision::Allowed, charge(2));
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            2,
            3,
            120,
        ))
        .unwrap();
    let leased = fixture.store.operation(operation.operation_id).unwrap();
    freeze_story_evidence(&fixture);
    fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .verify_structure()
        .unwrap();

    let error = fixture
        .store
        .release_unstarted_lease(ReleaseLeaseInput {
            operation_id: operation.operation_id,
            expected_operation_version: leased.version,
            lease_id: lease.lease_id,
            now: mutation_time(&fixture.story, 121),
        })
        .unwrap_err();
    assert!(matches!(
        error,
        JournalError::InvalidTransition {
            entity: "story_evidence",
            ..
        }
    ));
    assert_eq!(
        fixture.store.operation(operation.operation_id).unwrap(),
        leased
    );
    assert_eq!(reservation_state(&fixture, lease.lease_id), "reserved");
}

#[test]
fn recovery_rejects_tampered_budget_aggregates_and_reservation_time_atomically() {
    let release_fixture = JournalFixture::new(EnforcementMode::Enforced);
    let release_operation =
        policy_operation_with_charge(&release_fixture, 134, PolicyDecision::Allowed, charge(3));
    activate(&release_fixture);
    let release_lease = release_fixture
        .store
        .acquire_execution_lease(direct_request(
            &release_fixture,
            release_operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            3,
            3,
            120,
        ))
        .unwrap();
    let release_leased = release_fixture
        .store
        .operation(release_operation.operation_id)
        .unwrap();
    let events_before = release_fixture
        .store
        .story_evidence(release_fixture.story.story_id)
        .unwrap()
        .events
        .len();
    Connection::open(release_fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE budget_usage SET calls_reserved = calls_reserved + 1 WHERE session_id = ?1",
            params![release_fixture.story.authority.session_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        release_fixture
            .store
            .release_unstarted_lease(ReleaseLeaseInput {
                operation_id: release_operation.operation_id,
                expected_operation_version: release_leased.version,
                lease_id: release_lease.lease_id,
                now: mutation_time(&release_fixture.story, 121),
            }),
        Err(JournalError::Integrity(_))
    ));
    assert_eq!(
        release_fixture
            .store
            .operation(release_operation.operation_id)
            .unwrap(),
        release_leased
    );
    assert_eq!(
        reservation_state(&release_fixture, release_lease.lease_id),
        "reserved"
    );
    assert_eq!(
        release_fixture
            .store
            .story_evidence(release_fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        events_before
    );

    let unknown_fixture = JournalFixture::new(EnforcementMode::Enforced);
    let unknown_operation =
        policy_operation_with_charge(&unknown_fixture, 135, PolicyDecision::Allowed, charge(3));
    activate(&unknown_fixture);
    let unknown_lease = unknown_fixture
        .store
        .acquire_execution_lease(direct_request(
            &unknown_fixture,
            unknown_operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            3,
            3,
            120,
        ))
        .unwrap();
    let unknown_started = unknown_fixture
        .store
        .mark_execution_started(&unknown_lease)
        .unwrap();
    Connection::open(unknown_fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE budget_usage SET calls_reserved = calls_reserved + 1 WHERE session_id = ?1",
            params![unknown_fixture.story.authority.session_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        unknown_fixture
            .store
            .mark_outcome_unknown(MarkOutcomeUnknownInput {
                operation_id: unknown_operation.operation_id,
                expected_operation_version: unknown_started.operation_version,
                lease_id: unknown_lease.lease_id,
                lease_owner: unknown_lease.lease_owner.clone(),
                reason_code: "provider_result_not_durable".to_owned(),
                now: time::OffsetDateTime::now_utc(),
            }),
        Err(JournalError::Integrity(_))
    ));
    assert_eq!(
        unknown_fixture
            .store
            .operation(unknown_operation.operation_id)
            .unwrap()
            .state,
        OperationState::Executing
    );
    assert_eq!(
        reservation_state(&unknown_fixture, unknown_lease.lease_id),
        "reserved"
    );

    let time_fixture = JournalFixture::new(EnforcementMode::Enforced);
    let time_operation = policy_operation(&time_fixture, 136, PolicyDecision::Allowed);
    activate(&time_fixture);
    let time_lease = time_fixture
        .store
        .acquire_execution_lease(direct_request(
            &time_fixture,
            time_operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            1,
            3,
            120,
        ))
        .unwrap();
    let time_leased = time_fixture
        .store
        .operation(time_operation.operation_id)
        .unwrap();
    let forged_future = mutation_time(&time_fixture.story, 150)
        .format(&Rfc3339)
        .unwrap();
    Connection::open(time_fixture.state_dir.join("runwarden.db"))
        .unwrap()
        .execute(
            "UPDATE budget_reservations SET updated_at = ?1 WHERE lease_id = ?2",
            params![forged_future, time_lease.lease_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        time_fixture
            .store
            .release_unstarted_lease(ReleaseLeaseInput {
                operation_id: time_operation.operation_id,
                expected_operation_version: time_leased.version,
                lease_id: time_lease.lease_id,
                now: mutation_time(&time_fixture.story, 121),
            }),
        Err(JournalError::Integrity(_))
            | Err(JournalError::InvalidTransition {
                entity: "budget_reservation_time",
                ..
            })
    ));
    assert_eq!(
        reservation_state(&time_fixture, time_lease.lease_id),
        "reserved"
    );
}

#[test]
fn reviewed_unstarted_release_restores_live_approval_or_expires_both() {
    let live = JournalFixture::new(EnforcementMode::Enforced);
    let live_operation = policy_operation(&live, 125, PolicyDecision::RequiresReview);
    let live_approval = approve_operation(&live, &live_operation, 200);
    activate(&live);
    let live_lease = live
        .store
        .acquire_execution_lease(reviewed_request(
            &live,
            live_operation.operation_id,
            live_approval.approval_id,
            ExecutionLeaseId::new(),
            120,
        ))
        .unwrap();
    let live_leased = live.store.operation(live_operation.operation_id).unwrap();
    assert!(
        live.store
            .recovery_candidates(mutation_time(&live.story, 121))
            .unwrap()
            .is_empty()
    );
    let restored = live
        .store
        .release_unstarted_lease(ReleaseLeaseInput {
            operation_id: live_operation.operation_id,
            expected_operation_version: live_leased.version,
            lease_id: live_lease.lease_id,
            now: mutation_time(&live.story, 121),
        })
        .unwrap();
    assert_eq!(restored.state, OperationState::Approved);
    let restored_approval = live.store.approval(live_approval.approval_id).unwrap();
    assert_eq!(restored_approval.state, ApprovalState::Approved);
    assert!(restored_approval.lease_id.is_none());
    assert_eq!(restored_approval.version, 3);
    assert_eq!(reservation_state(&live, live_lease.lease_id), "released");
    assert!(
        live.store
            .recovery_candidates(mutation_time(&live.story, 121))
            .unwrap()
            .is_empty()
    );

    let expired = JournalFixture::new(EnforcementMode::Enforced);
    let expired_operation = policy_operation(&expired, 126, PolicyDecision::RequiresReview);
    let expired_approval = approve_operation(&expired, &expired_operation, 100);
    activate(&expired);
    let expired_lease = expired
        .store
        .acquire_execution_lease(reviewed_request(
            &expired,
            expired_operation.operation_id,
            expired_approval.approval_id,
            ExecutionLeaseId::new(),
            80,
        ))
        .unwrap();
    let expired_leased = expired
        .store
        .operation(expired_operation.operation_id)
        .unwrap();
    let terminal = expired
        .store
        .release_unstarted_lease(ReleaseLeaseInput {
            operation_id: expired_operation.operation_id,
            expected_operation_version: expired_leased.version,
            lease_id: expired_lease.lease_id,
            now: mutation_time(&expired.story, 101),
        })
        .unwrap();
    assert_eq!(terminal.state, OperationState::Expired);
    assert_eq!(
        terminal.side_effect_state,
        SideEffectState::BlockedBeforeExecution
    );
    let approval = expired
        .store
        .approval(expired_approval.approval_id)
        .unwrap();
    assert_eq!(approval.state, ApprovalState::Expired);
    assert!(approval.lease_id.is_none());
    assert_eq!(approval.version, 3);
    assert_eq!(
        reservation_state(&expired, expired_lease.lease_id),
        "released"
    );
    assert!(
        expired
            .store
            .recovery_candidates(mutation_time(&expired.story, 101))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn started_execution_is_never_released_and_unknown_commits_full_budget() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation_with_charge(&fixture, 127, PolicyDecision::Allowed, charge(3));
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            3,
            3,
            120,
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    let executing = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(executing.version, started.operation_version);
    assert_eq!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 121))
            .unwrap(),
        vec![candidate_for(&executing, &lease)]
    );
    assert!(matches!(
        fixture.store.release_unstarted_lease(ReleaseLeaseInput {
            operation_id: operation.operation_id,
            expected_operation_version: executing.version,
            lease_id: lease.lease_id,
            now: mutation_time(&fixture.story, 121),
        }),
        Err(JournalError::InvalidTransition { .. })
    ));

    let wrong_owner = fixture.store.mark_outcome_unknown(MarkOutcomeUnknownInput {
        operation_id: operation.operation_id,
        expected_operation_version: executing.version,
        lease_id: lease.lease_id,
        lease_owner: "other-runtime".to_owned(),
        reason_code: "provider_result_not_durable".to_owned(),
        now: mutation_time(&fixture.story, 121),
    });
    assert!(matches!(wrong_owner, Err(JournalError::Integrity(_))));
    let wrong_id = fixture.store.mark_outcome_unknown(MarkOutcomeUnknownInput {
        operation_id: operation.operation_id,
        expected_operation_version: executing.version,
        lease_id: ExecutionLeaseId::new(),
        lease_owner: lease.lease_owner.clone(),
        reason_code: "provider_result_not_durable".to_owned(),
        now: mutation_time(&fixture.story, 121),
    });
    assert!(matches!(wrong_id, Err(JournalError::Integrity(_))));
    let stale = fixture.store.mark_outcome_unknown(MarkOutcomeUnknownInput {
        operation_id: operation.operation_id,
        expected_operation_version: executing.version - 1,
        lease_id: lease.lease_id,
        lease_owner: lease.lease_owner.clone(),
        reason_code: "provider_result_not_durable".to_owned(),
        now: mutation_time(&fixture.story, 121),
    });
    assert!(matches!(
        stale,
        Err(JournalError::Conflict {
            entity: "operation",
            ..
        })
    ));
    let invalid_reason = fixture.store.mark_outcome_unknown(MarkOutcomeUnknownInput {
        operation_id: operation.operation_id,
        expected_operation_version: executing.version,
        lease_id: lease.lease_id,
        lease_owner: lease.lease_owner.clone(),
        reason_code: "raw provider exception: bearer secret".to_owned(),
        now: time::OffsetDateTime::now_utc(),
    });
    assert!(matches!(invalid_reason, Err(JournalError::Integrity(_))));
    assert_eq!(
        fixture.store.operation(operation.operation_id).unwrap(),
        executing
    );
    let reserved = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(reserved.calls_reserved, 3);
    assert_eq!(reserved.calls_committed, 0);

    let unknown = fixture
        .store
        .mark_outcome_unknown(MarkOutcomeUnknownInput {
            operation_id: operation.operation_id,
            expected_operation_version: executing.version,
            lease_id: lease.lease_id,
            lease_owner: lease.lease_owner.clone(),
            reason_code: "provider_result_not_durable".to_owned(),
            now: time::OffsetDateTime::now_utc(),
        })
        .unwrap();
    assert_eq!(unknown.state, OperationState::OutcomeUnknown);
    assert_eq!(unknown.side_effect_state, SideEffectState::OutcomeUnknown);
    assert_eq!(
        unknown.provider_result,
        Some(ProviderResultView {
            execution_status: ProviderExecutionStatus::OutcomeUnknown,
            output: SafeProviderOutput::None,
            output_hash: None,
            error_kind: Some("provider_outcome_unknown".to_owned()),
            reason_code: Some("provider_result_not_durable".to_owned()),
        })
    );
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 2);
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(budget.calls_committed, 3);
    assert_eq!(reservation_state(&fixture, lease.lease_id), "committed");
    assert!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 121))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn stale_recovery_candidate_cannot_overwrite_a_completed_result() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation(&fixture, 128, PolicyDecision::Allowed);
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            1,
            3,
            120,
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    let candidates = fixture
        .store
        .recovery_candidates(mutation_time(&fixture.story, 121))
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].operation_version, started.operation_version);
    fixture
        .store
        .record_execution_result(completed_result(&lease, started.operation_version))
        .unwrap();

    let stale = fixture.store.mark_outcome_unknown(MarkOutcomeUnknownInput {
        operation_id: operation.operation_id,
        expected_operation_version: candidates[0].operation_version,
        lease_id: candidates[0].lease_id,
        lease_owner: candidates[0].lease_owner.clone(),
        reason_code: "provider_result_not_durable".to_owned(),
        now: time::OffsetDateTime::now_utc(),
    });
    assert!(matches!(
        stale,
        Err(JournalError::Conflict {
            entity: "operation",
            ..
        })
    ));
    let completed = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(completed.state, OperationState::Completed);
    assert_eq!(completed.side_effect_state, SideEffectState::Completed);
    assert!(
        fixture
            .store
            .recovery_candidates(mutation_time(&fixture.story, 121))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn provider_result_and_unknown_recovery_have_exactly_one_atomic_winner() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = policy_operation_with_charge(&fixture, 132, PolicyDecision::Allowed, charge(3));
    activate(&fixture);
    let lease = fixture
        .store
        .acquire_execution_lease(direct_request(
            &fixture,
            operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            3,
            3,
            120,
        ))
        .unwrap();
    let started = fixture.store.mark_execution_started(&lease).unwrap();
    let started_version = started.operation_version;
    let barrier = Arc::new(Barrier::new(2));

    let result_store = fixture.store.clone();
    let result_barrier = Arc::clone(&barrier);
    let result_lease = lease.clone();
    let result_thread = std::thread::spawn(move || {
        result_barrier.wait();
        result_store.record_execution_result(completed_result(&result_lease, started_version))
    });
    let recovery_store = fixture.store.clone();
    let recovery_barrier = Arc::clone(&barrier);
    let recovery_lease = lease.clone();
    let recovery_thread = std::thread::spawn(move || {
        recovery_barrier.wait();
        recovery_store.mark_outcome_unknown(MarkOutcomeUnknownInput {
            operation_id: recovery_lease.operation_id,
            expected_operation_version: started_version,
            lease_id: recovery_lease.lease_id,
            lease_owner: recovery_lease.lease_owner.clone(),
            reason_code: "provider_result_not_durable".to_owned(),
            now: time::OffsetDateTime::now_utc(),
        })
    });

    let result = result_thread.join().unwrap();
    let recovery = recovery_thread.join().unwrap();
    assert_ne!(result.is_ok(), recovery.is_ok());
    let loser_is_conflict = match (&result, &recovery) {
        (Err(JournalError::Conflict { entity, .. }), Ok(_))
        | (Ok(_), Err(JournalError::Conflict { entity, .. })) => *entity == "operation",
        _ => false,
    };
    assert!(loser_is_conflict, "loser must observe the operation CAS");

    let operation = fixture.store.operation(operation.operation_id).unwrap();
    assert!(matches!(
        operation.state,
        OperationState::Completed | OperationState::OutcomeUnknown
    ));
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .unwrap();
    assert_eq!(budget.version, 2);
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(
        budget.calls_committed,
        if operation.state == OperationState::Completed {
            1
        } else {
            3
        }
    );
    assert_eq!(reservation_state(&fixture, lease.lease_id), "committed");
    fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .verify_structure()
        .unwrap();
}

#[test]
fn denied_and_failed_terminal_operations_are_not_recovery_candidates() {
    let denied = JournalFixture::new(EnforcementMode::Enforced);
    let denied_operation = policy_operation(&denied, 129, PolicyDecision::Denied);
    assert_eq!(denied_operation.state, OperationState::Denied);
    assert!(
        denied
            .store
            .recovery_candidates(mutation_time(&denied.story, 500))
            .unwrap()
            .is_empty()
    );

    let failed = JournalFixture::new(EnforcementMode::Enforced);
    let failed_operation = policy_operation(&failed, 130, PolicyDecision::Allowed);
    activate(&failed);
    let lease = failed
        .store
        .acquire_execution_lease(direct_request(
            &failed,
            failed_operation.operation_id,
            ExecutionLeaseId::new(),
            0,
            1,
            3,
            120,
        ))
        .unwrap();
    let started = failed.store.mark_execution_started(&lease).unwrap();
    failed
        .store
        .record_execution_result(failed_before_side_effect_result(
            &lease,
            started.operation_version,
        ))
        .unwrap();
    assert_eq!(
        failed
            .store
            .operation(failed_operation.operation_id)
            .unwrap()
            .state,
        OperationState::Failed
    );
    assert!(
        failed
            .store
            .recovery_candidates(mutation_time(&failed.story, 500))
            .unwrap()
            .is_empty()
    );
}
