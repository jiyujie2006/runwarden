mod common;

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, SecurityOperation, SideEffectState,
};
use runwarden_kernel::story::ApprovalId;
use runwarden_kernel::trace::{Sha256Digest, StoryEventPayload, canonical_json_v1};
use runwarden_state::{
    ApprovalDecisionInput, DurableApprovalBinding, ExpireApprovalInput, JournalError, NewApproval,
    OneShotConsumption, RecordPolicyInput, ReviewerDecision,
};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;

#[derive(Deserialize)]
struct OneShotEnvelope {
    maximum_consumptions: OneShotConsumption,
}

fn review_operation(fixture: &JournalFixture, suffix: u8) -> SecurityOperation {
    let operation = fixture
        .store
        .create_operation(fixture.operation(suffix, "send"))
        .unwrap()
        .operation;
    let operation = fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::RequiresReview,
            reason: "recipient requires a reviewer".to_owned(),
            next_state: OperationState::AwaitingApproval,
            checks: vec![PolicyCheck {
                check_id: "approval".to_owned(),
                layer: "authority".to_owned(),
                status: PolicyCheckStatus::RequiresReview,
                reason: "review is required".to_owned(),
                observation_ref: None,
            }],
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
                .proposal_commitment,
            now: mutation_time(&fixture.story, 2),
        })
        .unwrap();
    assert_eq!(
        fixture
            .store
            .policy_decision(operation.operation_id)
            .unwrap(),
        Some(PolicyDecision::RequiresReview)
    );
    operation
}

fn approval_binding(
    fixture: &JournalFixture,
    operation: &SecurityOperation,
) -> DurableApprovalBinding {
    let frozen = common::frozen_proposal(&fixture.store, operation.operation_id);
    DurableApprovalBinding::from_operation(operation, &frozen, &fixture.story.authority).unwrap()
}

fn create_pending(
    fixture: &JournalFixture,
    operation: &SecurityOperation,
    approval_id: ApprovalId,
    expires_at: OffsetDateTime,
) -> runwarden_state::ApprovalRecordV1 {
    fixture
        .store
        .create_approval(NewApproval {
            approval_id,
            operation_id: operation.operation_id,
            binding: approval_binding(fixture, operation),
            expires_at,
            now: mutation_time(&fixture.story, 3),
        })
        .unwrap()
}

#[test]
fn one_shot_consumption_accepts_only_the_json_integer_one() {
    assert_eq!(
        serde_json::to_value(OneShotConsumption::new()).unwrap(),
        json!(1)
    );
    let accepted: OneShotEnvelope =
        serde_json::from_value(json!({"maximum_consumptions": 1})).unwrap();
    assert_eq!(accepted.maximum_consumptions, OneShotConsumption::new());

    for invalid in [
        json!({"maximum_consumptions": 0}),
        json!({"maximum_consumptions": 2}),
        json!({"maximum_consumptions": -1}),
        json!({"maximum_consumptions": 1.0}),
        json!({"maximum_consumptions": "1"}),
        json!({"maximum_consumptions": null}),
        json!({}),
    ] {
        assert!(serde_json::from_value::<OneShotEnvelope>(invalid).is_err());
    }
}

#[test]
fn pending_approval_round_trips_a_canonical_bound_record_and_safe_event() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 31);
    let approval_id = ApprovalId::new();
    let expires_at = mutation_time(&fixture.story, 120);
    let record = create_pending(&fixture, &operation, approval_id, expires_at);

    assert_eq!(record.approval_id, approval_id);
    assert_eq!(record.operation_id, operation.operation_id);
    assert_eq!(record.state, ApprovalState::Pending);
    assert_eq!(record.version, 0);
    assert_eq!(record.expires_at, expires_at);
    assert_eq!(record.binding, approval_binding(&fixture, &operation));
    let binding_bytes = canonical_json_v1(&serde_json::to_value(&record.binding).unwrap());
    assert_eq!(
        record.binding_hash,
        Sha256Digest::from_bytes(&binding_bytes).as_str()
    );

    let by_id = fixture.store.approval(approval_id).unwrap();
    let by_operation = fixture
        .store
        .approval_for_operation(operation.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(by_id, record);
    assert_eq!(by_operation, record);

    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(evidence.events.len(), 3);
    assert!(matches!(
        evidence.events.last().unwrap().payload(),
        StoryEventPayload::ApprovalLifecycle {
            approval_id: event_approval_id,
            state: ApprovalState::Pending,
            reviewer_id_hash: None,
        } if *event_approval_id == approval_id
    ));
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}

#[test]
fn approval_creation_rejects_changed_binding_risk_order_and_session_overrun() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 32);

    let mut changed_actor = approval_binding(&fixture, &operation);
    changed_actor.actor_id = "other-actor".to_owned();
    let error = fixture
        .store
        .create_approval(NewApproval {
            approval_id: ApprovalId::new(),
            operation_id: operation.operation_id,
            binding: changed_actor,
            expires_at: mutation_time(&fixture.story, 120),
            now: mutation_time(&fixture.story, 3),
        })
        .unwrap_err();
    assert!(matches!(error, JournalError::Integrity(_)));

    let mut unsorted = approval_binding(&fixture, &operation);
    unsorted.risk_tags.reverse();
    assert!(matches!(
        fixture.store.create_approval(NewApproval {
            approval_id: ApprovalId::new(),
            operation_id: operation.operation_id,
            binding: unsorted,
            expires_at: mutation_time(&fixture.story, 120),
            now: mutation_time(&fixture.story, 3),
        }),
        Err(JournalError::Integrity(_))
    ));

    let mut changed_proposal = approval_binding(&fixture, &operation);
    changed_proposal.proposal_commitment = Sha256Digest::from_bytes(b"changed-proposal-binding");
    assert!(matches!(
        fixture.store.create_approval(NewApproval {
            approval_id: ApprovalId::new(),
            operation_id: operation.operation_id,
            binding: changed_proposal,
            expires_at: mutation_time(&fixture.story, 120),
            now: mutation_time(&fixture.story, 3),
        }),
        Err(JournalError::Integrity(_))
    ));

    let mut misleading = approval_binding(&fixture, &operation);
    misleading.risk_tags = vec!["email_send".to_owned(), "other_risk".to_owned()];
    assert!(matches!(
        fixture.store.create_approval(NewApproval {
            approval_id: ApprovalId::new(),
            operation_id: operation.operation_id,
            binding: misleading,
            expires_at: mutation_time(&fixture.story, 120),
            now: mutation_time(&fixture.story, 3),
        }),
        Err(JournalError::Integrity(_))
    ));

    assert!(matches!(
        fixture.store.create_approval(NewApproval {
            approval_id: ApprovalId::new(),
            operation_id: operation.operation_id,
            binding: approval_binding(&fixture, &operation),
            expires_at: fixture.story.authority.expires_at + time::Duration::seconds(1),
            now: mutation_time(&fixture.story, 3),
        }),
        Err(JournalError::InvalidTransition { .. })
    ));
    assert!(
        fixture
            .store
            .approval_for_operation(operation.operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        2
    );
}

#[test]
fn reviewer_approval_cas_updates_both_entities_and_hashes_only_reviewer_in_event() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 33);
    let approval_id = ApprovalId::new();
    create_pending(
        &fixture,
        &operation,
        approval_id,
        mutation_time(&fixture.story, 120),
    );
    let reviewer = "reviewer-primary";
    let reason = "approved for the bounded recipient";
    let approved = fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: reviewer.to_owned(),
            reason: reason.to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap();
    assert_eq!(approved.state, ApprovalState::Approved);
    assert_eq!(approved.version, 1);
    assert_eq!(approved.reviewer.as_deref(), Some(reviewer));
    assert_eq!(approved.reason.as_deref(), Some(reason));
    let updated = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(updated.state, OperationState::Approved);
    assert_eq!(updated.version, 2);
    assert_eq!(updated.side_effect_state, SideEffectState::NotAttempted);

    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 4);
    let expected_reviewer_hash = Sha256Digest::from_bytes(reviewer.as_bytes());
    assert!(matches!(
        evidence.events.last().unwrap().payload(),
        StoryEventPayload::ApprovalLifecycle {
            state: ApprovalState::Approved,
            reviewer_id_hash: Some(actual),
            ..
        } if actual == &expected_reviewer_hash
    ));
    let event_json = serde_json::to_string(&evidence.events).unwrap();
    assert!(!event_json.contains(reason));
    assert!(!event_json.contains(PRIVATE_MARKER));

    let stale = fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "reviewer-stale".to_owned(),
            reason: PRIVATE_MARKER.to_owned(),
            decision: ReviewerDecision::Deny,
            now: mutation_time(&fixture.story, 5),
        })
        .unwrap_err();
    assert!(matches!(
        stale,
        JournalError::Conflict {
            entity: "approval",
            expected: 0,
            actual: 1,
            ..
        }
    ));
    assert!(!stale.to_string().contains(PRIVATE_MARKER));
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        4
    );
}

#[test]
fn denial_expiry_and_stale_operation_versions_roll_back_both_entities() {
    let deny_fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let deny_operation = review_operation(&deny_fixture, 34);
    let deny_id = ApprovalId::new();
    create_pending(
        &deny_fixture,
        &deny_operation,
        deny_id,
        mutation_time(&deny_fixture.story, 120),
    );
    let denied = deny_fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id: deny_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "reviewer-deny".to_owned(),
            reason: "recipient remains outside scope".to_owned(),
            decision: ReviewerDecision::Deny,
            now: mutation_time(&deny_fixture.story, 4),
        })
        .unwrap();
    assert_eq!(denied.state, ApprovalState::Denied);
    let denied_operation = deny_fixture
        .store
        .operation(deny_operation.operation_id)
        .unwrap();
    assert_eq!(denied_operation.state, OperationState::DeniedByReviewer);
    assert_eq!(
        denied_operation.side_effect_state,
        SideEffectState::BlockedBeforeExecution
    );

    let stale_fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let stale_operation = review_operation(&stale_fixture, 35);
    let stale_id = ApprovalId::new();
    create_pending(
        &stale_fixture,
        &stale_operation,
        stale_id,
        mutation_time(&stale_fixture.story, 120),
    );
    let stale = stale_fixture
        .store
        .decide_approval(ApprovalDecisionInput {
            approval_id: stale_id,
            expected_version: 0,
            expected_operation_version: 0,
            reviewer: "reviewer".to_owned(),
            reason: "stale operation version".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&stale_fixture.story, 4),
        })
        .unwrap_err();
    assert!(matches!(
        stale,
        JournalError::Conflict {
            entity: "operation",
            expected: 0,
            actual: 1,
            ..
        }
    ));
    assert_eq!(stale_fixture.store.approval(stale_id).unwrap().version, 0);
    assert_eq!(
        stale_fixture
            .store
            .operation(stale_operation.operation_id)
            .unwrap()
            .state,
        OperationState::AwaitingApproval
    );

    let expiry_fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let expiry_operation = review_operation(&expiry_fixture, 36);
    let expiry_id = ApprovalId::new();
    let expires_at = mutation_time(&expiry_fixture.story, 20);
    create_pending(&expiry_fixture, &expiry_operation, expiry_id, expires_at);
    assert!(matches!(
        expiry_fixture.store.expire_approval(ExpireApprovalInput {
            approval_id: expiry_id,
            expected_approval_version: 0,
            expected_operation_version: 1,
            now: expires_at - time::Duration::nanoseconds(1),
        }),
        Err(JournalError::InvalidTransition { .. })
    ));
    assert_eq!(expiry_fixture.store.approval(expiry_id).unwrap().version, 0);
    let expired = expiry_fixture
        .store
        .expire_approval(ExpireApprovalInput {
            approval_id: expiry_id,
            expected_approval_version: 0,
            expected_operation_version: 1,
            now: expires_at,
        })
        .unwrap();
    assert_eq!(expired.state, ApprovalState::Expired);
    assert_eq!(expired.version, 1);
    let expired_operation = expiry_fixture
        .store
        .operation(expiry_operation.operation_id)
        .unwrap();
    assert_eq!(expired_operation.state, OperationState::Expired);
    assert_eq!(
        expired_operation.side_effect_state,
        SideEffectState::BlockedBeforeExecution
    );
}
