mod common;

use common::{JournalFixture, PRIVATE_MARKER, mutation_time};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, SecurityOperation, SideEffectState,
};
use runwarden_kernel::story::{ApprovalId, SecurityStory, SessionId, StoryId};
use runwarden_kernel::trace::{Sha256Digest, StoryEventPayload, canonical_json_v1};
use runwarden_state::{
    ApprovalDecisionInput, DemoActivation, DurableApprovalBinding, ExpireApprovalInput,
    JournalError, NewApproval, OneShotConsumption, RecordPolicyInput, ReviewerDecision,
    SessionRecord,
};
use rusqlite::{Connection, params};
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

fn activate_story(fixture: &JournalFixture, story: &SecurityStory, label: &str) {
    fixture
        .store
        .activate_demo(&DemoActivation {
            instance_id: format!("reviewer-instance-{label}"),
            story_id: story.story_id,
            session_id: story.authority.session_id,
            process_id: std::process::id(),
            host_id: "reviewer-test-host".to_owned(),
            instance_token_hash: Sha256Digest::from_bytes(b"reviewer-test-token")
                .as_str()
                .to_owned(),
            now: mutation_time(story, 3),
        })
        .unwrap();
}

fn create_other_story(fixture: &JournalFixture) -> SecurityStory {
    let mut story = fixture.story.clone();
    story.story_id = StoryId::new();
    story.title = "Other reviewer story".to_owned();
    story.scenario_id = "other-reviewer-story".to_owned();
    story.authority.session_id = SessionId::new();
    story.authority.actor_id = "other-reviewer-actor".to_owned();
    story.authority.authz_id = "other-reviewer-authz".to_owned();
    story.identity.actor_id = story.authority.actor_id.clone();
    fixture.store.create_story(&story).unwrap();
    fixture
        .store
        .create_session(&SessionRecord {
            session_id: story.authority.session_id,
            story_id: story.story_id,
            authority: story.authority.clone(),
            policy_snapshot_hash: story.authority.policy_snapshot_hash.clone(),
            expires_at: story.authority.expires_at,
        })
        .unwrap();
    story
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
fn active_reviewer_approval_succeeds_for_the_current_story_and_session() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 70);
    let approval_id = ApprovalId::new();
    create_pending(
        &fixture,
        &operation,
        approval_id,
        mutation_time(&fixture.story, 120),
    );
    activate_story(&fixture, &fixture.story, "current");

    let outcome = fixture
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "active-reviewer".to_owned(),
            reason: "approved in the active reviewer context".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap();

    assert_eq!(outcome.approval.state, ApprovalState::Approved);
    assert_eq!(outcome.approval.version, 1);
    assert_eq!(outcome.operation.operation_id, operation.operation_id);
    assert_eq!(outcome.operation.state, OperationState::Approved);
    assert_eq!(outcome.operation.version, 2);
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 4);
    assert!(matches!(
        evidence.events.last().unwrap().payload(),
        StoryEventPayload::ApprovalLifecycle {
            approval_id: event_approval_id,
            state: ApprovalState::Approved,
            ..
        } if *event_approval_id == approval_id
    ));
}

#[test]
fn active_reviewer_approval_without_an_active_story_changes_nothing() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 71);
    let approval_id = ApprovalId::new();
    create_pending(
        &fixture,
        &operation,
        approval_id,
        mutation_time(&fixture.story, 120),
    );
    let approval_before = fixture.store.approval(approval_id).unwrap();
    let operation_before = fixture.store.operation(operation.operation_id).unwrap();
    let event_count_before = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .events
        .len();

    let error = fixture
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "inactive-reviewer".to_owned(),
            reason: "there is no active reviewer context".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap_err();

    assert!(matches!(
        error,
        JournalError::InvalidTransition {
            entity: "active_story",
            ..
        }
    ));
    let unknown_error = fixture
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id: ApprovalId::new(),
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "unknown-inactive-reviewer".to_owned(),
            reason: "absence of an active story precedes approval lookup".to_owned(),
            decision: ReviewerDecision::Deny,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap_err();
    assert!(matches!(
        unknown_error,
        JournalError::InvalidTransition {
            entity: "active_story",
            ..
        }
    ));
    assert_eq!(
        fixture.store.approval(approval_id).unwrap(),
        approval_before
    );
    assert_eq!(
        fixture.store.operation(operation.operation_id).unwrap(),
        operation_before
    );
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        event_count_before
    );
}

#[test]
fn active_reviewer_approval_hides_an_approval_from_another_story() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 72);
    let approval_id = ApprovalId::new();
    create_pending(
        &fixture,
        &operation,
        approval_id,
        mutation_time(&fixture.story, 120),
    );
    let approval_before = fixture.store.approval(approval_id).unwrap();
    let mut corrupted_binding = approval_before.binding.clone();
    corrupted_binding.actor_id = "corrupted-cross-story-actor".to_owned();
    let binding_json = String::from_utf8(canonical_json_v1(
        &serde_json::to_value(&corrupted_binding).unwrap(),
    ))
    .unwrap();
    let binding_hash = Sha256Digest::from_bytes(binding_json.as_bytes())
        .as_str()
        .to_owned();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            r#"UPDATE approvals
               SET binding_json = ?1, binding_hash = ?2
               WHERE approval_id = ?3"#,
            params![binding_json, binding_hash, approval_id.to_string()],
        )
        .unwrap();
    let approval_row_before: (String, i64, String, String) = connection
        .query_row(
            r#"SELECT state, version, binding_json, binding_hash
               FROM approvals WHERE approval_id = ?1"#,
            params![approval_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let operation_row_before: (String, i64, String) = connection
        .query_row(
            r#"SELECT state, version, side_effect_state
               FROM operations WHERE operation_id = ?1"#,
            params![operation.operation_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let chain_counts_before: (i64, i64) = connection
        .query_row(
            r#"SELECT
                 (SELECT count(*) FROM events WHERE story_id = ?1),
                 (SELECT count(*) FROM story_frames WHERE story_id = ?1)"#,
            params![fixture.story.story_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let other_story = create_other_story(&fixture);
    activate_story(&fixture, &other_story, "other");

    let error = fixture
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "cross-story-reviewer".to_owned(),
            reason: "must not decide an approval from another story".to_owned(),
            decision: ReviewerDecision::Deny,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap_err();

    assert!(matches!(
        error,
        JournalError::NotFound {
            entity: "approval",
            id,
        } if id == approval_id.to_string()
    ));
    assert_eq!(
        connection
            .query_row(
                r#"SELECT state, version, binding_json, binding_hash
                   FROM approvals WHERE approval_id = ?1"#,
                params![approval_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap(),
        approval_row_before
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT state, version, side_effect_state
                   FROM operations WHERE operation_id = ?1"#,
                params![operation.operation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap(),
        operation_row_before
    );
    assert_eq!(
        connection
            .query_row(
                r#"SELECT
                     (SELECT count(*) FROM events WHERE story_id = ?1),
                     (SELECT count(*) FROM story_frames WHERE story_id = ?1)"#,
                params![fixture.story.story_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap(),
        chain_counts_before
    );
}

#[test]
fn active_reviewer_approval_rejects_tampered_active_instance_integrity() {
    let fixture = JournalFixture::new(runwarden_kernel::story::EnforcementMode::Enforced);
    let operation = review_operation(&fixture, 73);
    let approval_id = ApprovalId::new();
    create_pending(
        &fixture,
        &operation,
        approval_id,
        mutation_time(&fixture.story, 120),
    );
    activate_story(&fixture, &fixture.story, "tamper");
    let approval_before = fixture.store.approval(approval_id).unwrap();
    let operation_before = fixture.store.operation(operation.operation_id).unwrap();
    let event_count_before = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .events
        .len();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();

    connection
        .execute(
            "UPDATE active_instances SET instance_token_hash = 'not-a-digest' WHERE singleton = 1",
            [],
        )
        .unwrap();
    let invalid_token = fixture
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "metadata-reviewer".to_owned(),
            reason: "active metadata must remain valid".to_owned(),
            decision: ReviewerDecision::Approve,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap_err();
    assert!(matches!(invalid_token, JournalError::Integrity(_)));

    connection
        .execute(
            r#"UPDATE active_instances
               SET instance_token_hash = ?1, host_id = ''
               WHERE singleton = 1"#,
            params![
                Sha256Digest::from_bytes(b"reviewer-test-token")
                    .as_str()
                    .to_owned()
            ],
        )
        .unwrap();
    let invalid_host = fixture
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: 0,
            expected_operation_version: 1,
            reviewer: "host-reviewer".to_owned(),
            reason: "invalid active host metadata must fail closed".to_owned(),
            decision: ReviewerDecision::Deny,
            now: mutation_time(&fixture.story, 4),
        })
        .unwrap_err();
    assert!(matches!(invalid_host, JournalError::Integrity(_)));

    assert_eq!(
        fixture.store.approval(approval_id).unwrap(),
        approval_before
    );
    assert_eq!(
        fixture.store.operation(operation.operation_id).unwrap(),
        operation_before
    );
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        event_count_before
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
