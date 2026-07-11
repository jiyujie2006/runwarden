mod common;

use std::sync::{Arc, Barrier};

use common::{JournalFixture, PRIVATE_MARKER, mutation_time, operation_fixture};
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, SideEffectState,
};
use runwarden_kernel::story::{EnforcementMode, ObservationId};
use runwarden_state::{JournalError, RecordPolicyInput};
use rusqlite::{Connection, params};

#[test]
fn private_arguments_round_trip_but_never_enter_safe_views_or_evidence() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let outcome = fixture
        .store
        .create_operation(fixture.operation(1, "send"))
        .unwrap();
    assert!(outcome.created);
    assert_eq!(outcome.operation.state, OperationState::Proposed);
    assert_eq!(outcome.operation.version, 0);

    let private = fixture
        .store
        .load_private_operation_material(outcome.operation.operation_id)
        .unwrap();
    assert_eq!(private.arguments["token"], PRIVATE_MARKER);

    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    evidence.verify_structure().unwrap();
    assert_eq!(snapshot.operations.len(), 1);
    assert_eq!(evidence.events.len(), 1);
    assert_eq!(evidence.replay_frames.len(), 1);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}

#[test]
fn invocation_retry_is_idempotent_and_binding_changes_fail_closed() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let first = fixture
        .store
        .create_operation(fixture.operation(2, "send"))
        .unwrap();
    let retry = fixture
        .store
        .create_operation(fixture.operation(2, "send"))
        .unwrap();
    assert!(first.created);
    assert!(!retry.created);
    assert_eq!(retry.operation.operation_id, first.operation.operation_id);
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        1
    );

    let mismatch = fixture
        .store
        .create_operation(fixture.operation(2, "send_changed"))
        .unwrap_err();
    assert!(matches!(mismatch, JournalError::Integrity(_)));
    assert!(!mismatch.to_string().contains(PRIVATE_MARKER));
}

#[test]
fn policy_transition_is_versioned_and_raw_reason_is_not_evidence() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = fixture
        .store
        .create_operation(fixture.operation(3, "send"))
        .unwrap()
        .operation;
    let reason = "raw-policy-reason-secret";
    let updated = fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Denied,
            reason: reason.to_owned(),
            next_state: OperationState::Denied,
            checks: vec![PolicyCheck {
                check_id: "email-recipient".to_owned(),
                layer: "authority".to_owned(),
                status: PolicyCheckStatus::Failed,
                reason: "recipient not authorized".to_owned(),
                observation_ref: Some(ObservationId::new()),
            }],
            now: mutation_time(&fixture.story, 2),
        })
        .unwrap();
    assert_eq!(updated.version, 1);
    assert_eq!(updated.state, OperationState::Denied);
    assert_eq!(
        updated.side_effect_state,
        SideEffectState::BlockedBeforeExecution
    );
    assert_eq!(updated.policy_checks.len(), 1);

    let retry_after_transition = fixture
        .store
        .create_operation(fixture.operation(3, "send"))
        .unwrap();
    assert!(!retry_after_transition.created);
    assert_eq!(
        retry_after_transition.operation.operation_id,
        operation.operation_id
    );
    assert_eq!(
        retry_after_transition.operation.state,
        OperationState::Denied
    );
    assert_eq!(retry_after_transition.operation.version, 1);

    let stale = fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Allowed,
            reason: "stale".to_owned(),
            next_state: OperationState::PolicyEvaluated,
            checks: Vec::new(),
            now: mutation_time(&fixture.story, 3),
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
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 2);
    assert!(!serde_json::to_string(&evidence).unwrap().contains(reason));
    assert_eq!(
        evidence.story.status,
        runwarden_kernel::story::StoryStatus::BlockedBeforeSideEffect
    );
}

#[test]
fn concurrent_identical_invocations_commit_one_operation_event_and_frame() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let state_dir = fixture.state_dir.clone();
        let story = fixture.story.clone();
        handles.push(std::thread::spawn(move || {
            let store = runwarden_state::StateStore::open(state_dir).unwrap();
            let input = operation_fixture(&story, 9, "send");
            barrier.wait();
            store.create_operation(input)
        }));
    }
    barrier.wait();
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.created).count(), 1);
    assert_eq!(
        outcomes[0].operation.operation_id,
        outcomes[1].operation.operation_id
    );
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.story.operations.len(), 1);
    assert_eq!(evidence.events.len(), 1);
    assert_eq!(evidence.replay_frames.len(), 1);
}

#[test]
fn policy_matrix_enforces_enforced_and_monitor_only_semantics() {
    for (mode, decision, next_state, check_status, expected_state, expected_side) in [
        (
            EnforcementMode::Enforced,
            PolicyDecision::Allowed,
            OperationState::PolicyEvaluated,
            PolicyCheckStatus::Passed,
            OperationState::PolicyEvaluated,
            SideEffectState::NotAttempted,
        ),
        (
            EnforcementMode::Enforced,
            PolicyDecision::RequiresReview,
            OperationState::AwaitingApproval,
            PolicyCheckStatus::RequiresReview,
            OperationState::AwaitingApproval,
            SideEffectState::NotAttempted,
        ),
        (
            EnforcementMode::MonitorOnly,
            PolicyDecision::Denied,
            OperationState::PolicyEvaluated,
            PolicyCheckStatus::Failed,
            OperationState::PolicyEvaluated,
            SideEffectState::NotAttempted,
        ),
    ] {
        let fixture = JournalFixture::new(mode);
        let operation = fixture
            .store
            .create_operation(fixture.operation(10, "send"))
            .unwrap()
            .operation;
        let updated = fixture
            .store
            .record_policy(RecordPolicyInput {
                operation_id: operation.operation_id,
                expected_version: 0,
                decision: decision.clone(),
                reason: "matrix decision".to_owned(),
                next_state,
                checks: vec![PolicyCheck {
                    check_id: "matrix-check".to_owned(),
                    layer: "policy".to_owned(),
                    status: check_status,
                    reason: "matrix evidence".to_owned(),
                    observation_ref: None,
                }],
                now: mutation_time(&fixture.story, 2),
            })
            .unwrap();
        assert_eq!(updated.state, expected_state);
        assert_eq!(updated.side_effect_state, expected_side);
        let snapshot = fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap();
        if decision == PolicyDecision::RequiresReview {
            assert_eq!(
                snapshot.status,
                runwarden_kernel::story::StoryStatus::AwaitingApproval
            );
        } else {
            assert_eq!(
                snapshot.status,
                runwarden_kernel::story::StoryStatus::Running
            );
        }
    }
}

#[test]
fn invalid_policy_transition_and_argument_hash_mismatch_roll_back_every_row() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let mut bad_hash = fixture.operation(11, "send");
    bad_hash.argument_hash = runwarden_kernel::trace::Sha256Digest::from_bytes(b"wrong");
    assert!(matches!(
        fixture.store.create_operation(bad_hash),
        Err(JournalError::Integrity(_))
    ));
    assert!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .is_empty()
    );

    let operation = fixture
        .store
        .create_operation(fixture.operation(12, "send"))
        .unwrap()
        .operation;
    assert!(matches!(
        fixture.store.record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Denied,
            reason: "wrong target".to_owned(),
            next_state: OperationState::PolicyEvaluated,
            checks: vec![PolicyCheck {
                check_id: "deny".to_owned(),
                layer: "policy".to_owned(),
                status: PolicyCheckStatus::Failed,
                reason: "denied".to_owned(),
                observation_ref: None,
            }],
            now: mutation_time(&fixture.story, 2),
        }),
        Err(JournalError::InvalidTransition { .. })
    ));
    let unchanged = fixture.store.operation(operation.operation_id).unwrap();
    assert_eq!(unchanged.state, OperationState::Proposed);
    assert_eq!(unchanged.version, 0);
    assert_eq!(
        fixture
            .store
            .story_evidence(fixture.story.story_id)
            .unwrap()
            .events
            .len(),
        1
    );
}

#[test]
fn private_and_evidence_tampering_fail_before_trusted_reads() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = fixture
        .store
        .create_operation(fixture.operation(13, "send"))
        .unwrap()
        .operation;
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE operations SET private_arguments_json = ?1 WHERE operation_id = ?2",
            params![
                br#"{"token":"changed"}"#.as_slice(),
                operation.operation_id.to_string()
            ],
        )
        .unwrap();
    assert!(matches!(
        fixture
            .store
            .load_private_operation_material(operation.operation_id),
        Err(JournalError::Integrity(_))
    ));

    connection
        .execute(
            "UPDATE events SET redacted_payload_json = '{}' WHERE story_id = ?1 AND sequence = 1",
            params![fixture.story.story_id.to_string()],
        )
        .unwrap();
    // The display snapshot intentionally reads only safe scalars and the
    // final frame; full evidence reads must detect payload-chain tampering.
    assert!(fixture.store.story_snapshot(fixture.story.story_id).is_ok());
    assert!(matches!(
        fixture.store.story_evidence(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture.store.operation(operation.operation_id),
        Err(JournalError::Integrity(_))
    ));
}
