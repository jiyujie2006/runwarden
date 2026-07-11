mod common;

use std::sync::{Arc, Barrier};

use common::{JournalFixture, PRIVATE_MARKER, mutation_time, operation_fixture};
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::{
    OperationState, PolicyCheck, PolicyCheckStatus, SideEffectState,
};
use runwarden_kernel::story::{
    EnforcementMode, EvidenceStatus, InvocationKey, ObservationId, StoryReplayFrame,
};
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
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
    assert!(matches!(
        mismatch,
        JournalError::InvocationConflict { operation_id }
            if operation_id == first.operation.operation_id
    ));
    assert!(!mismatch.to_string().contains(PRIVATE_MARKER));
}

#[test]
fn proposal_components_are_frozen_at_creation_and_policy_evaluation() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);

    let mut changed_contract = fixture.operation(4, "send");
    changed_contract.provider_contract_hash = Sha256Digest::from_bytes(b"changed-contract");
    assert!(matches!(
        fixture.store.create_operation(changed_contract),
        Err(JournalError::Integrity(_))
    ));

    let mut changed_charge = fixture.operation(5, "send");
    changed_charge.budget_charge.calls = 2;
    assert!(matches!(
        fixture.store.create_operation(changed_charge),
        Err(JournalError::Integrity(_))
    ));

    let mut changed_commitment = fixture.operation(6, "send");
    changed_commitment.proposal_commitment = Sha256Digest::from_bytes(b"changed-proposal");
    assert!(matches!(
        fixture.store.create_operation(changed_commitment),
        Err(JournalError::Integrity(_))
    ));

    let operation = fixture
        .store
        .create_operation(fixture.operation(7, "send"))
        .unwrap()
        .operation;
    assert!(matches!(
        fixture.store.record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Allowed,
            reason: "drifted policy proposal".to_owned(),
            next_state: OperationState::PolicyEvaluated,
            checks: vec![PolicyCheck {
                check_id: "proposal-binding".to_owned(),
                layer: "kernel".to_owned(),
                status: PolicyCheckStatus::Passed,
                reason: "must bind the exact proposal".to_owned(),
                observation_ref: None,
            }],
            proposal_commitment: Sha256Digest::from_bytes(b"different-policy-proposal"),
            now: mutation_time(&fixture.story, 2),
        }),
        Err(JournalError::Integrity(_))
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
fn stored_frozen_proposal_fields_are_immutable_and_tamper_evident() {
    let cases = [
        (
            "proposal_commitment",
            Sha256Digest::from_bytes(b"tampered-proposal")
                .as_str()
                .to_owned(),
        ),
        (
            "provider_contract_hash",
            Sha256Digest::from_bytes(b"tampered-contract")
                .as_str()
                .to_owned(),
        ),
        (
            "proposed_budget_charge_json",
            r#"{"calls":2,"file_bytes":0,"network_bytes":0}"#.to_owned(),
        ),
    ];

    for (index, (column, value)) in cases.into_iter().enumerate() {
        let fixture = JournalFixture::new(EnforcementMode::Enforced);
        let suffix = u8::try_from(20 + index).unwrap();
        let operation = fixture
            .store
            .create_operation(fixture.operation(suffix, "send"))
            .unwrap()
            .operation;
        let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
        let statement = format!("UPDATE operations SET {column} = ?1 WHERE operation_id = ?2");
        assert!(
            connection
                .execute(
                    &statement,
                    params![value, operation.operation_id.to_string()]
                )
                .is_err()
        );

        connection
            .execute_batch("DROP TRIGGER operations_invocation_binding_immutable")
            .unwrap();
        connection
            .execute(
                &statement,
                params![value, operation.operation_id.to_string()],
            )
            .unwrap();
        assert!(matches!(
            fixture
                .store
                .operation_runtime_snapshot(operation.operation_id),
            Err(JournalError::Integrity(_))
        ));
    }
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
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
                .proposal_commitment,
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
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
                .proposal_commitment,
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
                proposal_commitment: common::frozen_proposal(
                    &fixture.store,
                    operation.operation_id,
                )
                .proposal_commitment,
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
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id,)
                .proposal_commitment,
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

#[test]
fn a_denied_operation_does_not_finalize_a_multi_operation_story() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let first = fixture
        .store
        .create_operation(fixture.operation(30, "send_denied"))
        .unwrap()
        .operation;
    fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: first.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Denied,
            reason: "first action denied".to_owned(),
            next_state: OperationState::Denied,
            checks: vec![PolicyCheck {
                check_id: "deny-first".to_owned(),
                layer: "policy".to_owned(),
                status: PolicyCheckStatus::Failed,
                reason: "denied".to_owned(),
                observation_ref: None,
            }],
            proposal_commitment: common::frozen_proposal(&fixture.store, first.operation_id)
                .proposal_commitment,
            now: mutation_time(&fixture.story, 2),
        })
        .unwrap();
    assert_eq!(
        fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap()
            .status,
        runwarden_kernel::story::StoryStatus::BlockedBeforeSideEffect
    );

    let mut second_input = fixture.operation(31, "send_next");
    second_input.now = mutation_time(&fixture.story, 3);
    let second = fixture.store.create_operation(second_input).unwrap();
    assert!(second.created);
    let snapshot = fixture
        .store
        .story_snapshot(fixture.story.story_id)
        .unwrap();
    assert_eq!(snapshot.operations.len(), 2);
    assert_eq!(
        snapshot.status,
        runwarden_kernel::story::StoryStatus::Running
    );
}

#[test]
fn stored_story_version_tampering_blocks_reads_and_the_next_append() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    fixture
        .store
        .create_operation(fixture.operation(32, "send"))
        .unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            "UPDATE stories SET version = 99 WHERE story_id = ?1",
            params![fixture.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.story_snapshot(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture.store.story_evidence(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture
            .store
            .create_operation(fixture.operation(33, "send_after_tamper")),
        Err(JournalError::Integrity(_))
    ));
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM operations WHERE story_id = ?1",
            params![fixture.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn invocation_key_is_immutable_and_bound_without_entering_safe_output() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    fixture
        .store
        .create_operation(fixture.operation(40, "send"))
        .unwrap();
    let safe = serde_json::to_string(
        &fixture
            .store
            .story_snapshot(fixture.story.story_id)
            .unwrap(),
    )
    .unwrap();
    assert!(!safe.contains("inv_"));

    let changed_key = InvocationKey::from_hmac_bytes([41; 32]);
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE operations SET invocation_key = ?1 WHERE story_id = ?2",
                params![changed_key.as_str(), fixture.story.story_id.to_string()],
            )
            .is_err()
    );

    // Simulate lower-level schema tampering: even if the immutable trigger is
    // removed, the hidden binding hash prevents a substituted valid key from
    // becoming a second durable invocation.
    connection
        .execute_batch("DROP TRIGGER operations_invocation_binding_immutable")
        .unwrap();
    connection
        .execute(
            "UPDATE operations SET invocation_key = ?1 WHERE story_id = ?2",
            params![changed_key.as_str(), fixture.story.story_id.to_string()],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.story_evidence(fixture.story.story_id),
        Err(JournalError::Integrity(_))
    ));
    assert!(matches!(
        fixture
            .store
            .create_operation(fixture.operation(40, "send")),
        Err(JournalError::Integrity(_))
    ));
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM operations WHERE story_id = ?1",
            params![fixture.story.story_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn two_invocations_reusing_one_operation_id_return_a_structured_conflict() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let shared_operation_id = runwarden_kernel::story::OperationId::new();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for suffix in [50, 51] {
        let barrier = Arc::clone(&barrier);
        let state_dir = fixture.state_dir.clone();
        let story = fixture.story.clone();
        handles.push(std::thread::spawn(move || {
            let store = runwarden_state::StateStore::open(state_dir).unwrap();
            let mut input = operation_fixture(&story, suffix, "send");
            input.operation_id = shared_operation_id;
            barrier.wait();
            store.create_operation(input)
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
                    entity: "operation",
                    ..
                })
            ))
            .count(),
        1
    );
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    assert_eq!(evidence.story.operations.len(), 1);
    assert_eq!(evidence.events.len(), 1);
}

#[test]
fn a_finalized_verified_story_rejects_post_verification_operations() {
    let fixture = JournalFixture::new(EnforcementMode::Enforced);
    let operation = fixture
        .store
        .create_operation(fixture.operation(70, "send"))
        .unwrap()
        .operation;
    fixture
        .store
        .record_policy(RecordPolicyInput {
            operation_id: operation.operation_id,
            expected_version: 0,
            decision: PolicyDecision::Denied,
            reason: "finalized denial".to_owned(),
            next_state: OperationState::Denied,
            checks: vec![PolicyCheck {
                check_id: "final-deny".to_owned(),
                layer: "policy".to_owned(),
                status: PolicyCheckStatus::Failed,
                reason: "denied".to_owned(),
                observation_ref: None,
            }],
            proposal_commitment: common::frozen_proposal(&fixture.store, operation.operation_id)
                .proposal_commitment,
            now: mutation_time(&fixture.story, 2),
        })
        .unwrap();
    let evidence = fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap();
    let old_frame = evidence.replay_frames.last().unwrap();
    let mut finalized_story = evidence.story;
    finalized_story.evidence_status = EvidenceStatus::Verified;
    let finalized_frame = StoryReplayFrame::seal(
        old_frame.sequence,
        old_frame.story_version,
        old_frame.event_hash.clone(),
        old_frame.previous_frame_hash.clone(),
        old_frame.recorded_at,
        finalized_story.clone(),
    )
    .unwrap();
    let finalized_json = String::from_utf8(canonical_json_v1(
        &serde_json::to_value(&finalized_story).unwrap(),
    ))
    .unwrap();
    let connection = Connection::open(fixture.state_dir.join("runwarden.db")).unwrap();
    connection
        .execute(
            r#"UPDATE story_frames
               SET snapshot_hash = ?1, frame_hash = ?2, safe_story_json = ?3
               WHERE story_id = ?4 AND sequence = ?5"#,
            params![
                finalized_frame.snapshot_hash,
                finalized_frame.frame_hash,
                finalized_json,
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
            params![finalized_json, fixture.story.story_id.to_string()],
        )
        .unwrap();
    fixture
        .store
        .story_evidence(fixture.story.story_id)
        .unwrap()
        .verify_structure()
        .unwrap();

    let mut next = fixture.operation(71, "send_after_finalization");
    next.now = mutation_time(&fixture.story, 3);
    assert!(matches!(
        fixture.store.create_operation(next),
        Err(JournalError::InvalidTransition {
            entity: "story",
            ..
        })
    ));
}
