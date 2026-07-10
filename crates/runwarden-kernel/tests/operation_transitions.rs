use runwarden_kernel::operation::{OperationState, SideEffectState};

#[test]
fn operation_state_machine_accepts_only_documented_edges() {
    assert!(OperationState::Proposed.can_transition_to(&OperationState::PolicyEvaluated));
    assert!(OperationState::PolicyEvaluated.can_transition_to(&OperationState::Denied));
    assert!(OperationState::AwaitingApproval.can_transition_to(&OperationState::Approved));
    assert!(OperationState::Executing.can_transition_to(&OperationState::OutcomeUnknown));
    assert!(!OperationState::Denied.can_transition_to(&OperationState::Executing));
    assert!(!OperationState::Completed.can_transition_to(&OperationState::Proposed));
}

#[test]
fn side_effect_execution_semantics_are_unambiguous() {
    assert!(SideEffectState::Completed.was_executed());
    assert!(SideEffectState::ExecutedWithError.was_executed());
    for state in [
        SideEffectState::NotAttempted,
        SideEffectState::BlockedBeforeExecution,
        SideEffectState::Simulated,
        SideEffectState::FailedBeforeSideEffect,
        SideEffectState::OutcomeUnknown,
    ] {
        assert!(!state.was_executed());
    }
}

#[test]
fn operation_state_machine_matches_the_complete_transition_contract() {
    let states = [
        OperationState::Proposed,
        OperationState::PolicyEvaluated,
        OperationState::Denied,
        OperationState::AwaitingApproval,
        OperationState::DeniedByReviewer,
        OperationState::Expired,
        OperationState::Approved,
        OperationState::ObservedOnly,
        OperationState::ExecutionLeased,
        OperationState::Executing,
        OperationState::Completed,
        OperationState::Failed,
        OperationState::OutcomeUnknown,
    ];
    let allowed = [
        (OperationState::Proposed, OperationState::PolicyEvaluated),
        (OperationState::PolicyEvaluated, OperationState::Denied),
        (
            OperationState::PolicyEvaluated,
            OperationState::AwaitingApproval,
        ),
        (
            OperationState::PolicyEvaluated,
            OperationState::ExecutionLeased,
        ),
        (
            OperationState::PolicyEvaluated,
            OperationState::ObservedOnly,
        ),
        (
            OperationState::AwaitingApproval,
            OperationState::DeniedByReviewer,
        ),
        (OperationState::AwaitingApproval, OperationState::Expired),
        (OperationState::AwaitingApproval, OperationState::Approved),
        (OperationState::Approved, OperationState::ExecutionLeased),
        (OperationState::ExecutionLeased, OperationState::Executing),
        (OperationState::Executing, OperationState::Completed),
        (OperationState::Executing, OperationState::Failed),
        (OperationState::Executing, OperationState::OutcomeUnknown),
    ];

    for current in states {
        for next in states {
            assert_eq!(
                current.can_transition_to(&next),
                allowed.contains(&(current, next)),
                "unexpected transition result for {current:?} -> {next:?}"
            );
        }
    }
}

#[test]
fn operation_terminal_states_are_frozen() {
    for state in [
        OperationState::Denied,
        OperationState::DeniedByReviewer,
        OperationState::Expired,
        OperationState::ObservedOnly,
        OperationState::Completed,
        OperationState::Failed,
        OperationState::OutcomeUnknown,
    ] {
        assert!(state.is_terminal(), "{state:?} must be terminal");
    }

    for state in [
        OperationState::Proposed,
        OperationState::PolicyEvaluated,
        OperationState::AwaitingApproval,
        OperationState::Approved,
        OperationState::ExecutionLeased,
        OperationState::Executing,
    ] {
        assert!(!state.is_terminal(), "{state:?} must not be terminal");
    }
}

#[test]
fn operation_and_side_effect_states_use_snake_case() {
    assert_eq!(
        serde_json::to_value(OperationState::DeniedByReviewer).unwrap(),
        "denied_by_reviewer"
    );
    assert_eq!(
        serde_json::to_value(SideEffectState::FailedBeforeSideEffect).unwrap(),
        "failed_before_side_effect"
    );
}
