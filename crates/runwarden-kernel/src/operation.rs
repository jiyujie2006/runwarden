use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Proposed,
    PolicyEvaluated,
    Denied,
    AwaitingApproval,
    DeniedByReviewer,
    Expired,
    Approved,
    ObservedOnly,
    ExecutionLeased,
    Executing,
    Completed,
    Failed,
    OutcomeUnknown,
}

impl OperationState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        matches!(
            (self, next),
            (Self::Proposed, Self::PolicyEvaluated)
                | (Self::PolicyEvaluated, Self::Denied)
                | (Self::PolicyEvaluated, Self::AwaitingApproval)
                | (Self::PolicyEvaluated, Self::ExecutionLeased)
                | (Self::PolicyEvaluated, Self::ObservedOnly)
                | (Self::AwaitingApproval, Self::DeniedByReviewer)
                | (Self::AwaitingApproval, Self::Expired)
                | (Self::AwaitingApproval, Self::Approved)
                | (Self::Approved, Self::ExecutionLeased)
                | (Self::ExecutionLeased, Self::Executing)
                | (Self::Executing, Self::Completed)
                | (Self::Executing, Self::Failed)
                | (Self::Executing, Self::OutcomeUnknown)
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::DeniedByReviewer
                | Self::Expired
                | Self::Completed
                | Self::Failed
                | Self::ObservedOnly
                | Self::OutcomeUnknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectState {
    NotAttempted,
    BlockedBeforeExecution,
    Simulated,
    Completed,
    FailedBeforeSideEffect,
    ExecutedWithError,
    OutcomeUnknown,
}

impl SideEffectState {
    pub fn was_executed(&self) -> bool {
        matches!(self, Self::Completed | Self::ExecutedWithError)
    }
}
