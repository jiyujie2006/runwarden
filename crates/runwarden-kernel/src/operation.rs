use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::WorkspaceRelativePath;
use crate::authority::ApprovalState;
use crate::resource::ResourceClaim;
use crate::story::{ApprovalId, ExecutionLeaseId, ObservationId, OperationId, SessionId, StoryId};
use crate::trace::Sha256Digest;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckStatus {
    Passed,
    Failed,
    RequiresReview,
    NotEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheck {
    pub check_id: String,
    pub layer: String,
    pub status: PolicyCheckStatus,
    pub reason: String,
    pub observation_ref: Option<ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalView {
    pub approval_id: ApprovalId,
    pub state: ApprovalState,
    pub binding_digest: String,
    pub reviewer: Option<String>,
    pub reason: Option<String>,
    pub expires_at: Option<String>,
    pub lease_id: Option<ExecutionLeaseId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeArgumentView {
    File {
        path: WorkspaceRelativePath,
        content_hash: Option<Sha256Digest>,
    },
    Email {
        recipients: Vec<String>,
        subject_hash: Sha256Digest,
        body_hash: Sha256Digest,
    },
    Network {
        method: String,
        origin: String,
        body_hash: Option<Sha256Digest>,
    },
    Store {
        namespace: String,
        key_hash: Sha256Digest,
        value_hash: Option<Sha256Digest>,
    },
    Input {
        source: String,
        content_hash: Sha256Digest,
    },
    Code {
        runtime: String,
        script_hash: Sha256Digest,
    },
    Evidence {
        story_id: StoryId,
        operation_id: OperationId,
    },
    Artifact {
        relative_path: WorkspaceRelativePath,
        format: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeProviderOutput {
    File {
        bytes: u64,
        content_hash: Sha256Digest,
    },
    Email {
        receipt_hash: Sha256Digest,
    },
    Network {
        status_code: u16,
        response_hash: Sha256Digest,
        bytes: u64,
    },
    Store {
        key_hash: Sha256Digest,
        version: u64,
    },
    Input {
        content_hash: Sha256Digest,
        risk_codes: Vec<String>,
    },
    Code {
        exit_code: Option<i32>,
        stdout_hash: Sha256Digest,
        stderr_hash: Sha256Digest,
        output_bytes: u64,
        truncated: bool,
    },
    ExternalMcp {
        output_hash: Sha256Digest,
        bytes: u64,
    },
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderResultView {
    pub execution_status: ProviderExecutionStatus,
    pub output: SafeProviderOutput,
    pub output_hash: Option<Sha256Digest>,
    pub error_kind: Option<String>,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExecutionStatus {
    NotExecuted,
    Running,
    Completed,
    FailedBeforeSideEffect,
    ExecutedWithError,
    OutcomeUnknown,
    Simulated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityOperation {
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub parent_model_call_id: Option<String>,
    pub proposed_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub resource_claim: ResourceClaim,
    pub argument_hash: Sha256Digest,
    pub arguments: SafeArgumentView,
    pub policy_snapshot_hash: Sha256Digest,
    pub state: OperationState,
    pub version: u64,
    pub policy_checks: Vec<PolicyCheck>,
    pub approval: Option<ApprovalView>,
    pub provider_result: Option<ProviderResultView>,
    pub side_effect_state: SideEffectState,
    pub observation_refs: Vec<ObservationId>,
}
