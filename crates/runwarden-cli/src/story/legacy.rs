use anyhow::{Context, Result};
use runwarden_kernel::operation::{
    OperationState, ProviderExecutionStatus, ProviderResultView, SafeArgumentView,
    SafeProviderOutput, SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::session::AuthoritySnapshot;
use runwarden_kernel::story::{
    EnforcementMode, EvidenceStatus, OperationId, RunMode, SchemaVersion, SecurityStory, SessionId,
    StageStatus, StoryId, StoryIdentity, StoryProvenance, StoryStage, StoryStageStatus,
    StoryStatus,
};
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use serde_json::Value;

const REDACTED_PROVIDER: &str = "legacy.redacted_provider";
const REDACTED_ACTION: &str = "redacted_action";
const REDACTED_ARGUMENT_SOURCE: &str = "legacy_redacted_arguments";
const REDACTED_RESOURCE_SUMMARY: &str = "legacy resource details redacted";

pub struct LegacyStoryContext {
    pub title: String,
    pub scenario_id: String,
    pub attack_category: String,
    pub safe_attack_preview: String,
    pub attack_content_hash: String,
    pub authority: AuthoritySnapshot,
}

pub fn adapt_legacy_webui(input: &Value, context: LegacyStoryContext) -> Result<SecurityStory> {
    let calls = input
        .get("provider_calls")
        .and_then(Value::as_array)
        .context("legacy webui provider_calls must be an array")?;
    let policy_snapshot_hash =
        Sha256Digest::try_from(context.authority.policy_snapshot_hash.clone())
            .map_err(anyhow::Error::msg)
            .context("legacy authority policy_snapshot_hash must be a SHA-256 digest")?;
    let attack_content_hash = Sha256Digest::try_from(context.attack_content_hash)
        .map_err(anyhow::Error::msg)
        .context("legacy attack_content_hash must be a SHA-256 digest")?;
    let story_id = StoryId::new();
    let session_id = context.authority.session_id;
    let operations = calls
        .iter()
        .map(|call| adapt_operation(story_id, session_id, &policy_snapshot_hash, call))
        .collect::<Result<Vec<_>>>()?;
    let status = derive_story_status(&operations);
    let identity = legacy_identity(&context.authority);
    let stage_statuses = legacy_stage_statuses(&operations);
    let final_outcome_summary = legacy_outcome_summary(status);

    Ok(SecurityStory {
        schema_version: SchemaVersion::current(),
        story_id,
        title: context.title,
        scenario_id: context.scenario_id,
        attack_category: context.attack_category,
        run_mode: RunMode::Recorded,
        enforcement_mode: EnforcementMode::Enforced,
        provenance: StoryProvenance::LegacyDerived,
        status,
        evidence_status: EvidenceStatus::Incomplete,
        identity,
        authority: context.authority,
        safe_attack_preview: context.safe_attack_preview,
        attack_content_hash: attack_content_hash.as_str().to_string(),
        stage_statuses,
        operations,
        event_count: 0,
        report_claims: Vec::new(),
        final_outcome_summary,
        final_event_hash: None,
    })
}

fn adapt_operation(
    story_id: StoryId,
    session_id: SessionId,
    policy_snapshot_hash: &Sha256Digest,
    call: &Value,
) -> Result<SecurityOperation> {
    let call = call
        .as_object()
        .context("legacy provider call must be an object")?;
    let decision = call
        .get("decision")
        .and_then(Value::as_str)
        .context("legacy provider call decision must be a string")?;
    let execution_status = call
        .get("execution_status")
        .and_then(Value::as_str)
        .context("legacy provider call execution_status must be a string")?;
    let side_effect_executed = call
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .context("legacy provider call side_effect_executed must be a boolean")?;
    let arguments = call
        .get("arguments")
        .context("legacy provider call arguments are required")?;
    let argument_hash = hash_value(arguments);
    let output_hash = call
        .get("output")
        .map(hash_value)
        .unwrap_or_else(|| hash_value(&Value::Null));
    let (provider, action) = safe_provider_action(
        call.get("provider").and_then(Value::as_str),
        call.get("action").and_then(Value::as_str),
    );
    let disposition = legacy_disposition(decision, execution_status, side_effect_executed);

    Ok(SecurityOperation {
        operation_id: OperationId::new(),
        story_id,
        session_id,
        parent_model_call_id: None,
        proposed_tool_call_id: None,
        provider: provider.to_string(),
        action: action.to_string(),
        resource_claim: ResourceClaim::OpaqueLegacy {
            provider: provider.to_string(),
            redacted_summary: REDACTED_RESOURCE_SUMMARY.to_string(),
        },
        argument_hash: argument_hash.clone(),
        arguments: SafeArgumentView::Input {
            source: REDACTED_ARGUMENT_SOURCE.to_string(),
            content_hash: argument_hash,
        },
        policy_snapshot_hash: policy_snapshot_hash.clone(),
        state: disposition.operation_state,
        version: 1,
        policy_checks: Vec::new(),
        approval: None,
        provider_result: Some(ProviderResultView {
            execution_status: disposition.provider_status,
            output: SafeProviderOutput::None,
            output_hash: Some(output_hash),
            error_kind: disposition.error_kind.map(ToString::to_string),
            reason_code: Some(disposition.reason_code.to_string()),
        }),
        side_effect_state: disposition.side_effect_state,
        observation_refs: Vec::new(),
    })
}

#[derive(Clone, Copy)]
struct LegacyDisposition {
    operation_state: OperationState,
    side_effect_state: SideEffectState,
    provider_status: ProviderExecutionStatus,
    error_kind: Option<&'static str>,
    reason_code: &'static str,
}

fn legacy_disposition(
    decision: &str,
    execution_status: &str,
    side_effect_executed: bool,
) -> LegacyDisposition {
    match (decision, execution_status, side_effect_executed) {
        ("denied", "not_executed", false) => LegacyDisposition {
            operation_state: OperationState::Denied,
            side_effect_state: SideEffectState::BlockedBeforeExecution,
            provider_status: ProviderExecutionStatus::NotExecuted,
            error_kind: Some("legacy_policy_denied"),
            reason_code: "legacy_denied",
        },
        ("requires_review", "not_executed", false) => LegacyDisposition {
            operation_state: OperationState::AwaitingApproval,
            side_effect_state: SideEffectState::NotAttempted,
            provider_status: ProviderExecutionStatus::NotExecuted,
            error_kind: None,
            reason_code: "legacy_requires_review",
        },
        ("allowed", "completed", false) => LegacyDisposition {
            operation_state: OperationState::ObservedOnly,
            side_effect_state: SideEffectState::NotAttempted,
            provider_status: ProviderExecutionStatus::Completed,
            error_kind: None,
            reason_code: "legacy_observed_without_side_effect",
        },
        ("allowed", "simulated", false) => LegacyDisposition {
            operation_state: OperationState::ObservedOnly,
            side_effect_state: SideEffectState::Simulated,
            provider_status: ProviderExecutionStatus::Simulated,
            error_kind: None,
            reason_code: "legacy_simulated",
        },
        ("allowed", "completed", true) => LegacyDisposition {
            operation_state: OperationState::Completed,
            side_effect_state: SideEffectState::Completed,
            provider_status: ProviderExecutionStatus::Completed,
            error_kind: None,
            reason_code: "legacy_completed_with_side_effect",
        },
        ("allowed", "failed", false) => LegacyDisposition {
            operation_state: OperationState::Failed,
            side_effect_state: SideEffectState::FailedBeforeSideEffect,
            provider_status: ProviderExecutionStatus::FailedBeforeSideEffect,
            error_kind: Some("legacy_execution_failed"),
            reason_code: "legacy_failed_before_side_effect",
        },
        ("allowed", "executed_with_error", true) => LegacyDisposition {
            operation_state: OperationState::Failed,
            side_effect_state: SideEffectState::ExecutedWithError,
            provider_status: ProviderExecutionStatus::ExecutedWithError,
            error_kind: Some("legacy_execution_error"),
            reason_code: "legacy_executed_with_error",
        },
        _ => LegacyDisposition {
            operation_state: OperationState::OutcomeUnknown,
            side_effect_state: SideEffectState::OutcomeUnknown,
            provider_status: ProviderExecutionStatus::OutcomeUnknown,
            error_kind: Some("legacy_outcome_contradiction"),
            reason_code: "legacy_outcome_unknown",
        },
    }
}

fn safe_provider_action(
    provider: Option<&str>,
    action: Option<&str>,
) -> (&'static str, &'static str) {
    match (provider, action) {
        (Some("runwarden.input.inspect"), Some("inspect")) => {
            ("runwarden.input.inspect", "inspect")
        }
        (Some("external.mcp.browser.open_page"), Some("open_page")) => {
            ("external.mcp.browser.open_page", "open_page")
        }
        (Some("external.api.request"), Some("request")) => ("external.api.request", "request"),
        (Some("external.knowledge.write"), Some("write")) => ("external.knowledge.write", "write"),
        (Some("external.memory.write"), Some("write")) => ("external.memory.write", "write"),
        (Some("external.mcp.filesystem.read_file"), Some("read_file")) => {
            ("external.mcp.filesystem.read_file", "read_file")
        }
        (Some("external.email.send"), Some("send")) => ("external.email.send", "send"),
        _ => (REDACTED_PROVIDER, REDACTED_ACTION),
    }
}

fn hash_value(value: &Value) -> Sha256Digest {
    Sha256Digest::from_bytes(&canonical_json_v1(value))
}

fn derive_story_status(operations: &[SecurityOperation]) -> StoryStatus {
    if operations
        .iter()
        .any(|operation| operation.state == OperationState::OutcomeUnknown)
    {
        StoryStatus::OutcomeUnknown
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::Failed)
    {
        StoryStatus::Failed
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::AwaitingApproval)
    {
        StoryStatus::AwaitingApproval
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::Completed)
    {
        StoryStatus::CompletedWithControlledSideEffect
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::Denied)
    {
        StoryStatus::BlockedBeforeSideEffect
    } else if operations.is_empty() {
        StoryStatus::Running
    } else {
        StoryStatus::OutcomeUnknown
    }
}

fn legacy_identity(authority: &AuthoritySnapshot) -> StoryIdentity {
    StoryIdentity {
        agent_id: "legacy-unavailable".to_string(),
        model_id: "legacy-unavailable".to_string(),
        actor_id: authority.actor_id.clone(),
        reviewer_id: None,
    }
}

fn legacy_stage_statuses(operations: &[SecurityOperation]) -> Vec<StoryStageStatus> {
    let has_review = operations
        .iter()
        .any(|operation| operation.state == OperationState::AwaitingApproval);
    let has_denial = operations
        .iter()
        .any(|operation| operation.state == OperationState::Denied);
    let execution_status = if operations
        .iter()
        .any(|operation| operation.state == OperationState::OutcomeUnknown)
    {
        StageStatus::Incomplete
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::Failed)
    {
        StageStatus::Failed
    } else if operations
        .iter()
        .any(|operation| operation.state == OperationState::Completed)
    {
        StageStatus::Completed
    } else if has_review || has_denial {
        StageStatus::Blocked
    } else {
        StageStatus::Incomplete
    };
    let stage = |stage, status, summary: &str| StoryStageStatus {
        stage,
        status,
        summary: summary.to_string(),
        observation_refs: Vec::new(),
    };

    vec![
        stage(
            StoryStage::Identity,
            StageStatus::Incomplete,
            "legacy agent and model identity unavailable",
        ),
        stage(
            StoryStage::Attack,
            StageStatus::Completed,
            "trusted scenario attack metadata recorded",
        ),
        stage(
            StoryStage::Model,
            StageStatus::Incomplete,
            "legacy model-call evidence unavailable",
        ),
        stage(
            StoryStage::ProposedTool,
            if operations.is_empty() {
                StageStatus::Incomplete
            } else {
                StageStatus::Completed
            },
            "legacy provider calls converted to redacted operations",
        ),
        stage(
            StoryStage::Policy,
            if has_denial {
                StageStatus::Blocked
            } else {
                StageStatus::Incomplete
            },
            "legacy policy result lacks native observations",
        ),
        stage(
            StoryStage::Approval,
            if has_review {
                StageStatus::Active
            } else {
                StageStatus::Incomplete
            },
            "legacy approval records are not native approvals",
        ),
        stage(
            StoryStage::Execution,
            execution_status,
            "legacy execution outcome conservatively classified",
        ),
        stage(
            StoryStage::Evidence,
            StageStatus::Incomplete,
            "no native story events or observations were minted",
        ),
    ]
}

fn legacy_outcome_summary(status: StoryStatus) -> String {
    match status {
        StoryStatus::Running => "Legacy conversion has no terminal operation outcome.".to_string(),
        StoryStatus::AwaitingApproval => {
            "Legacy record contains a review-held operation; native evidence is unavailable."
                .to_string()
        }
        StoryStatus::BlockedBeforeSideEffect => {
            "Legacy record reports blocking before side effect; native evidence is unavailable."
                .to_string()
        }
        StoryStatus::CompletedWithControlledSideEffect => {
            "Legacy record reports a controlled side effect; native evidence is unavailable."
                .to_string()
        }
        StoryStatus::Failed => {
            "Legacy record reports an execution failure; native evidence is unavailable."
                .to_string()
        }
        StoryStatus::OutcomeUnknown => {
            "Legacy record does not establish a trustworthy terminal outcome.".to_string()
        }
        StoryStatus::EvidenceInvalid => {
            "Legacy conversion cannot establish native evidence validity.".to_string()
        }
    }
}
