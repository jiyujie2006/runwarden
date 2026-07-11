use std::time::Duration as StdDuration;

use runwarden_kernel::contracts::{PolicyDecision, ProviderCall};
use runwarden_kernel::kernel::ProviderRegistry;
use runwarden_kernel::operation::{
    ApprovalView, OperationState, ProviderResultView, SecurityOperation, SideEffectState,
};
use runwarden_kernel::policy::{SessionContext, evaluate_proposal};
use runwarden_kernel::session::BudgetUsageSnapshot;
use runwarden_kernel::story::{ApprovalId, EnforcementMode, InvocationKey, OperationId, SessionId};
use runwarden_providers::catalog::full_provider_registry;
use runwarden_providers::executor::{PermitIssuer, ProviderExecutor};
use runwarden_providers::resource_claims::ResourceExtractorRegistry;
use runwarden_providers::{SafeArgumentProjectionError, project_safe_arguments};
use runwarden_state::{
    ApprovalRecordV1, CreateOperationOutcome, DurableApprovalBinding, ExecutionLease,
    ExecutionResultInput, ExecutionStarted, ExpireApprovalInput, JournalError,
    MarkOutcomeUnknownInput, NewApproval, NewOperation, OperationRuntimeSnapshot,
    PrivateOperationMaterial, RecordPolicyInput, ReleaseLeaseInput, StateStore,
};
use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::context::RuntimeContext;
use crate::errors::RuntimeError;

const APPROVAL_LIFETIME: Duration = Duration::seconds(120);

/// Private provider input. Deliberately not `Debug` or serializable because
/// arguments can contain message bodies, credentials, or file content.
#[derive(Clone)]
pub struct RuntimeRequest {
    pub invocation_key: InvocationKey,
    pub provider: String,
    pub action: String,
    pub arguments: Value,
    pub parent_model_call_id: Option<String>,
    pub proposed_tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDisposition {
    Proposed,
    Denied,
    AwaitingApproval,
    Approved,
    Executing,
    Completed,
    Failed,
    Expired,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResponse {
    pub operation_id: OperationId,
    pub operation_version: u64,
    pub operation_state: OperationState,
    pub disposition: RuntimeDisposition,
    pub policy_decision: Option<PolicyDecision>,
    pub side_effect_state: SideEffectState,
    pub approval: Option<ApprovalView>,
    pub provider_result: Option<ProviderResultView>,
    pub observation_refs: Vec<runwarden_kernel::story::ObservationId>,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalWaitPolicy {
    pub timeout: StdDuration,
    pub poll_interval: StdDuration,
}

impl ApprovalWaitPolicy {
    pub fn contest_default() -> Self {
        Self {
            timeout: StdDuration::from_secs(120),
            poll_interval: StdDuration::from_millis(100),
        }
    }

    pub fn immediate() -> Self {
        Self {
            timeout: StdDuration::ZERO,
            poll_interval: StdDuration::from_millis(1),
        }
    }
}

impl Default for ApprovalWaitPolicy {
    fn default() -> Self {
        Self::contest_default()
    }
}

/// Narrow durable contract used by orchestration. Later-stage methods have
/// fail-closed defaults so Task 1 test doubles cannot accidentally simulate a
/// successful execution boundary.
pub trait RuntimeJournal: Send + Sync {
    fn active_context(
        &self,
        instance_token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<RuntimeContext, JournalError>;

    fn create_operation(&self, input: NewOperation)
    -> Result<CreateOperationOutcome, JournalError>;

    fn budget_snapshot(&self, session_id: SessionId) -> Result<BudgetUsageSnapshot, JournalError>;

    fn record_policy(&self, input: RecordPolicyInput) -> Result<SecurityOperation, JournalError>;

    fn create_approval(&self, input: NewApproval) -> Result<ApprovalRecordV1, JournalError>;

    fn approval_for_operation(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<ApprovalRecordV1>, JournalError> {
        Err(unavailable("approval_for_operation"))
    }

    fn policy_decision(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<PolicyDecision>, JournalError> {
        Err(unavailable("policy_decision"))
    }

    fn operation(&self, _operation_id: OperationId) -> Result<SecurityOperation, JournalError> {
        Err(unavailable("operation"))
    }

    fn operation_snapshot(
        &self,
        _operation_id: OperationId,
    ) -> Result<OperationRuntimeSnapshot, JournalError> {
        Err(unavailable("operation_snapshot"))
    }

    fn expire_approval(
        &self,
        _input: ExpireApprovalInput,
    ) -> Result<ApprovalRecordV1, JournalError> {
        Err(unavailable("expire_approval"))
    }

    fn acquire_execution_lease(
        &self,
        _input: runwarden_state::LeaseRequest,
    ) -> Result<ExecutionLease, JournalError> {
        Err(unavailable("acquire_execution_lease"))
    }

    fn execution_lease(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<ExecutionLease>, JournalError> {
        Err(unavailable("execution_lease"))
    }

    fn release_unstarted_lease(
        &self,
        _input: ReleaseLeaseInput,
    ) -> Result<SecurityOperation, JournalError> {
        Err(unavailable("release_unstarted_lease"))
    }

    fn mark_execution_started(
        &self,
        _lease: &ExecutionLease,
    ) -> Result<ExecutionStarted, JournalError> {
        Err(unavailable("mark_execution_started"))
    }

    fn record_execution_result(&self, _input: ExecutionResultInput) -> Result<(), JournalError> {
        Err(unavailable("record_execution_result"))
    }

    fn mark_outcome_unknown(
        &self,
        _input: MarkOutcomeUnknownInput,
    ) -> Result<SecurityOperation, JournalError> {
        Err(unavailable("mark_outcome_unknown"))
    }

    fn load_private_operation_material(
        &self,
        _operation_id: OperationId,
    ) -> Result<PrivateOperationMaterial, JournalError> {
        Err(unavailable("load_private_operation_material"))
    }

    fn has_execution_started(&self, _operation_id: OperationId) -> Result<bool, JournalError> {
        Err(unavailable("has_execution_started"))
    }
}

fn unavailable(method: &'static str) -> JournalError {
    JournalError::Integrity(format!("runtime journal method unavailable: {method}"))
}

impl RuntimeJournal for StateStore {
    fn active_context(
        &self,
        instance_token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<RuntimeContext, JournalError> {
        let snapshot = self.active_context_snapshot(instance_token_hash, now)?;
        RuntimeContext::from_server_records(
            snapshot.active,
            snapshot.story,
            snapshot.session,
            instance_token_hash,
            now,
        )
        .map_err(|error| JournalError::Integrity(error.to_string()))
    }

    fn create_operation(
        &self,
        input: NewOperation,
    ) -> Result<CreateOperationOutcome, JournalError> {
        StateStore::create_operation(self, input)
    }

    fn budget_snapshot(&self, session_id: SessionId) -> Result<BudgetUsageSnapshot, JournalError> {
        StateStore::budget_snapshot(self, session_id)
    }

    fn record_policy(&self, input: RecordPolicyInput) -> Result<SecurityOperation, JournalError> {
        StateStore::record_policy(self, input)
    }

    fn create_approval(&self, input: NewApproval) -> Result<ApprovalRecordV1, JournalError> {
        StateStore::create_approval(self, input)
    }

    fn approval_for_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApprovalRecordV1>, JournalError> {
        StateStore::approval_for_operation(self, operation_id)
    }

    fn policy_decision(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PolicyDecision>, JournalError> {
        StateStore::policy_decision(self, operation_id)
    }

    fn operation(&self, operation_id: OperationId) -> Result<SecurityOperation, JournalError> {
        StateStore::operation(self, operation_id)
    }

    fn operation_snapshot(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationRuntimeSnapshot, JournalError> {
        StateStore::operation_runtime_snapshot(self, operation_id)
    }

    fn expire_approval(
        &self,
        input: ExpireApprovalInput,
    ) -> Result<ApprovalRecordV1, JournalError> {
        StateStore::expire_approval(self, input)
    }

    fn acquire_execution_lease(
        &self,
        input: runwarden_state::LeaseRequest,
    ) -> Result<ExecutionLease, JournalError> {
        StateStore::acquire_execution_lease(self, input)
    }

    fn execution_lease(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ExecutionLease>, JournalError> {
        StateStore::execution_lease(self, operation_id)
    }

    fn release_unstarted_lease(
        &self,
        input: ReleaseLeaseInput,
    ) -> Result<SecurityOperation, JournalError> {
        StateStore::release_unstarted_lease(self, input)
    }

    fn mark_execution_started(
        &self,
        lease: &ExecutionLease,
    ) -> Result<ExecutionStarted, JournalError> {
        StateStore::mark_execution_started(self, lease)
    }

    fn record_execution_result(&self, input: ExecutionResultInput) -> Result<(), JournalError> {
        StateStore::record_execution_result(self, input)
    }

    fn mark_outcome_unknown(
        &self,
        input: MarkOutcomeUnknownInput,
    ) -> Result<SecurityOperation, JournalError> {
        StateStore::mark_outcome_unknown(self, input)
    }

    fn load_private_operation_material(
        &self,
        operation_id: OperationId,
    ) -> Result<PrivateOperationMaterial, JournalError> {
        StateStore::load_private_operation_material(self, operation_id)
    }

    fn has_execution_started(&self, operation_id: OperationId) -> Result<bool, JournalError> {
        StateStore::has_execution_started(self, operation_id)
    }
}

pub trait RuntimeApi: Send + Sync {
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError>;
    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
}

pub trait McpRuntime: Send + Sync {
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError>;
    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
}

pub struct OperationRuntime<J, E, C>
where
    J: RuntimeJournal,
    E: ProviderExecutor,
    C: Clock,
{
    journal: J,
    _executor: E,
    clock: C,
    context: RuntimeContext,
    _permit_issuer: PermitIssuer,
    _lease_owner: String,
    _wait_policy: ApprovalWaitPolicy,
    catalog: ProviderRegistry,
    extractors: ResourceExtractorRegistry,
    policy_context: SessionContext,
}

impl<J, E, C> OperationRuntime<J, E, C>
where
    J: RuntimeJournal,
    E: ProviderExecutor,
    C: Clock,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        journal: J,
        executor: E,
        clock: C,
        context: RuntimeContext,
        permit_issuer: PermitIssuer,
        lease_owner: String,
        wait_policy: ApprovalWaitPolicy,
    ) -> Result<Self, RuntimeError> {
        if lease_owner.trim().is_empty() || lease_owner.len() > 256 {
            return Err(RuntimeError::ContextUnavailable(
                "lease owner is empty or oversized".to_owned(),
            ));
        }
        if wait_policy.poll_interval.is_zero() {
            return Err(RuntimeError::ContextUnavailable(
                "approval polling interval must be positive".to_owned(),
            ));
        }
        let catalog = full_provider_registry();
        let (extractors, verifier) = ResourceExtractorRegistry::contest_authoritative()
            .map_err(|error| RuntimeError::ContextUnavailable(error.code().to_owned()))?;
        let policy_context = SessionContext::from_authority(
            context.story().story_id,
            context.session().authority.clone(),
            &catalog,
            context.story().enforcement_mode,
            verifier,
        )
        .map_err(|error| RuntimeError::ContextUnavailable(error.to_string()))?;
        Ok(Self {
            journal,
            _executor: executor,
            clock,
            context,
            _permit_issuer: permit_issuer,
            _lease_owner: lease_owner,
            _wait_policy: wait_policy,
            catalog,
            extractors,
            policy_context,
        })
    }

    fn invoke_inner(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError> {
        let now = self.clock.now();
        let provider = self
            .catalog
            .get(&request.provider)
            .ok_or_else(|| RuntimeError::ProviderUnknown(request.provider.clone()))?;
        let bound = self
            .extractors
            .extract_bound(
                provider,
                &request.action,
                &request.arguments,
                self.context.extraction_context(),
                self.context.budget_limits(),
                self.context.story().enforcement_mode,
            )
            .map_err(|error| RuntimeError::ResourceInvalid(error.code().to_owned()))?;
        let safe_arguments =
            project_safe_arguments(&request.arguments, bound.claim()).map_err(projection_error)?;
        let operation_id = OperationId::new();
        let created = self
            .journal
            .create_operation(NewOperation {
                operation_id,
                story_id: self.context.story().story_id,
                session_id: self.context.session().session_id,
                invocation_key: request.invocation_key,
                parent_model_call_id: request.parent_model_call_id,
                proposed_tool_call_id: request.proposed_tool_call_id,
                provider: request.provider.clone(),
                action: request.action.clone(),
                resource_claim: bound.claim().clone(),
                argument_hash: runwarden_providers::executor::canonical_argument_hash(
                    &request.arguments,
                ),
                arguments: safe_arguments,
                private_material: PrivateOperationMaterial {
                    arguments: request.arguments.clone(),
                },
                policy_snapshot_hash: self
                    .policy_context
                    .authority
                    .policy_snapshot_hash
                    .clone()
                    .try_into()
                    .map_err(|_| {
                        RuntimeError::ContextUnavailable(
                            "policy snapshot hash is not canonical".to_owned(),
                        )
                    })?,
                now,
            })
            .map_err(map_create_operation_error)?;

        if !created.created {
            match created.operation.state {
                OperationState::Proposed => {}
                OperationState::AwaitingApproval => {
                    self.repair_pending_approval(&created.operation, now)?;
                    return self.status_inner(created.operation.operation_id);
                }
                _ => return self.status_inner(created.operation.operation_id),
            }
        }

        let usage = self
            .journal
            .budget_snapshot(self.context.session().session_id)
            .map_err(|_| before_execution("budget_snapshot"))?;
        let call = ProviderCall {
            session_id: self.context.session().session_id.to_string(),
            provider: request.provider,
            action: request.action,
            arguments: request.arguments,
            actor_id: Some(self.context.session().authority.actor_id.clone()),
            authz_id: Some(self.context.session().authority.authz_id.clone()),
            approval_id: None,
        };
        let evaluation = evaluate_proposal(
            &self.policy_context,
            &usage,
            bound.budget_charge(),
            provider,
            &call,
            bound.claim(),
            bound.binding(),
            now,
        );
        let next_state = policy_state(self.context.story().enforcement_mode, &evaluation.decision);
        let operation = self
            .journal
            .record_policy(RecordPolicyInput {
                operation_id: created.operation.operation_id,
                expected_version: created.operation.version,
                decision: evaluation.decision.clone(),
                reason: evaluation.reason,
                next_state,
                checks: evaluation.checks,
                now,
            })
            .map_err(|_| before_execution("record_policy"))?;

        if self.context.story().enforcement_mode == EnforcementMode::Enforced
            && evaluation.decision == PolicyDecision::RequiresReview
        {
            self.journal
                .create_approval(self.pending_approval_input(&operation, now)?)
                .map_err(|_| before_execution("create_approval"))?;
        }

        self.status_inner(operation.operation_id)
    }

    fn pending_approval_input(
        &self,
        operation: &SecurityOperation,
        now: OffsetDateTime,
    ) -> Result<NewApproval, RuntimeError> {
        let binding =
            DurableApprovalBinding::from_operation(operation, &self.context.session().authority)
                .map_err(|_| before_execution("create_approval"))?;
        let requested_expiry = now.checked_add(APPROVAL_LIFETIME).ok_or_else(|| {
            RuntimeError::ContextUnavailable("approval expiry overflowed".to_owned())
        })?;
        Ok(NewApproval {
            approval_id: ApprovalId::new(),
            operation_id: operation.operation_id,
            binding,
            expires_at: requested_expiry.min(self.context.session().expires_at),
            now,
        })
    }

    /// Repair the pre-execution crash gap where the policy write committed
    /// `AwaitingApproval`, but no pending approval was observed by the caller.
    fn repair_pending_approval(
        &self,
        operation: &SecurityOperation,
        now: OffsetDateTime,
    ) -> Result<ApprovalRecordV1, RuntimeError> {
        if let Some(existing) = self
            .journal
            .approval_for_operation(operation.operation_id)
            .map_err(|_| before_execution("approval_for_operation"))?
        {
            return Ok(existing);
        }

        match self
            .journal
            .create_approval(self.pending_approval_input(operation, now)?)
        {
            Ok(created) => Ok(created),
            Err(_) => self
                .journal
                .approval_for_operation(operation.operation_id)
                .map_err(|_| before_execution("create_approval"))?
                .ok_or_else(|| before_execution("create_approval")),
        }
    }

    fn status_inner(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        let snapshot = self
            .journal
            .operation_snapshot(operation_id)
            .map_err(|_| before_execution("operation_status"))?;
        let operation = snapshot.operation;
        if operation.story_id != self.context.story().story_id
            || operation.session_id != self.context.session().session_id
        {
            return Err(RuntimeError::OperationConflict { operation_id });
        }
        Ok(response_from_operation(operation, snapshot.policy_decision))
    }

    fn resume_inner(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        let response = self.status_inner(operation_id)?;
        match response.operation_state {
            OperationState::AwaitingApproval => {
                let operation = self
                    .journal
                    .operation(operation_id)
                    .map_err(|_| before_execution("operation_status"))?;
                if operation.story_id != self.context.story().story_id
                    || operation.session_id != self.context.session().session_id
                {
                    return Err(RuntimeError::OperationConflict { operation_id });
                }
                self.repair_pending_approval(&operation, self.clock.now())?;
                self.status_inner(operation_id)
            }
            OperationState::Approved
            | OperationState::PolicyEvaluated
            | OperationState::ExecutionLeased => Ok(response),
            state if state.is_terminal() => Ok(response),
            state => Err(RuntimeError::OperationNotResumable {
                operation_id,
                state,
            }),
        }
    }
}

impl<J, E, C> RuntimeApi for OperationRuntime<J, E, C>
where
    J: RuntimeJournal,
    E: ProviderExecutor,
    C: Clock,
{
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError> {
        self.invoke_inner(request)
    }

    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        self.status_inner(operation_id)
    }

    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        self.resume_inner(operation_id)
    }
}

impl<J, E, C> McpRuntime for OperationRuntime<J, E, C>
where
    J: RuntimeJournal,
    E: ProviderExecutor,
    C: Clock,
{
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError> {
        self.invoke_inner(request)
    }

    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        self.status_inner(operation_id)
    }

    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        self.resume_inner(operation_id)
    }
}

fn projection_error(error: SafeArgumentProjectionError) -> RuntimeError {
    RuntimeError::ResourceInvalid(error.to_string())
}

fn before_execution(point: &'static str) -> RuntimeError {
    RuntimeError::JournalBeforeExecution(point.to_owned())
}

fn map_create_operation_error(error: JournalError) -> RuntimeError {
    match error {
        JournalError::InvocationConflict { operation_id } => {
            RuntimeError::OperationConflict { operation_id }
        }
        _ => before_execution("create_operation"),
    }
}

fn policy_state(mode: EnforcementMode, decision: &PolicyDecision) -> OperationState {
    if mode == EnforcementMode::MonitorOnly {
        OperationState::PolicyEvaluated
    } else {
        match decision {
            PolicyDecision::Allowed => OperationState::PolicyEvaluated,
            PolicyDecision::Denied => OperationState::Denied,
            PolicyDecision::RequiresReview => OperationState::AwaitingApproval,
        }
    }
}

fn response_from_operation(
    operation: SecurityOperation,
    policy_decision: Option<PolicyDecision>,
) -> RuntimeResponse {
    let disposition = match operation.state {
        OperationState::Proposed => RuntimeDisposition::Proposed,
        OperationState::PolicyEvaluated => match policy_decision.as_ref() {
            Some(PolicyDecision::Allowed) => RuntimeDisposition::Approved,
            Some(PolicyDecision::Denied) => RuntimeDisposition::Denied,
            Some(PolicyDecision::RequiresReview) | None => RuntimeDisposition::Proposed,
        },
        OperationState::Approved => RuntimeDisposition::Approved,
        OperationState::Denied | OperationState::DeniedByReviewer => RuntimeDisposition::Denied,
        OperationState::AwaitingApproval => RuntimeDisposition::AwaitingApproval,
        OperationState::Expired => RuntimeDisposition::Expired,
        OperationState::ExecutionLeased | OperationState::Executing => {
            RuntimeDisposition::Executing
        }
        OperationState::Completed => RuntimeDisposition::Completed,
        OperationState::Failed | OperationState::ObservedOnly => RuntimeDisposition::Failed,
        OperationState::OutcomeUnknown => RuntimeDisposition::OutcomeUnknown,
    };
    RuntimeResponse {
        operation_id: operation.operation_id,
        operation_version: operation.version,
        operation_state: operation.state,
        disposition,
        policy_decision,
        side_effect_state: operation.side_effect_state,
        approval: operation.approval,
        provider_result: operation.provider_result,
        observation_refs: operation.observation_refs,
    }
}
