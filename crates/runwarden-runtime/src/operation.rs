use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::contracts::{PolicyDecision, ProviderCall};
use runwarden_kernel::kernel::ProviderRegistry;
use runwarden_kernel::operation::{
    ApprovalView, OperationState, ProviderExecutionStatus, ProviderResultView, SecurityOperation,
    SideEffectState,
};
use runwarden_kernel::policy::{SessionContext, evaluate_proposal};
use runwarden_kernel::resource_binding::{
    resource_proposal_commitment, resource_proposal_commitment_from_hashes,
};
use runwarden_kernel::session::BudgetUsageSnapshot;
use runwarden_kernel::story::{
    ApprovalId, EnforcementMode, ExecutionLeaseId, InvocationKey, OperationId, SessionId,
};
use runwarden_providers::catalog::full_provider_registry;
use runwarden_providers::executor::{
    CleanupDisposition, PermitClaims, PermitIssuer, ProviderExecutionOutcome,
    ProviderExecutionRequest, ProviderExecutionResult, ProviderExecutor, ReconciliationResult,
    canonical_argument_hash, canonical_provider_contract_hash,
};
use runwarden_providers::resource_claims::ResourceExtractorRegistry;
use runwarden_providers::{SafeArgumentProjectionError, project_safe_arguments};
use runwarden_state::{
    ApprovalRecordV1, CreateOperationOutcome, DurableApprovalBinding, ExecutionLease,
    ExecutionResultInput, ExecutionStarted, ExpireApprovalInput, FrozenProposalBinding,
    JournalError, LeaseAuthorization, LeaseRequest, MarkOutcomeUnknownInput, NewApproval,
    NewOperation, OperationRuntimeSnapshot, PrivateOperationMaterial, RecordPolicyInput,
    ReleaseLeaseInput, StateStore,
};
use serde::Serialize;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::approval::{ApprovalWaitOutcome, ApprovalWaitPolicy, wait_for_approval};
use crate::context::RuntimeContext;
use crate::errors::RuntimeError;

const APPROVAL_LIFETIME: Duration = Duration::seconds(120);
const EXECUTION_LEASE_LIFETIME: Duration = Duration::seconds(30);

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

    fn execution_snapshot(
        &self,
        _operation_id: OperationId,
    ) -> Result<runwarden_state::ExecutionRuntimeSnapshot, JournalError> {
        Err(unavailable("execution_snapshot"))
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
        _now: OffsetDateTime,
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

    fn execution_snapshot(
        &self,
        operation_id: OperationId,
    ) -> Result<runwarden_state::ExecutionRuntimeSnapshot, JournalError> {
        StateStore::execution_runtime_snapshot(self, operation_id)
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
        now: OffsetDateTime,
    ) -> Result<ExecutionStarted, JournalError> {
        StateStore::mark_execution_started_at(self, lease, now)
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
    executor: E,
    clock: C,
    context: RuntimeContext,
    permit_issuer: PermitIssuer,
    lease_owner: String,
    wait_policy: ApprovalWaitPolicy,
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
            executor,
            clock,
            context,
            permit_issuer,
            lease_owner,
            wait_policy,
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
        let provider_contract_hash = canonical_provider_contract_hash(provider)
            .map_err(|_| before_execution("provider_contract_hash"))?;
        let proposal_commitment = resource_proposal_commitment(
            provider,
            &request.action,
            &request.arguments,
            bound.claim(),
            bound.budget_charge(),
        );
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
                proposal_commitment: proposal_commitment.clone(),
                provider_contract_hash: provider_contract_hash.clone(),
                budget_charge: *bound.budget_charge(),
                now,
            })
            .map_err(map_create_operation_error)?;

        if !created.created {
            match created.operation.state {
                OperationState::Proposed => {}
                OperationState::AwaitingApproval => {
                    self.repair_pending_approval(&created.operation, now)?;
                    return self.drive_operation(created.operation.operation_id);
                }
                _ => return self.drive_operation(created.operation.operation_id),
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
        let policy_input = RecordPolicyInput {
            operation_id: created.operation.operation_id,
            expected_version: created.operation.version,
            decision: evaluation.decision.clone(),
            reason: evaluation.reason,
            next_state,
            checks: evaluation.checks,
            proposal_commitment: evaluation.proposal_commitment,
            now,
        };
        let operation = match self.journal.record_policy(policy_input) {
            Ok(operation) => operation,
            Err(_) => {
                let current = self
                    .journal
                    .operation(created.operation.operation_id)
                    .map_err(|_| before_execution("record_policy"))?;
                if current.state == OperationState::Proposed {
                    return Err(before_execution("record_policy"));
                }
                return self.drive_operation(current.operation_id);
            }
        };

        if self.context.story().enforcement_mode == EnforcementMode::Enforced
            && evaluation.decision == PolicyDecision::RequiresReview
        {
            self.journal
                .create_approval(self.pending_approval_input(&operation, now)?)
                .map_err(|_| before_execution("create_approval"))?;
        }

        self.drive_operation(operation.operation_id)
    }

    fn pending_approval_input(
        &self,
        operation: &SecurityOperation,
        now: OffsetDateTime,
    ) -> Result<NewApproval, RuntimeError> {
        let snapshot = self
            .journal
            .operation_snapshot(operation.operation_id)
            .map_err(|_| before_execution("create_approval"))?;
        if snapshot.operation.story_id != operation.story_id
            || snapshot.operation.session_id != operation.session_id
            || snapshot.operation.version != operation.version
            || snapshot.operation.state != operation.state
            || snapshot.operation.provider != operation.provider
            || snapshot.operation.action != operation.action
            || snapshot.operation.argument_hash != operation.argument_hash
            || snapshot.operation.resource_claim != operation.resource_claim
            || snapshot.operation.policy_snapshot_hash != operation.policy_snapshot_hash
        {
            return Err(RuntimeError::OperationConflict {
                operation_id: operation.operation_id,
            });
        }
        let binding = DurableApprovalBinding::from_operation(
            operation,
            &snapshot.frozen_proposal,
            &self.context.session().authority,
        )
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

    fn drive_operation(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        // Every successful branch advances durable state. The bound prevents
        // malformed journals from turning recovery into an unbounded loop.
        for _ in 0..16 {
            let snapshot = self.owned_operation_snapshot(operation_id)?;
            match snapshot.operation.state {
                OperationState::Proposed => {
                    return Err(RuntimeError::OperationNotResumable {
                        operation_id,
                        state: OperationState::Proposed,
                    });
                }
                OperationState::AwaitingApproval => {
                    self.repair_pending_approval(&snapshot.operation, self.clock.now())?;
                    match wait_for_approval(
                        &self.journal,
                        &self.clock,
                        operation_id,
                        self.wait_policy,
                    )? {
                        ApprovalWaitOutcome::Approved | ApprovalWaitOutcome::Terminal => {
                            continue;
                        }
                        ApprovalWaitOutcome::TimedOut => return self.status_inner(operation_id),
                    }
                }
                OperationState::PolicyEvaluated => {
                    if self.context.story().enforcement_mode != EnforcementMode::Enforced
                        || snapshot.policy_decision != Some(PolicyDecision::Allowed)
                    {
                        return Ok(response_from_operation(
                            snapshot.operation,
                            snapshot.policy_decision,
                        ));
                    }
                    match self.acquire_new_lease(
                        &snapshot.operation,
                        &snapshot.frozen_proposal,
                        None,
                    ) {
                        Ok((lease, request)) => return self.execute_leased(lease, request),
                        Err(error) => {
                            let current = self.owned_operation_snapshot(operation_id)?;
                            if current.operation.state == OperationState::PolicyEvaluated {
                                return Err(error);
                            }
                            continue;
                        }
                    }
                }
                OperationState::Approved => {
                    let approval = self
                        .journal
                        .approval_for_operation(operation_id)
                        .map_err(|_| before_execution("approval_for_operation"))?
                        .ok_or_else(|| before_execution("approval_for_operation"))?;
                    if approval.state != ApprovalState::Approved {
                        continue;
                    }
                    match self.acquire_new_lease(
                        &snapshot.operation,
                        &snapshot.frozen_proposal,
                        Some(&approval),
                    ) {
                        Ok((lease, request)) => return self.execute_leased(lease, request),
                        Err(error) => {
                            let current = self.owned_operation_snapshot(operation_id)?;
                            if current.operation.state == OperationState::Approved {
                                return Err(error);
                            }
                            continue;
                        }
                    }
                }
                OperationState::ExecutionLeased => {
                    let execution = match self.journal.execution_snapshot(operation_id) {
                        Ok(execution) => execution,
                        Err(_) => {
                            // Another resume may cross the start or result CAS
                            // between the operation snapshot and this exact
                            // lease snapshot. Re-read the durable state before
                            // classifying that expected race as journal damage.
                            let current = self.owned_operation_snapshot(operation_id)?;
                            if current.operation.state != OperationState::ExecutionLeased {
                                continue;
                            }
                            // A concurrent BEGIN IMMEDIATE start transaction
                            // may transiently block opening the exact read
                            // snapshot. Retry only within the bounded
                            // state-machine loop; persistent corruption still
                            // fails closed without dispatch.
                            std::thread::yield_now();
                            continue;
                        }
                    };
                    self.require_owned_operation(&execution.operation)?;
                    if execution.execution_started {
                        return Err(RuntimeError::OperationConflict { operation_id });
                    }
                    let now = self.clock.now();
                    if now >= execution.lease.expires_at {
                        match self.journal.release_unstarted_lease(ReleaseLeaseInput {
                            operation_id,
                            expected_operation_version: execution.operation.version,
                            lease_id: execution.lease.lease_id,
                            now,
                        }) {
                            Ok(_) => continue,
                            Err(_) => {
                                let current = self.owned_operation_snapshot(operation_id)?;
                                if current.operation.state == OperationState::ExecutionLeased {
                                    return Err(before_execution("release_unstarted_lease"));
                                }
                                continue;
                            }
                        }
                    }
                    if execution.lease.lease_owner != self.lease_owner {
                        return Err(RuntimeError::OperationConflict { operation_id });
                    }
                    let request = self.rebuild_execution_request(
                        &execution.operation,
                        &execution.frozen_proposal,
                    )?;
                    validate_request_matches_lease(&request, &execution.lease)?;
                    return self.execute_leased(execution.lease, request);
                }
                OperationState::Executing => {
                    match self.reconcile_or_status(operation_id) {
                        Ok(response) => return Ok(response),
                        Err(RuntimeError::JournalBeforeExecution(point))
                            if point == "execution_snapshot" =>
                        {
                            // A concurrent executor can commit the terminal
                            // result between the broad operation snapshot and
                            // the exact executing snapshot. Re-read through
                            // the bounded state-machine loop before treating
                            // that expected transition as journal damage.
                            let current = self.owned_operation_snapshot(operation_id)?;
                            if current.operation.state == OperationState::Executing {
                                std::thread::yield_now();
                            }
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                state if state.is_terminal() => {
                    return Ok(response_from_operation(
                        snapshot.operation,
                        snapshot.policy_decision,
                    ));
                }
                state => {
                    return Err(RuntimeError::OperationNotResumable {
                        operation_id,
                        state,
                    });
                }
            }
        }
        Err(RuntimeError::ContextUnavailable(
            "operation state did not converge".to_owned(),
        ))
    }

    fn owned_operation_snapshot(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationRuntimeSnapshot, RuntimeError> {
        let snapshot = self
            .journal
            .operation_snapshot(operation_id)
            .map_err(|_| before_execution("operation_status"))?;
        self.require_owned_operation(&snapshot.operation)?;
        Ok(snapshot)
    }

    fn require_owned_operation(&self, operation: &SecurityOperation) -> Result<(), RuntimeError> {
        if operation.story_id != self.context.story().story_id
            || operation.session_id != self.context.session().session_id
        {
            Err(RuntimeError::OperationConflict {
                operation_id: operation.operation_id,
            })
        } else {
            Ok(())
        }
    }

    fn acquire_new_lease(
        &self,
        operation: &SecurityOperation,
        frozen_proposal: &FrozenProposalBinding,
        approval: Option<&ApprovalRecordV1>,
    ) -> Result<(ExecutionLease, ProviderExecutionRequest), RuntimeError> {
        self.require_owned_operation(operation)?;
        let request = self.rebuild_execution_request(operation, frozen_proposal)?;
        let usage = self
            .journal
            .budget_snapshot(operation.session_id)
            .map_err(|_| before_execution("budget_snapshot"))?;
        let now = self.clock.now();
        let requested_expiry = now.checked_add(EXECUTION_LEASE_LIFETIME).ok_or_else(|| {
            RuntimeError::ContextUnavailable("execution lease expiry overflowed".to_owned())
        })?;
        let mut expires_at = requested_expiry.min(self.context.session().expires_at);
        let authorization = if let Some(approval) = approval {
            if approval.operation_id != operation.operation_id
                || approval.state != ApprovalState::Approved
            {
                return Err(RuntimeError::OperationConflict {
                    operation_id: operation.operation_id,
                });
            }
            expires_at = expires_at.min(approval.expires_at);
            LeaseAuthorization::ReviewerApproval {
                approval_id: approval.approval_id,
                expected_approval_version: approval.version,
            }
        } else {
            LeaseAuthorization::StoredPolicyAllow
        };
        if now >= expires_at {
            return Err(before_execution("acquire_execution_lease"));
        }
        let lease = self
            .journal
            .acquire_execution_lease(LeaseRequest {
                operation_id: operation.operation_id,
                expected_operation_version: operation.version,
                authorization,
                lease_id: ExecutionLeaseId::new(),
                lease_owner: self.lease_owner.clone(),
                instance_id: self.context.active_instance().instance_id.clone(),
                instance_token_hash: self.context.active_instance().instance_token_hash.clone(),
                expected_budget_version: usage.version,
                budget_charge: request.budget_charge,
                proposal_commitment: frozen_proposal.proposal_commitment.clone(),
                provider_contract_hash: frozen_proposal.provider_contract_hash.clone(),
                expires_at,
                now,
            })
            .map_err(|_| before_execution("acquire_execution_lease"))?;
        validate_request_matches_lease(&request, &lease)?;
        Ok((lease, request))
    }

    fn rebuild_execution_request(
        &self,
        operation: &SecurityOperation,
        frozen_proposal: &FrozenProposalBinding,
    ) -> Result<ProviderExecutionRequest, RuntimeError> {
        self.require_owned_operation(operation)?;
        let provider = self
            .catalog
            .get(&operation.provider)
            .ok_or_else(|| RuntimeError::ProviderUnknown(operation.provider.clone()))?;
        let private = self
            .journal
            .load_private_operation_material(operation.operation_id)
            .map_err(|_| before_execution("load_private_operation_material"))?;
        let argument_hash = canonical_argument_hash(&private.arguments);
        if argument_hash != operation.argument_hash {
            return Err(RuntimeError::OperationConflict {
                operation_id: operation.operation_id,
            });
        }
        let bound = self
            .extractors
            .extract_bound(
                provider,
                &operation.action,
                &private.arguments,
                self.context.extraction_context(),
                self.context.budget_limits(),
                self.context.story().enforcement_mode,
            )
            .map_err(|error| RuntimeError::ResourceInvalid(error.code().to_owned()))?;
        let safe_arguments =
            project_safe_arguments(&private.arguments, bound.claim()).map_err(projection_error)?;
        if bound.claim() != &operation.resource_claim || safe_arguments != operation.arguments {
            return Err(RuntimeError::OperationConflict {
                operation_id: operation.operation_id,
            });
        }
        if operation.policy_snapshot_hash.as_str()
            != self.context.session().policy_snapshot_hash.as_str()
        {
            return Err(RuntimeError::OperationConflict {
                operation_id: operation.operation_id,
            });
        }
        let provider_contract_hash = canonical_provider_contract_hash(provider)
            .map_err(|_| before_execution("provider_contract_hash"))?;
        let resource_claim_hash = operation.resource_claim.digest();
        let current_commitment = resource_proposal_commitment_from_hashes(
            provider_contract_hash.clone(),
            &operation.provider,
            &operation.action,
            argument_hash.clone(),
            resource_claim_hash.clone(),
            *bound.budget_charge(),
        );
        if provider_contract_hash != frozen_proposal.provider_contract_hash
            || *bound.budget_charge() != frozen_proposal.budget_charge
            || current_commitment != frozen_proposal.proposal_commitment
        {
            return Err(RuntimeError::OperationConflict {
                operation_id: operation.operation_id,
            });
        }
        Ok(ProviderExecutionRequest {
            operation_id: operation.operation_id,
            story_id: operation.story_id,
            session_id: operation.session_id,
            provider: operation.provider.clone(),
            action: operation.action.clone(),
            arguments: private.arguments,
            argument_hash,
            resource_claim: operation.resource_claim.clone(),
            resource_claim_hash,
            policy_snapshot_hash: operation.policy_snapshot_hash.clone(),
            provider_contract_hash,
            budget_charge: *bound.budget_charge(),
        })
    }

    fn execute_leased(
        &self,
        lease: ExecutionLease,
        request: ProviderExecutionRequest,
    ) -> Result<RuntimeResponse, RuntimeError> {
        validate_request_matches_lease(&request, &lease)?;
        let started = match self
            .journal
            .mark_execution_started(&lease, self.clock.now())
        {
            Ok(started) => started,
            Err(_) => {
                let current = self.owned_operation_snapshot(lease.operation_id)?;
                if current.operation.state != OperationState::ExecutionLeased {
                    return Ok(response_from_operation(
                        current.operation,
                        current.policy_decision,
                    ));
                }
                return Err(before_execution("mark_execution_started"));
            }
        };
        let claims = PermitClaims {
            lease_id: lease.lease_id,
            operation_id: request.operation_id,
            story_id: request.story_id,
            session_id: request.session_id,
            provider: request.provider.clone(),
            action: request.action.clone(),
            argument_hash: request.argument_hash.clone(),
            resource_claim_hash: request.resource_claim_hash.clone(),
            policy_snapshot_hash: request.policy_snapshot_hash.clone(),
            provider_contract_hash: request.provider_contract_hash.clone(),
            budget_charge: lease.budget_charge,
            expires_at: lease.expires_at,
            execution_started_version: started.operation_version,
        };
        let permit = match self.permit_issuer.seal(claims) {
            Ok(permit) => permit,
            Err(_) => {
                let _ = self.mark_unknown(
                    &started,
                    &lease,
                    "execution_permit_seal_failed",
                    self.clock.now(),
                );
                return Err(RuntimeError::JournalAfterExecution {
                    operation_id: request.operation_id,
                    reason: "execution_permit_seal_failed".to_owned(),
                });
            }
        };
        let outcome = self.executor.execute(&permit, &request, self.clock.now());
        self.persist_execution_outcome(&started, &lease, outcome)
    }

    fn persist_execution_outcome(
        &self,
        started: &ExecutionStarted,
        lease: &ExecutionLease,
        outcome: ProviderExecutionOutcome,
    ) -> Result<RuntimeResponse, RuntimeError> {
        let ProviderExecutionOutcome { result, cleanup } = outcome;
        let status = result.execution_status();
        if result.validate_against(lease.budget_charge).is_err() {
            return self.persist_unknown_result(started, lease, "provider_result_invalid", cleanup);
        }
        match status {
            ProviderExecutionStatus::Running => self.persist_unknown_result(
                started,
                lease,
                "provider_result_still_running",
                cleanup,
            ),
            ProviderExecutionStatus::Simulated => {
                self.persist_unknown_result(started, lease, "simulated_result_rejected", cleanup)
            }
            ProviderExecutionStatus::OutcomeUnknown => self.persist_unknown_result(
                started,
                lease,
                result.reason_code().unwrap_or("provider_outcome_unknown"),
                cleanup,
            ),
            ProviderExecutionStatus::Completed
            | ProviderExecutionStatus::NotExecuted
            | ProviderExecutionStatus::FailedBeforeSideEffect
            | ProviderExecutionStatus::ExecutedWithError => {
                self.persist_known_result(started, lease, result, cleanup)
            }
        }
    }

    fn persist_known_result(
        &self,
        started: &ExecutionStarted,
        lease: &ExecutionLease,
        result: ProviderExecutionResult,
        cleanup: Option<runwarden_providers::executor::CleanupToken>,
    ) -> Result<RuntimeResponse, RuntimeError> {
        let next_state = match result.execution_status() {
            ProviderExecutionStatus::Completed => OperationState::Completed,
            ProviderExecutionStatus::NotExecuted
            | ProviderExecutionStatus::FailedBeforeSideEffect
            | ProviderExecutionStatus::ExecutedWithError => OperationState::Failed,
            ProviderExecutionStatus::Running
            | ProviderExecutionStatus::OutcomeUnknown
            | ProviderExecutionStatus::Simulated => {
                return self.persist_unknown_result(
                    started,
                    lease,
                    "provider_result_invalid",
                    cleanup,
                );
            }
        };
        let input = ExecutionResultInput {
            operation_id: started.operation_id,
            expected_operation_version: started.operation_version,
            lease_id: started.lease_id,
            lease_owner: started.lease_owner.clone(),
            next_state,
            side_effect_state: result.side_effect_state(),
            provider_result: provider_result_view(&result),
            actual_budget_charge: result.actual_budget_charge(),
            now: self.clock.now(),
        };
        if self.journal.record_execution_result(input).is_err() {
            let committed_before_fallback = self
                .owned_operation_snapshot(started.operation_id)
                .is_ok_and(|snapshot| snapshot.operation.state.is_terminal());
            let unknown_committed = if committed_before_fallback {
                false
            } else {
                self.mark_unknown(
                    started,
                    lease,
                    "provider_result_persistence_failed",
                    self.clock.now(),
                )
                .is_ok()
            };
            let terminal_after_fallback = committed_before_fallback
                || unknown_committed
                || self
                    .owned_operation_snapshot(started.operation_id)
                    .is_ok_and(|snapshot| snapshot.operation.state.is_terminal());
            let cleanup_error = if let Some(token) = cleanup {
                let disposition = if terminal_after_fallback {
                    CleanupDisposition::ResultCommitted
                } else {
                    CleanupDisposition::JournalFailedRetainForReconcile
                };
                self.executor
                    .finalize_cleanup(token, disposition)
                    .err()
                    .map(|error| error.to_string())
            } else {
                None
            };
            if let Some(cleanup_reason) = cleanup_error {
                return Err(RuntimeError::JournalAndCleanupAfterExecution {
                    operation_id: started.operation_id,
                    journal_reason: "provider_result_persistence_failed".to_owned(),
                    cleanup_reason,
                });
            }
            return Err(RuntimeError::JournalAfterExecution {
                operation_id: started.operation_id,
                reason: "provider_result_persistence_failed".to_owned(),
            });
        }
        self.finalize_committed_cleanup(started.operation_id, cleanup)?;
        self.status_inner(started.operation_id)
    }

    fn persist_unknown_result(
        &self,
        started: &ExecutionStarted,
        lease: &ExecutionLease,
        reason_code: &str,
        cleanup: Option<runwarden_providers::executor::CleanupToken>,
    ) -> Result<RuntimeResponse, RuntimeError> {
        if self
            .mark_unknown(started, lease, reason_code, self.clock.now())
            .is_err()
        {
            let terminal = self
                .owned_operation_snapshot(started.operation_id)
                .is_ok_and(|snapshot| snapshot.operation.state.is_terminal());
            let cleanup_error = if let Some(token) = cleanup {
                let disposition = if terminal {
                    CleanupDisposition::ResultCommitted
                } else {
                    CleanupDisposition::JournalFailedRetainForReconcile
                };
                self.executor
                    .finalize_cleanup(token, disposition)
                    .err()
                    .map(|error| error.to_string())
            } else {
                None
            };
            if let Some(cleanup_reason) = cleanup_error {
                return Err(RuntimeError::JournalAndCleanupAfterExecution {
                    operation_id: started.operation_id,
                    journal_reason: "outcome_unknown_persistence_failed".to_owned(),
                    cleanup_reason,
                });
            }
            return Err(RuntimeError::JournalAfterExecution {
                operation_id: started.operation_id,
                reason: "outcome_unknown_persistence_failed".to_owned(),
            });
        }
        self.finalize_committed_cleanup(started.operation_id, cleanup)?;
        self.status_inner(started.operation_id)
    }

    fn mark_unknown(
        &self,
        started: &ExecutionStarted,
        lease: &ExecutionLease,
        reason_code: &str,
        now: OffsetDateTime,
    ) -> Result<SecurityOperation, JournalError> {
        self.journal.mark_outcome_unknown(MarkOutcomeUnknownInput {
            operation_id: started.operation_id,
            expected_operation_version: started.operation_version,
            lease_id: lease.lease_id,
            lease_owner: lease.lease_owner.clone(),
            reason_code: stable_reason_code(reason_code),
            now,
        })
    }

    fn finalize_committed_cleanup(
        &self,
        operation_id: OperationId,
        cleanup: Option<runwarden_providers::executor::CleanupToken>,
    ) -> Result<(), RuntimeError> {
        if let Some(token) = cleanup {
            self.executor
                .finalize_cleanup(token, CleanupDisposition::ResultCommitted)
                .map_err(|error| RuntimeError::CleanupAfterCommit {
                    operation_id,
                    reason: error.to_string(),
                })?;
        }
        Ok(())
    }

    fn reconcile_or_status(
        &self,
        operation_id: OperationId,
    ) -> Result<RuntimeResponse, RuntimeError> {
        let execution = self
            .journal
            .execution_snapshot(operation_id)
            .map_err(|_| before_execution("execution_snapshot"))?;
        self.require_owned_operation(&execution.operation)?;
        if execution.operation.state != OperationState::Executing || !execution.execution_started {
            return Err(RuntimeError::OperationConflict { operation_id });
        }
        if self.clock.now() < execution.lease.expires_at {
            return Ok(response_from_operation(
                execution.operation,
                Some(execution.policy_decision),
            ));
        }
        let request =
            self.rebuild_execution_request(&execution.operation, &execution.frozen_proposal)?;
        validate_request_matches_lease(&request, &execution.lease)?;
        let reconciliation = self.executor.reconcile(&request);
        let started = ExecutionStarted {
            operation_id,
            operation_version: execution.operation.version,
            approval_version: None,
            lease_id: execution.lease.lease_id,
            lease_owner: execution.lease.lease_owner.clone(),
        };
        match reconciliation.result {
            ReconciliationResult::Completed(result) => self.persist_known_result(
                &started,
                &execution.lease,
                *result,
                reconciliation.cleanup,
            ),
            ReconciliationResult::NotExecuted => self.persist_known_result(
                &started,
                &execution.lease,
                ProviderExecutionResult::blocked(
                    "reconciliation_not_executed",
                    "provider_not_executed",
                ),
                reconciliation.cleanup,
            ),
            ReconciliationResult::Unknown => self.persist_unknown_result(
                &started,
                &execution.lease,
                "reconciliation_outcome_unknown",
                reconciliation.cleanup,
            ),
        }
    }

    fn status_inner(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        let snapshot = self.owned_operation_snapshot(operation_id)?;
        Ok(response_from_operation(
            snapshot.operation,
            snapshot.policy_decision,
        ))
    }

    fn resume_inner(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        let snapshot = self.owned_operation_snapshot(operation_id)?;
        match snapshot.operation.state {
            OperationState::AwaitingApproval
            | OperationState::Approved
            | OperationState::PolicyEvaluated
            | OperationState::ExecutionLeased
            | OperationState::Executing => self.drive_operation(operation_id),
            state if state.is_terminal() => Ok(response_from_operation(
                snapshot.operation,
                snapshot.policy_decision,
            )),
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

fn validate_request_matches_lease(
    request: &ProviderExecutionRequest,
    lease: &ExecutionLease,
) -> Result<(), RuntimeError> {
    if request.operation_id != lease.operation_id
        || request.story_id != lease.story_id
        || request.session_id != lease.session_id
        || request.provider != lease.provider
        || request.action != lease.action
        || request.argument_hash != lease.argument_hash
        || request.resource_claim_hash != lease.resource_claim_hash
        || request.policy_snapshot_hash != lease.policy_snapshot_hash
        || request.provider_contract_hash != lease.provider_contract_hash
        || request.budget_charge != lease.budget_charge
        || resource_proposal_commitment_from_hashes(
            request.provider_contract_hash.clone(),
            &request.provider,
            &request.action,
            request.argument_hash.clone(),
            request.resource_claim_hash.clone(),
            request.budget_charge,
        ) != lease.proposal_commitment
    {
        Err(RuntimeError::OperationConflict {
            operation_id: request.operation_id,
        })
    } else {
        Ok(())
    }
}

fn provider_result_view(result: &ProviderExecutionResult) -> ProviderResultView {
    ProviderResultView {
        execution_status: result.execution_status(),
        output: result.output().clone(),
        output_hash: result.output_hash().cloned(),
        error_kind: result.error_kind().map(ToOwned::to_owned),
        reason_code: result.reason_code().map(ToOwned::to_owned),
    }
}

fn stable_reason_code(value: &str) -> String {
    runwarden_kernel::trace::EventCode::try_from(value.to_owned())
        .map(String::from)
        .unwrap_or_else(|_| "runtime_outcome_unknown".to_owned())
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
