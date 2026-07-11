use std::sync::Arc;

use hmac::{Hmac, Mac};
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::contracts::KernelProvider;
use runwarden_kernel::operation::{ProviderExecutionStatus, SafeProviderOutput, SideEffectState};
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ExecutionLeaseId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::{EventCode, Sha256Digest, canonical_json_v1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const PERMIT_DOMAIN_V1: &[u8] = b"runwarden.execution-permit.hmac-sha256.v1\0";
const PROVIDER_CONTRACT_DOMAIN_V1: &str = "runwarden.kernel-provider-contract.v1";
const INVALID_ERROR_KIND: &str = "invalid_error_kind";
const INVALID_REASON_CODE: &str = "invalid_reason_code";

/// Private provider material frozen after typed claim extraction and before
/// any side effect. Deliberately not `Debug` or serializable: `arguments` may
/// contain credentials, message bodies, or other sensitive values.
#[derive(Clone)]
pub struct ProviderExecutionRequest {
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub provider: String,
    pub action: String,
    pub arguments: Value,
    pub argument_hash: Sha256Digest,
    pub resource_claim: ResourceClaim,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub provider_contract_hash: Sha256Digest,
    pub budget_charge: BudgetCharge,
}

pub fn canonical_argument_hash(arguments: &Value) -> Sha256Digest {
    Sha256Digest::from_bytes(&canonical_json_v1(arguments))
}

pub fn canonical_provider_contract_hash(
    provider: &KernelProvider,
) -> Result<Sha256Digest, ProviderContractHashError> {
    #[derive(Serialize)]
    struct ContractMaterial<'a> {
        domain: &'static str,
        provider: &'a KernelProvider,
    }

    let value = serde_json::to_value(ContractMaterial {
        domain: PROVIDER_CONTRACT_DOMAIN_V1,
        provider,
    })
    .map_err(|_| ProviderContractHashError::Encoding)?;
    Ok(Sha256Digest::from_bytes(&canonical_json_v1(&value)))
}

/// Process-authenticated execution capability. Its claims and tag remain
/// private, non-cloneable, non-debuggable, and non-serializable.
pub struct ExecutionPermit {
    claims: PermitClaims,
    authentication_tag: [u8; 32],
}

/// State-independent claims produced only after the durable execution-start
/// boundary. Plan 4 owns the conversion from the journal lease/start records.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermitClaims {
    pub lease_id: ExecutionLeaseId,
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub provider_contract_hash: Sha256Digest,
    pub budget_charge: BudgetCharge,
    pub expires_at: OffsetDateTime,
    pub execution_started_version: u64,
}

/// Namespace for generating one process-local permit authority. It has no
/// public constructor and contains no serializable key material.
pub struct PermitAuthority(());

pub struct PermitIssuer {
    key: Arc<Zeroizing<[u8; 32]>>,
}

pub struct PermitVerifier {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl Clone for PermitIssuer {
    fn clone(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
        }
    }
}

impl Clone for PermitVerifier {
    fn clone(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
        }
    }
}

impl PermitAuthority {
    pub fn generate() -> Result<(PermitIssuer, PermitVerifier), PermitAuthorityError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut key[..]).map_err(|error| {
            PermitAuthorityError::EntropyUnavailable {
                reason: error.to_string(),
            }
        })?;
        let key = Arc::new(key);
        Ok((
            PermitIssuer {
                key: Arc::clone(&key),
            },
            PermitVerifier { key },
        ))
    }
}

impl PermitIssuer {
    pub fn seal(&self, claims: PermitClaims) -> Result<ExecutionPermit, PermitSealError> {
        validate_claim_shape(&claims)?;
        let message = permit_message(&claims)?;
        let mut mac = new_mac(&self.key[..])?;
        mac.update(&message);
        let bytes = mac.finalize().into_bytes();
        let mut authentication_tag = [0_u8; 32];
        authentication_tag.copy_from_slice(&bytes);
        Ok(ExecutionPermit {
            claims,
            authentication_tag,
        })
    }
}

impl PermitVerifier {
    /// Authenticate the capability and bind it to freshly recomputed request
    /// commitments. This method deliberately does not consume a permit.
    /// `DefaultProviderExecutor` must atomically claim an operation before its
    /// first side effect and return the stored reconciliation outcome on a
    /// duplicate call. A restarted process cannot validate the old key, and
    /// Plan 4 must never reissue a permit for recovery of an executing call.
    pub fn validate<'permit>(
        &self,
        permit: &'permit ExecutionPermit,
        request: &ProviderExecutionRequest,
        current_provider: &KernelProvider,
        now: OffsetDateTime,
    ) -> Result<&'permit PermitClaims, PermitValidationError> {
        let message = permit_message(&permit.claims)
            .map_err(|_| PermitValidationError::AuthenticationFailed)?;
        let mut mac =
            new_mac(&self.key[..]).map_err(|_| PermitValidationError::AuthenticationFailed)?;
        mac.update(&message);
        mac.verify_slice(&permit.authentication_tag)
            .map_err(|_| PermitValidationError::AuthenticationFailed)?;

        if now >= permit.claims.expires_at {
            return Err(PermitValidationError::Expired);
        }
        let current_contract_hash = canonical_provider_contract_hash(current_provider)
            .map_err(|_| PermitValidationError::ProviderContractMismatch)?;
        if current_provider.id != request.provider
            || request.provider_contract_hash != permit.claims.provider_contract_hash
            || permit.claims.provider_contract_hash != current_contract_hash
        {
            return Err(PermitValidationError::ProviderContractMismatch);
        }
        if matches!(request.resource_claim, ResourceClaim::OpaqueLegacy { .. }) {
            return Err(PermitValidationError::OpaqueLegacyClaim);
        }
        let computed_argument_hash = canonical_argument_hash(&request.arguments);
        if request.argument_hash != computed_argument_hash
            || permit.claims.argument_hash != computed_argument_hash
        {
            return Err(PermitValidationError::ArgumentHashMismatch);
        }
        let computed_resource_hash = request.resource_claim.digest();
        if request.resource_claim_hash != computed_resource_hash
            || permit.claims.resource_claim_hash != computed_resource_hash
        {
            return Err(PermitValidationError::ResourceClaimHashMismatch);
        }
        if request.budget_charge != permit.claims.budget_charge {
            return Err(PermitValidationError::BudgetChargeMismatch);
        }
        if request.operation_id != permit.claims.operation_id
            || request.story_id != permit.claims.story_id
            || request.session_id != permit.claims.session_id
            || request.provider != permit.claims.provider
            || request.action != permit.claims.action
            || request.policy_snapshot_hash != permit.claims.policy_snapshot_hash
        {
            return Err(PermitValidationError::ContextMismatch);
        }
        if permit.claims.execution_started_version == 0 {
            return Err(PermitValidationError::ExecutionStartMissing);
        }
        if permit.claims.budget_charge.calls == 0 {
            return Err(PermitValidationError::InvalidBudgetCharge);
        }
        Ok(&permit.claims)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderContractHashError {
    #[error("provider contract could not be canonically encoded")]
    Encoding,
}

#[derive(Debug, thiserror::Error)]
pub enum PermitAuthorityError {
    #[error("operating-system entropy is unavailable: {reason}")]
    EntropyUnavailable { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum PermitSealError {
    #[error("permit provider is invalid")]
    InvalidProvider,
    #[error("permit action is invalid")]
    InvalidAction,
    #[error("permit execution-start version must be positive")]
    ExecutionStartMissing,
    #[error("permit call budget must be positive")]
    InvalidBudgetCharge,
    #[error("permit claims could not be encoded")]
    Encoding,
    #[error("permit authentication could not be initialized")]
    Authentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PermitValidationError {
    #[error("execution permit authentication failed")]
    AuthenticationFailed,
    #[error("execution permit is expired")]
    Expired,
    #[error("opaque legacy resource claims are not executable")]
    OpaqueLegacyClaim,
    #[error("canonical argument commitment does not match the permit")]
    ArgumentHashMismatch,
    #[error("resource claim commitment does not match the permit")]
    ResourceClaimHashMismatch,
    #[error("provider contract commitment does not match the permit")]
    ProviderContractMismatch,
    #[error("budget charge does not match the permit")]
    BudgetChargeMismatch,
    #[error("execution request context does not match the permit")]
    ContextMismatch,
    #[error("permit has no durable execution-start version")]
    ExecutionStartMissing,
    #[error("permit has an invalid budget charge")]
    InvalidBudgetCharge,
}

fn validate_claim_shape(claims: &PermitClaims) -> Result<(), PermitSealError> {
    EventCode::try_from(claims.provider.clone()).map_err(|_| PermitSealError::InvalidProvider)?;
    EventCode::try_from(claims.action.clone()).map_err(|_| PermitSealError::InvalidAction)?;
    if claims.execution_started_version == 0 {
        return Err(PermitSealError::ExecutionStartMissing);
    }
    if claims.budget_charge.calls == 0 {
        return Err(PermitSealError::InvalidBudgetCharge);
    }
    Ok(())
}

fn permit_message(claims: &PermitClaims) -> Result<Vec<u8>, PermitSealError> {
    let value = serde_json::to_value(claims).map_err(|_| PermitSealError::Encoding)?;
    let claims = canonical_json_v1(&value);
    let capacity = PERMIT_DOMAIN_V1
        .len()
        .checked_add(claims.len())
        .ok_or(PermitSealError::Encoding)?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(capacity)
        .map_err(|_| PermitSealError::Encoding)?;
    message.extend_from_slice(PERMIT_DOMAIN_V1);
    message.extend_from_slice(&claims);
    Ok(message)
}

fn new_mac(key: &[u8]) -> Result<Hmac<Sha256>, PermitSealError> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| PermitSealError::Authentication)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionResult {
    execution_status: ProviderExecutionStatus,
    side_effect_state: SideEffectState,
    output: SafeProviderOutput,
    output_hash: Option<Sha256Digest>,
    receipt: Option<ExecutionReceipt>,
    error_kind: Option<String>,
    reason_code: Option<String>,
    actual_budget_charge: BudgetCharge,
}

impl ProviderExecutionResult {
    pub fn blocked(error_kind: &str, reason_code: &str) -> Self {
        Self {
            execution_status: ProviderExecutionStatus::NotExecuted,
            side_effect_state: SideEffectState::BlockedBeforeExecution,
            output: SafeProviderOutput::None,
            output_hash: None,
            receipt: None,
            error_kind: Some(stable_code_or(error_kind, INVALID_ERROR_KIND)),
            reason_code: Some(stable_code_or(reason_code, INVALID_REASON_CODE)),
            actual_budget_charge: BudgetCharge {
                calls: 0,
                file_bytes: 0,
                network_bytes: 0,
            },
        }
    }

    pub fn execution_status(&self) -> ProviderExecutionStatus {
        self.execution_status
    }

    pub fn side_effect_state(&self) -> SideEffectState {
        self.side_effect_state
    }

    pub fn output(&self) -> &SafeProviderOutput {
        &self.output
    }

    pub fn output_hash(&self) -> Option<&Sha256Digest> {
        self.output_hash.as_ref()
    }

    pub fn receipt(&self) -> Option<&ExecutionReceipt> {
        self.receipt.as_ref()
    }

    pub fn error_kind(&self) -> Option<&str> {
        self.error_kind.as_deref()
    }

    pub fn reason_code(&self) -> Option<&str> {
        self.reason_code.as_deref()
    }

    pub fn actual_budget_charge(&self) -> BudgetCharge {
        self.actual_budget_charge
    }

    pub fn validate(&self) -> Result<(), ProviderResultValidationError> {
        for value in [self.error_kind.as_deref(), self.reason_code.as_deref()]
            .into_iter()
            .flatten()
        {
            EventCode::try_from(value.to_owned())
                .map_err(|_| ProviderResultValidationError::InvalidCode)?;
        }
        let coherent_state = matches!(
            (self.execution_status, self.side_effect_state),
            (
                ProviderExecutionStatus::NotExecuted,
                SideEffectState::BlockedBeforeExecution,
            ) | (
                ProviderExecutionStatus::FailedBeforeSideEffect,
                SideEffectState::BlockedBeforeExecution | SideEffectState::FailedBeforeSideEffect,
            ) | (
                ProviderExecutionStatus::Completed,
                SideEffectState::Completed,
            ) | (
                ProviderExecutionStatus::ExecutedWithError,
                SideEffectState::ExecutedWithError,
            ) | (
                ProviderExecutionStatus::OutcomeUnknown,
                SideEffectState::OutcomeUnknown,
            ) | (
                ProviderExecutionStatus::Simulated,
                SideEffectState::Simulated,
            )
        );
        if !coherent_state {
            return Err(ProviderResultValidationError::IncoherentState);
        }
        let no_claimed_output = matches!(
            self.execution_status,
            ProviderExecutionStatus::NotExecuted
                | ProviderExecutionStatus::FailedBeforeSideEffect
                | ProviderExecutionStatus::OutcomeUnknown
        );
        if no_claimed_output
            && (!matches!(self.output, SafeProviderOutput::None) || self.output_hash.is_some())
        {
            return Err(ProviderResultValidationError::UnexpectedOutput);
        }
        if no_claimed_output && self.receipt.is_some() {
            return Err(ProviderResultValidationError::UnexpectedReceipt);
        }
        let before_side_effect = matches!(
            self.execution_status,
            ProviderExecutionStatus::NotExecuted | ProviderExecutionStatus::FailedBeforeSideEffect
        );
        if before_side_effect
            && (self.actual_budget_charge.calls != 0
                || self.actual_budget_charge.file_bytes != 0
                || self.actual_budget_charge.network_bytes != 0)
        {
            return Err(ProviderResultValidationError::InvalidBudgetCharge);
        }
        if matches!(
            self.execution_status,
            ProviderExecutionStatus::Completed | ProviderExecutionStatus::ExecutedWithError
        ) && self.actual_budget_charge.calls == 0
        {
            return Err(ProviderResultValidationError::InvalidBudgetCharge);
        }
        if self.execution_status == ProviderExecutionStatus::Simulated
            && (self.actual_budget_charge.calls != 0
                || self.actual_budget_charge.file_bytes != 0
                || self.actual_budget_charge.network_bytes != 0)
        {
            return Err(ProviderResultValidationError::InvalidBudgetCharge);
        }
        if self.execution_status == ProviderExecutionStatus::Completed {
            if self.error_kind.is_some() {
                return Err(ProviderResultValidationError::UnexpectedErrorKind);
            }
        } else if self.reason_code.is_none() {
            return Err(ProviderResultValidationError::MissingReasonCode);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        reserved: BudgetCharge,
    ) -> Result<(), ProviderResultValidationError> {
        self.validate()?;
        if self.actual_budget_charge.calls > reserved.calls
            || self.actual_budget_charge.file_bytes > reserved.file_bytes
            || self.actual_budget_charge.network_bytes > reserved.network_bytes
        {
            return Err(ProviderResultValidationError::BudgetExceedsReservation);
        }
        if self.execution_status == ProviderExecutionStatus::OutcomeUnknown
            && self.actual_budget_charge != reserved
        {
            return Err(ProviderResultValidationError::UnknownBudgetMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderResultValidationError {
    #[error("provider result status and side-effect state are incoherent")]
    IncoherentState,
    #[error("provider result contains an invalid stable code")]
    InvalidCode,
    #[error("pre-side-effect result unexpectedly contains output")]
    UnexpectedOutput,
    #[error("pre-side-effect result unexpectedly contains a receipt")]
    UnexpectedReceipt,
    #[error("pre-side-effect result unexpectedly consumes budget")]
    InvalidBudgetCharge,
    #[error("provider result budget exceeds the execution permit reservation")]
    BudgetExceedsReservation,
    #[error("unknown provider outcome must conservatively charge the full reservation")]
    UnknownBudgetMismatch,
    #[error("failed provider result is missing a stable reason code")]
    MissingReasonCode,
    #[error("completed provider result unexpectedly contains an error kind")]
    UnexpectedErrorKind,
}

fn stable_code_or(value: &str, fallback: &'static str) -> String {
    EventCode::try_from(value.to_owned())
        .map(String::from)
        .unwrap_or_else(|_| fallback.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub operation_id: OperationId,
    pub kind: String,
    pub relative_path: WorkspaceRelativePath,
    pub sha256: Sha256Digest,
}

pub struct ProviderExecutionOutcome {
    pub result: ProviderExecutionResult,
    pub cleanup: Option<CleanupToken>,
}

pub struct CleanupToken {
    _id: String,
    _provider: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupDisposition {
    ResultCommitted,
    JournalFailedRetainForReconcile,
}

#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    #[error("unknown cleanup token")]
    UnknownToken,
    #[error("cleanup token/provider mismatch")]
    ProviderMismatch,
    #[error("cleanup failed: {reason_code}")]
    Failed { reason_code: String },
}

pub enum ReconciliationResult {
    Completed(Box<ProviderExecutionResult>),
    NotExecuted,
    Unknown,
}

pub trait ProviderExecutor: Send + Sync {
    /// Implementors must validate first and atomically claim the permit's
    /// operation before touching files, processes, DNS, sockets, or receipts.
    /// A duplicate call returns reconciliation state; it never repeats the
    /// backend side effect.
    fn execute(
        &self,
        permit: &ExecutionPermit,
        request: &ProviderExecutionRequest,
        now: OffsetDateTime,
    ) -> ProviderExecutionOutcome;

    fn reconcile(&self, operation_id: OperationId) -> ReconciliationResult;

    fn finalize_cleanup(
        &self,
        token: CleanupToken,
        disposition: CleanupDisposition,
    ) -> Result<(), CleanupError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use runwarden_kernel::contracts::{ProviderClass, ProviderKind, ProviderRisk, SideEffectKind};
    use runwarden_kernel::resource::{DataClass, ResourceClaim};
    use time::Duration;

    fn fixed_provider() -> KernelProvider {
        KernelProvider {
            id: "external.email.send".to_owned(),
            class: ProviderClass::External,
            kind: ProviderKind::Plugin,
            risk: ProviderRisk::NetworkActive,
            side_effects: vec![SideEffectKind::Network],
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: serde_json::json!({"type":"object"}),
            evidence_contract: serde_json::json!({"obs_refs_required":true}),
            authority_requirements: serde_json::json!({"approval_required":true}),
        }
    }

    fn fixed_request() -> ProviderExecutionRequest {
        let arguments = serde_json::json!({"to":["reviewer@example.test"]});
        let resource_claim = ResourceClaim::Email {
            recipients: vec!["reviewer@example.test".to_owned()],
            classification: DataClass::Internal,
        };
        ProviderExecutionRequest {
            operation_id: OperationId::new(),
            story_id: StoryId::new(),
            session_id: SessionId::new(),
            provider: "external.email.send".to_owned(),
            action: "send".to_owned(),
            argument_hash: canonical_argument_hash(&arguments),
            arguments,
            resource_claim_hash: resource_claim.digest(),
            resource_claim,
            policy_snapshot_hash: Sha256Digest::from_bytes(b"policy"),
            provider_contract_hash: canonical_provider_contract_hash(&fixed_provider()).unwrap(),
            budget_charge: BudgetCharge {
                calls: 1,
                file_bytes: 0,
                network_bytes: 0,
            },
        }
    }

    #[test]
    fn direct_authentication_tag_forgery_is_rejected() {
        let request = fixed_request();
        let now = OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap();
        let claims = PermitClaims {
            lease_id: ExecutionLeaseId::new(),
            operation_id: request.operation_id,
            story_id: request.story_id,
            session_id: request.session_id,
            provider: request.provider.clone(),
            action: request.action.clone(),
            argument_hash: request.argument_hash.clone(),
            resource_claim_hash: request.resource_claim_hash.clone(),
            policy_snapshot_hash: request.policy_snapshot_hash.clone(),
            provider_contract_hash: request.provider_contract_hash.clone(),
            budget_charge: request.budget_charge,
            expires_at: now + Duration::minutes(1),
            execution_started_version: 2,
        };
        let key = Arc::new(Zeroizing::new([7_u8; 32]));
        let issuer = PermitIssuer {
            key: Arc::clone(&key),
        };
        let verifier = PermitVerifier { key };
        let mut permit = issuer.seal(claims).unwrap();
        permit.authentication_tag[0] ^= 1;
        assert!(matches!(
            verifier.validate(&permit, &request, &fixed_provider(), now),
            Err(PermitValidationError::AuthenticationFailed)
        ));
    }

    #[test]
    fn contradictory_provider_result_is_rejected_inside_the_trusted_crate() {
        let mut result =
            ProviderExecutionResult::blocked("sandbox_unavailable", "sandbox_not_installed");
        result.side_effect_state = SideEffectState::Completed;
        assert_eq!(
            result.validate(),
            Err(ProviderResultValidationError::IncoherentState)
        );
    }

    #[test]
    fn executed_and_unknown_results_enforce_reserved_budget_and_evidence_shape() {
        let mut completed =
            ProviderExecutionResult::blocked("provider_error", "provider_completed");
        completed.execution_status = ProviderExecutionStatus::Completed;
        completed.side_effect_state = SideEffectState::Completed;
        completed.error_kind = None;
        assert_eq!(
            completed.validate(),
            Err(ProviderResultValidationError::InvalidBudgetCharge)
        );
        completed.actual_budget_charge.calls = 2;
        assert_eq!(
            completed.validate_against(BudgetCharge {
                calls: 1,
                file_bytes: 0,
                network_bytes: 0,
            }),
            Err(ProviderResultValidationError::BudgetExceedsReservation)
        );

        let mut unknown =
            ProviderExecutionResult::blocked("provider_error", "provider_outcome_unknown");
        unknown.execution_status = ProviderExecutionStatus::OutcomeUnknown;
        unknown.side_effect_state = SideEffectState::OutcomeUnknown;
        unknown.actual_budget_charge.calls = 1;
        unknown.output_hash = Some(Sha256Digest::from_bytes(b"unsupported-output"));
        assert_eq!(
            unknown.validate(),
            Err(ProviderResultValidationError::UnexpectedOutput)
        );
        unknown.output_hash = None;
        assert_eq!(
            unknown.validate_against(BudgetCharge {
                calls: 2,
                file_bytes: 0,
                network_bytes: 0,
            }),
            Err(ProviderResultValidationError::UnknownBudgetMismatch)
        );
    }
}
