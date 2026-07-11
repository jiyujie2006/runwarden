//! Non-side-effecting baseline observation for policy A/B evaluation.

use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::operation::SideEffectState;
use runwarden_kernel::resource::{FileAccess, MemoryAccess, ResourceClaim};
use runwarden_kernel::resource_binding::resource_proposal_commitment;
use runwarden_kernel::trace::{EventCode, Sha256Digest};
use serde::Serialize;

use super::{ProviderExecutionRequest, canonical_argument_hash, canonical_provider_contract_hash};
use crate::catalog::full_provider_registry;

const INVALID_PROVIDER: &str = "invalid_provider";
const INVALID_ACTION: &str = "invalid_action";
const PROVIDER_UNKNOWN: &str = "provider_unknown";
const PROVIDER_CONTRACT_MISMATCH: &str = "provider_contract_mismatch";
const ARGUMENT_HASH_MISMATCH: &str = "argument_hash_mismatch";
const INVALID_ARGUMENTS: &str = "invalid_arguments";
const RESOURCE_CLAIM_HASH_MISMATCH: &str = "resource_claim_hash_mismatch";
const OPAQUE_LEGACY_CLAIM: &str = "opaque_legacy_claim";
const INVALID_BUDGET_CHARGE: &str = "invalid_budget_charge";
const CLAIM_FAMILY_MISMATCH: &str = "claim_family_mismatch";
const EVALUATION_RESOURCE_MISMATCH: &str = "evaluation_resource_mismatch";
const EVALUATION_POLICY_MISMATCH: &str = "evaluation_policy_mismatch";
const EVALUATION_CHARGE_MISMATCH: &str = "evaluation_charge_mismatch";
const EVALUATION_PROPOSAL_MISMATCH: &str = "evaluation_proposal_mismatch";
const EVALUATION_BINDING_UNVERIFIED: &str = "evaluation_binding_unverified";
const EXTRACTOR_NOT_REGISTERED: &str = "extractor_not_registered";
const UNSUPPORTED_ACTION: &str = "unsupported_action";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum BaselineDisposition {
    SimulatedWouldExecute,
    NotExecutable { reason_code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatedEffect {
    pub provider_id: String,
    pub action: String,
    pub resource_claim_digest: Sha256Digest,
    pub arguments_commitment: Sha256Digest,
    pub effect_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorObservation {
    pub shadow_policy_decision: PolicyDecision,
    pub baseline_disposition: BaselineDisposition,
    pub simulated_effect: Option<SimulatedEffect>,
    pub side_effect_state: SideEffectState,
    pub resource_claim: ResourceClaim,
}

pub trait MonitorObserver {
    fn observe(
        &self,
        evaluation: &runwarden_kernel::policy::PolicyEvaluation,
        request: &ProviderExecutionRequest,
    ) -> MonitorObservation;
}

/// Stateless counterfactual observer. It owns no capability and cannot
/// delegate to any side-effecting implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct MonitorOnlyObserver;

impl MonitorObserver for MonitorOnlyObserver {
    fn observe(
        &self,
        evaluation: &runwarden_kernel::policy::PolicyEvaluation,
        request: &ProviderExecutionRequest,
    ) -> MonitorObservation {
        match validate_proposal(evaluation, request) {
            Ok(effect_kind) => MonitorObservation {
                shadow_policy_decision: evaluation.decision.clone(),
                baseline_disposition: BaselineDisposition::SimulatedWouldExecute,
                simulated_effect: Some(SimulatedEffect {
                    provider_id: request.provider.clone(),
                    action: request.action.clone(),
                    resource_claim_digest: request.resource_claim_hash.clone(),
                    arguments_commitment: request.argument_hash.clone(),
                    effect_kind: effect_kind.to_owned(),
                }),
                side_effect_state: SideEffectState::Simulated,
                resource_claim: request.resource_claim.clone(),
            },
            Err(reason_code) => not_executable(evaluation, request, reason_code),
        }
    }
}

fn validate_proposal(
    evaluation: &runwarden_kernel::policy::PolicyEvaluation,
    request: &ProviderExecutionRequest,
) -> Result<&'static str, &'static str> {
    if EventCode::try_from(request.provider.clone()).is_err() {
        return Err(INVALID_PROVIDER);
    }
    if EventCode::try_from(request.action.clone()).is_err() {
        return Err(INVALID_ACTION);
    }

    let catalog = full_provider_registry();
    let provider = catalog.get(&request.provider).ok_or(PROVIDER_UNKNOWN)?;
    let current_contract_hash =
        canonical_provider_contract_hash(provider).map_err(|_| PROVIDER_CONTRACT_MISMATCH)?;
    if request.provider_contract_hash != current_contract_hash {
        return Err(PROVIDER_CONTRACT_MISMATCH);
    }
    if request.argument_hash != canonical_argument_hash(&request.arguments) {
        return Err(ARGUMENT_HASH_MISMATCH);
    }
    if request
        .arguments
        .as_object()
        .is_none_or(|arguments| arguments.is_empty())
    {
        return Err(INVALID_ARGUMENTS);
    }
    if matches!(request.resource_claim, ResourceClaim::OpaqueLegacy { .. }) {
        return Err(OPAQUE_LEGACY_CLAIM);
    }
    if request.resource_claim_hash != request.resource_claim.digest() {
        return Err(RESOURCE_CLAIM_HASH_MISMATCH);
    }
    if request.budget_charge.calls != 1 {
        return Err(INVALID_BUDGET_CHARGE);
    }

    let (expected_action, effect_kind, claim_family) =
        expected_proposal_shape(&request.provider).ok_or(EXTRACTOR_NOT_REGISTERED)?;
    if request.action != expected_action {
        return Err(UNSUPPORTED_ACTION);
    }
    if !claim_family.matches(&request.resource_claim) {
        return Err(CLAIM_FAMILY_MISMATCH);
    }

    if evaluation.resource_claim_hash != request.resource_claim_hash {
        return Err(EVALUATION_RESOURCE_MISMATCH);
    }
    if evaluation.policy_snapshot_hash != request.policy_snapshot_hash {
        return Err(EVALUATION_POLICY_MISMATCH);
    }
    if evaluation.budget_charge != request.budget_charge {
        return Err(EVALUATION_CHARGE_MISMATCH);
    }
    if !evaluation.proposal_binding_verified {
        return Err(EVALUATION_BINDING_UNVERIFIED);
    }
    let proposal_commitment = resource_proposal_commitment(
        provider,
        &request.action,
        &request.arguments,
        &request.resource_claim,
        &request.budget_charge,
    );
    if evaluation.proposal_commitment != proposal_commitment {
        return Err(EVALUATION_PROPOSAL_MISMATCH);
    }

    Ok(effect_kind)
}

#[derive(Clone, Copy)]
enum ClaimFamily {
    File(FileAccess),
    Network,
    Browser,
    Email,
    Memory(MemoryAccess),
    InputInspection,
}

impl ClaimFamily {
    fn matches(self, claim: &ResourceClaim) -> bool {
        match (self, claim) {
            (ClaimFamily::File(expected), ResourceClaim::File { access, .. }) => {
                *access == expected
            }
            (ClaimFamily::Network, ResourceClaim::Network { method, origin, .. }) => {
                !method.is_empty() && !origin.is_empty()
            }
            (ClaimFamily::Browser, ResourceClaim::Network { method, origin, .. }) => {
                method == "GET" && !origin.is_empty()
            }
            (ClaimFamily::Email, ResourceClaim::Email { recipients, .. }) => !recipients.is_empty(),
            (ClaimFamily::Memory(expected), ResourceClaim::Memory { access, .. }) => {
                *access == expected
            }
            (ClaimFamily::InputInspection, ResourceClaim::InputInspection { source, .. }) => {
                source == "tool_input"
            }
            _ => false,
        }
    }
}

fn expected_proposal_shape(provider: &str) -> Option<(&'static str, &'static str, ClaimFamily)> {
    match provider {
        "external.mcp.filesystem.read_file" => Some((
            "read_file",
            "file_read",
            ClaimFamily::File(FileAccess::Read),
        )),
        "external.mcp.filesystem.write_file" => Some((
            "write_file",
            "file_write",
            ClaimFamily::File(FileAccess::Write),
        )),
        "external.email.send" => Some(("send", "email_send", ClaimFamily::Email)),
        "external.api.request" => Some(("request", "network_request", ClaimFamily::Network)),
        "external.mcp.browser.open_page" => {
            Some(("open_page", "browser_open_page", ClaimFamily::Browser))
        }
        "external.memory.read" => Some((
            "read",
            "memory_read",
            ClaimFamily::Memory(MemoryAccess::Read),
        )),
        "external.memory.write" => Some((
            "write",
            "memory_write",
            ClaimFamily::Memory(MemoryAccess::Write),
        )),
        "external.knowledge.read" => Some((
            "read",
            "knowledge_read",
            ClaimFamily::Memory(MemoryAccess::Read),
        )),
        "external.knowledge.write" => Some((
            "write",
            "knowledge_write",
            ClaimFamily::Memory(MemoryAccess::Write),
        )),
        "runwarden.input.inspect" => {
            Some(("inspect", "input_inspection", ClaimFamily::InputInspection))
        }
        _ => None,
    }
}

fn not_executable(
    evaluation: &runwarden_kernel::policy::PolicyEvaluation,
    request: &ProviderExecutionRequest,
    reason_code: &'static str,
) -> MonitorObservation {
    debug_assert!(EventCode::try_from(reason_code.to_owned()).is_ok());
    MonitorObservation {
        shadow_policy_decision: evaluation.decision.clone(),
        baseline_disposition: BaselineDisposition::NotExecutable {
            reason_code: reason_code.to_owned(),
        },
        simulated_effect: None,
        side_effect_state: SideEffectState::NotAttempted,
        resource_claim: request.resource_claim.clone(),
    }
}
