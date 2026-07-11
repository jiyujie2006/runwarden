//! Process-authenticated binding between extraction inputs and a typed claim.

use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::contracts::KernelProvider;
use crate::resource::{ResourceClaim, canonical_provider_contract_hash};
use crate::session::BudgetCharge;
use crate::story::EnforcementMode;
use crate::trace::{EventCode, Sha256Digest, canonical_json_v1};

const RESOURCE_BINDING_DOMAIN_V1: &[u8] = b"runwarden.resource-binding.hmac-sha256.v1\0";
const RESOURCE_PROPOSAL_DOMAIN_V1: &[u8] = b"runwarden.resource-proposal.sha256.v1\0";

/// Namespace for creating one process-local extraction-binding authority.
/// There is intentionally no constructor that accepts caller-provided key
/// material.
pub struct ResourceBindingAuthority(());

/// Trusted capability held by the provider extractor boundary.
pub struct ResourceBindingIssuer {
    key: Arc<Zeroizing<[u8; 32]>>,
}

/// Verification capability held by an immutable policy session context.
pub struct ResourceBindingVerifier {
    key: Arc<Zeroizing<[u8; 32]>>,
}

/// Opaque authentication proof. It exposes no claims and cannot be copied,
/// logged, debug-formatted, or serialized.
pub struct ResourceBindingProof {
    authentication_tag: [u8; 32],
}

impl Clone for ResourceBindingIssuer {
    fn clone(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
        }
    }
}

impl Clone for ResourceBindingVerifier {
    fn clone(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
        }
    }
}

impl fmt::Debug for ResourceBindingIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceBindingIssuer")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for ResourceBindingVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResourceBindingVerifier")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl ResourceBindingAuthority {
    pub fn generate()
    -> Result<(ResourceBindingIssuer, ResourceBindingVerifier), ResourceBindingAuthorityError> {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut key[..])
            .map_err(|_| ResourceBindingAuthorityError::EntropyUnavailable)?;
        let key = Arc::new(key);
        Ok((
            ResourceBindingIssuer {
                key: Arc::clone(&key),
            },
            ResourceBindingVerifier { key },
        ))
    }
}

impl ResourceBindingIssuer {
    pub fn seal(
        &self,
        provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        claim: &ResourceClaim,
        budget_charge: &BudgetCharge,
        enforcement_mode: EnforcementMode,
    ) -> Result<ResourceBindingProof, ResourceBindingSealError> {
        validate_public_codes(provider, action)?;
        let message = binding_message(
            provider,
            action,
            arguments,
            claim,
            budget_charge,
            enforcement_mode,
        )?;
        let mut mac = new_mac(&self.key[..])?;
        mac.update(&message);
        let bytes = mac.finalize().into_bytes();
        let mut authentication_tag = [0_u8; 32];
        authentication_tag.copy_from_slice(&bytes);
        Ok(ResourceBindingProof { authentication_tag })
    }
}

impl ResourceBindingVerifier {
    /// Recomputes the complete expected extraction tuple and authenticates it
    /// in constant time. Every mismatch deliberately has the same public
    /// result so callers cannot use the verifier as a proof oracle.
    #[allow(clippy::too_many_arguments)] // Exact tuple mirrors `seal` and prevents partial checks.
    pub fn validate(
        &self,
        proof: &ResourceBindingProof,
        provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        claim: &ResourceClaim,
        budget_charge: &BudgetCharge,
        enforcement_mode: EnforcementMode,
    ) -> Result<(), ResourceBindingValidationError> {
        let message = binding_message(
            provider,
            action,
            arguments,
            claim,
            budget_charge,
            enforcement_mode,
        )
        .map_err(|_| ResourceBindingValidationError::AuthenticationFailed)?;
        let mut mac = new_mac(&self.key[..])
            .map_err(|_| ResourceBindingValidationError::AuthenticationFailed)?;
        mac.update(&message);
        mac.verify_slice(&proof.authentication_tag)
            .map_err(|_| ResourceBindingValidationError::AuthenticationFailed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceBindingAuthorityError {
    #[error("operating-system entropy is unavailable")]
    EntropyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceBindingSealError {
    #[error("resource binding provider id is invalid")]
    InvalidProvider,
    #[error("resource binding action is invalid")]
    InvalidAction,
    #[error("resource binding material could not be encoded")]
    Encoding,
    #[error("resource binding authentication could not be initialized")]
    Authentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResourceBindingValidationError {
    #[error("resource binding authentication failed")]
    AuthenticationFailed,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceProposalMaterial<'a> {
    provider_contract_hash: Sha256Digest,
    provider: &'a str,
    action: &'a str,
    argument_hash: Sha256Digest,
    resource_claim_hash: Sha256Digest,
    budget_charge: BudgetCharge,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceBindingMaterial {
    proposal_commitment: Sha256Digest,
    enforcement_mode: EnforcementMode,
}

/// Stable, non-authorizing commitment used to prove that a policy evaluation
/// and a monitor observation describe the same complete provider proposal.
pub fn resource_proposal_commitment(
    provider: &KernelProvider,
    action: &str,
    arguments: &Value,
    claim: &ResourceClaim,
    budget_charge: &BudgetCharge,
) -> Sha256Digest {
    resource_proposal_commitment_from_hashes(
        canonical_provider_contract_hash(provider),
        provider.id.as_str(),
        action,
        Sha256Digest::from_bytes(&canonical_json_v1(arguments)),
        claim.digest(),
        *budget_charge,
    )
}

/// Reconstruct the proposal commitment from already-validated durable
/// components. This lets the journal detect contract or budget drift without
/// retaining raw arguments or a second provider catalog.
pub fn resource_proposal_commitment_from_hashes(
    provider_contract_hash: Sha256Digest,
    provider: &str,
    action: &str,
    argument_hash: Sha256Digest,
    resource_claim_hash: Sha256Digest,
    budget_charge: BudgetCharge,
) -> Sha256Digest {
    let material = ResourceProposalMaterial {
        provider_contract_hash,
        provider,
        action,
        argument_hash,
        resource_claim_hash,
        budget_charge,
    };
    let value = serde_json::to_value(material).expect("resource proposal material serializes");
    let encoded = canonical_json_v1(&value);
    let mut domain_separated = Vec::new();
    domain_separated.extend_from_slice(RESOURCE_PROPOSAL_DOMAIN_V1);
    domain_separated.extend_from_slice(&encoded);
    Sha256Digest::from_bytes(&domain_separated)
}

fn validate_public_codes(
    provider: &KernelProvider,
    action: &str,
) -> Result<(), ResourceBindingSealError> {
    EventCode::try_from(provider.id.clone())
        .map_err(|_| ResourceBindingSealError::InvalidProvider)?;
    EventCode::try_from(action.to_owned()).map_err(|_| ResourceBindingSealError::InvalidAction)?;
    Ok(())
}

fn binding_message(
    provider: &KernelProvider,
    action: &str,
    arguments: &Value,
    claim: &ResourceClaim,
    budget_charge: &BudgetCharge,
    enforcement_mode: EnforcementMode,
) -> Result<Vec<u8>, ResourceBindingSealError> {
    let material = ResourceBindingMaterial {
        proposal_commitment: resource_proposal_commitment(
            provider,
            action,
            arguments,
            claim,
            budget_charge,
        ),
        enforcement_mode,
    };
    let value = serde_json::to_value(material).map_err(|_| ResourceBindingSealError::Encoding)?;
    let encoded = canonical_json_v1(&value);
    let capacity = RESOURCE_BINDING_DOMAIN_V1
        .len()
        .checked_add(encoded.len())
        .ok_or(ResourceBindingSealError::Encoding)?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(capacity)
        .map_err(|_| ResourceBindingSealError::Encoding)?;
    message.extend_from_slice(RESOURCE_BINDING_DOMAIN_V1);
    message.extend_from_slice(&encoded);
    Ok(message)
}

fn new_mac(key: &[u8]) -> Result<Hmac<Sha256>, ResourceBindingSealError> {
    <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| ResourceBindingSealError::Authentication)
}
