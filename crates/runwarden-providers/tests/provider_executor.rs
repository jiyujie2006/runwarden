use runwarden_kernel::contracts::{
    KernelProvider, ProviderClass, ProviderKind, ProviderRisk, SideEffectKind,
};
use runwarden_kernel::operation::{ProviderExecutionStatus, SafeProviderOutput, SideEffectState};
use runwarden_kernel::resource::{DataClass, ResourceClaim};
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ExecutionLeaseId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::executor::{
    PermitAuthority, PermitClaims, PermitValidationError, ProviderExecutionRequest,
    ProviderExecutionResult, canonical_argument_hash, canonical_provider_contract_hash,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
}

fn provider() -> KernelProvider {
    KernelProvider {
        id: "external.email.send".to_owned(),
        class: ProviderClass::External,
        kind: ProviderKind::Plugin,
        risk: ProviderRisk::NetworkActive,
        side_effects: vec![SideEffectKind::Network],
        input_schema: json!({"type":"object"}),
        output_schema: json!({"type":"object"}),
        evidence_contract: json!({"obs_refs_required":true}),
        authority_requirements: json!({"approval_required":true}),
    }
}

fn request_fixture() -> ProviderExecutionRequest {
    let arguments = json!({
        "subject": "Q2",
        "to": ["finance@example.test"]
    });
    let resource_claim = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
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
        policy_snapshot_hash: Sha256Digest::from_bytes(b"permit-policy"),
        provider_contract_hash: canonical_provider_contract_hash(&provider()).unwrap(),
        budget_charge: BudgetCharge {
            calls: 1,
            file_bytes: 0,
            network_bytes: 0,
        },
    }
}

fn claims(request: &ProviderExecutionRequest) -> PermitClaims {
    PermitClaims {
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
        expires_at: fixed_now() + Duration::minutes(5),
        execution_started_version: 3,
    }
}

#[test]
fn permit_accepts_only_the_canonical_frozen_arguments() {
    let request = request_fixture();
    let provider = provider();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let permit = issuer.seal(claims(&request)).unwrap();
    assert!(
        verifier
            .validate(&permit, &request, &provider, fixed_now())
            .is_ok()
    );
    assert!(
        verifier
            .validate(&permit, &request, &provider, fixed_now())
            .is_ok(),
        "validation authenticates but does not itself execute or consume"
    );

    let changed = ProviderExecutionRequest {
        arguments: json!({
            "subject": "Q2",
            "to": ["attacker@example.test"]
        }),
        ..request
    };
    assert!(matches!(
        verifier.validate(&permit, &changed, &provider, fixed_now()),
        Err(PermitValidationError::ArgumentHashMismatch)
    ));
}

#[test]
fn permit_recomputes_claim_digest_and_binds_charge_and_provider_contract() {
    let request = request_fixture();
    let provider = provider();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let permit = issuer.seal(claims(&request)).unwrap();

    let changed_claim = ProviderExecutionRequest {
        resource_claim: ResourceClaim::Email {
            recipients: vec!["attacker@example.test".to_owned()],
            classification: DataClass::Internal,
        },
        ..request.clone()
    };
    assert!(matches!(
        verifier.validate(&permit, &changed_claim, &provider, fixed_now()),
        Err(PermitValidationError::ResourceClaimHashMismatch)
    ));

    let changed_charge = ProviderExecutionRequest {
        budget_charge: BudgetCharge {
            calls: 2,
            ..request.budget_charge
        },
        ..request.clone()
    };
    assert!(matches!(
        verifier.validate(&permit, &changed_charge, &provider, fixed_now()),
        Err(PermitValidationError::BudgetChargeMismatch)
    ));

    let changed_contract = ProviderExecutionRequest {
        provider_contract_hash: Sha256Digest::from_bytes(b"forged-low-risk-contract"),
        ..request
    };
    assert!(matches!(
        verifier.validate(&permit, &changed_contract, &provider, fixed_now()),
        Err(PermitValidationError::ProviderContractMismatch)
    ));

    let mut downgraded_provider = provider.clone();
    downgraded_provider.risk = ProviderRisk::Low;
    downgraded_provider.side_effects.clear();
    let mutually_downgraded_request = ProviderExecutionRequest {
        provider_contract_hash: canonical_provider_contract_hash(&downgraded_provider).unwrap(),
        ..request_fixture()
    };
    let mutually_downgraded_permit = issuer.seal(claims(&mutually_downgraded_request)).unwrap();
    assert!(matches!(
        verifier.validate(
            &mutually_downgraded_permit,
            &mutually_downgraded_request,
            &provider,
            fixed_now(),
        ),
        Err(PermitValidationError::ProviderContractMismatch)
    ));
}

#[test]
fn permit_rejects_another_process_authority_and_the_exact_expiry_boundary() {
    let request = request_fixture();
    let provider = provider();
    let permit_claims = claims(&request);
    let expiry = permit_claims.expires_at;
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let permit = issuer.seal(permit_claims).unwrap();
    let (_, other_verifier) = PermitAuthority::generate().unwrap();

    assert!(matches!(
        other_verifier.validate(&permit, &request, &provider, fixed_now()),
        Err(PermitValidationError::AuthenticationFailed)
    ));
    assert!(matches!(
        verifier.validate(&permit, &request, &provider, expiry),
        Err(PermitValidationError::Expired)
    ));
}

#[test]
fn permit_rejects_opaque_legacy_and_context_substitution() {
    let request = request_fixture();
    let provider = provider();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let permit = issuer.seal(claims(&request)).unwrap();
    let opaque = ProviderExecutionRequest {
        resource_claim: ResourceClaim::OpaqueLegacy {
            provider: request.provider.clone(),
            redacted_summary: "legacy display only".to_owned(),
        },
        ..request.clone()
    };
    assert!(matches!(
        verifier.validate(&permit, &opaque, &provider, fixed_now()),
        Err(PermitValidationError::OpaqueLegacyClaim)
    ));

    let substituted = ProviderExecutionRequest {
        operation_id: OperationId::new(),
        ..request
    };
    assert!(matches!(
        verifier.validate(&permit, &substituted, &provider, fixed_now()),
        Err(PermitValidationError::ContextMismatch)
    ));
}

#[test]
fn provider_result_uses_authoritative_blocked_state_and_stable_codes() {
    let result = ProviderExecutionResult::blocked("sandbox_unavailable", "sandbox_not_installed");
    assert_eq!(
        result.execution_status(),
        ProviderExecutionStatus::NotExecuted
    );
    assert_eq!(
        result.side_effect_state(),
        SideEffectState::BlockedBeforeExecution
    );
    assert!(!result.side_effect_state().was_executed());
    assert_eq!(result.output(), &SafeProviderOutput::None);
    assert_eq!(result.error_kind(), Some("sandbox_unavailable"));
    assert_eq!(result.reason_code(), Some("sandbox_not_installed"));
    result.validate().unwrap();
    result
        .validate_against(BudgetCharge {
            calls: 1,
            file_bytes: 0,
            network_bytes: 0,
        })
        .unwrap();

    let sanitized = ProviderExecutionResult::blocked(
        "raw exception with spaces",
        "authorization: Bearer should never enter evidence",
    );
    assert_eq!(sanitized.error_kind(), Some("invalid_error_kind"));
    assert_eq!(sanitized.reason_code(), Some("invalid_reason_code"));
    sanitized.validate().unwrap();
}
