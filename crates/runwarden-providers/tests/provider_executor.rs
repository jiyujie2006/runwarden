use std::fs;
use std::time::Duration as StdDuration;

use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::contracts::{
    KernelProvider, PolicyDecision, ProviderClass, ProviderKind, ProviderRisk, SideEffectKind,
};
use runwarden_kernel::operation::{ProviderExecutionStatus, SafeProviderOutput, SideEffectState};
use runwarden_kernel::policy::PolicyEvaluation;
use runwarden_kernel::resource::{
    DataClass, ExecutionLimits, FileAccess, MemoryAccess, NetworkCapability, ResourceClaim,
};
use runwarden_kernel::resource_binding::resource_proposal_commitment;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ExecutionLeaseId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::{EventCode, Sha256Digest};
use runwarden_providers::catalog::full_provider_registry;
use runwarden_providers::executor::{
    BaselineDisposition, DefaultProviderExecutor, ExecutorConfig, MonitorObservation,
    MonitorObserver, MonitorOnlyObserver, PermitAuthority, PermitClaims, PermitIssuer,
    PermitValidationError, ProviderExecutionOutcome, ProviderExecutionRequest,
    ProviderExecutionResult, ProviderExecutor, ReconciliationResult, canonical_argument_hash,
    canonical_provider_contract_hash,
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

fn catalog_provider(provider_id: &str) -> KernelProvider {
    full_provider_registry()
        .get(provider_id)
        .unwrap_or_else(|| panic!("provider is missing from the Rust catalog: {provider_id}"))
        .clone()
}

fn catalog_email_request() -> ProviderExecutionRequest {
    request_for(
        &catalog_provider("external.email.send"),
        "send",
        json!({
            "to": ["finance@example.test"],
            "subject": "Q2",
            "body": "Quarterly review"
        }),
        ResourceClaim::Email {
            recipients: vec!["finance@example.test".to_owned()],
            classification: DataClass::Internal,
        },
    )
}

fn request_for(
    provider: &KernelProvider,
    action: &str,
    arguments: serde_json::Value,
    resource_claim: ResourceClaim,
) -> ProviderExecutionRequest {
    let file_bytes = u64::from(provider.side_effects.iter().any(|effect| {
        matches!(
            effect,
            SideEffectKind::FileRead | SideEffectKind::FileWrite | SideEffectKind::ArtifactWrite
        )
    })) * 4_096;
    let network_bytes = u64::from(provider.side_effects.contains(&SideEffectKind::Network)) * 4_096;
    ProviderExecutionRequest {
        operation_id: OperationId::new(),
        story_id: StoryId::new(),
        session_id: SessionId::new(),
        provider: provider.id.clone(),
        action: action.to_owned(),
        argument_hash: canonical_argument_hash(&arguments),
        arguments,
        resource_claim_hash: resource_claim.digest(),
        resource_claim,
        policy_snapshot_hash: Sha256Digest::from_bytes(b"monitor-policy-a"),
        provider_contract_hash: canonical_provider_contract_hash(provider).unwrap(),
        budget_charge: BudgetCharge {
            calls: 1,
            file_bytes,
            network_bytes,
        },
    }
}

fn evaluation_for(
    request: &ProviderExecutionRequest,
    decision: PolicyDecision,
) -> PolicyEvaluation {
    let proposal_commitment = full_provider_registry()
        .get(&request.provider)
        .map(|provider| {
            resource_proposal_commitment(
                provider,
                &request.action,
                &request.arguments,
                &request.resource_claim,
                &request.budget_charge,
            )
        })
        .unwrap_or_else(|| Sha256Digest::from_bytes(b"uncatalogued-provider"));
    let denied = decision == PolicyDecision::Denied;
    PolicyEvaluation {
        decision,
        denial_kind: denied.then(|| "shadow_policy_denied".to_owned()),
        reason: if denied {
            "shadow policy denies this proposal"
        } else {
            "shadow policy evaluated this proposal"
        }
        .to_owned(),
        proposal_binding_verified: true,
        proposal_commitment,
        resource_claim_hash: request.resource_claim_hash.clone(),
        policy_snapshot_hash: request.policy_snapshot_hash.clone(),
        budget_usage_version: 7,
        budget_charge: request.budget_charge,
        checks: Vec::new(),
    }
}

fn assert_not_executable(observation: &MonitorObservation) {
    let BaselineDisposition::NotExecutable { reason_code } = &observation.baseline_disposition
    else {
        panic!("malformed or uncatalogued proposals must not be simulated as executable");
    };
    EventCode::try_from(reason_code.clone()).expect("observer reason must be a stable event code");
    assert!(observation.simulated_effect.is_none());
    assert_eq!(observation.side_effect_state, SideEffectState::NotAttempted);
}

fn executor_fixture() -> (tempfile::TempDir, PermitIssuer, DefaultProviderExecutor) {
    let root = tempfile::tempdir().expect("executor root");
    let sandbox_root = root.path().join("sandbox");
    let trusted_runtime_root = root.path().join("runtime");
    fs::create_dir_all(&sandbox_root).expect("sandbox root");
    fs::create_dir_all(&trusted_runtime_root).expect("trusted runtime root");
    let (issuer, verifier) = PermitAuthority::generate().expect("permit authority");
    let config = ExecutorConfig::new(
        sandbox_root,
        trusted_runtime_root,
        4_096,
        StdDuration::from_secs(2),
        verifier,
    )
    .expect("valid trusted executor configuration");
    let executor = DefaultProviderExecutor::new(config);
    (root, issuer, executor)
}

fn assert_blocked_without_output(outcome: &ProviderExecutionOutcome, reserved: BudgetCharge) {
    assert_eq!(
        outcome.result.execution_status(),
        ProviderExecutionStatus::NotExecuted
    );
    assert_eq!(
        outcome.result.side_effect_state(),
        SideEffectState::BlockedBeforeExecution
    );
    assert_eq!(outcome.result.output(), &SafeProviderOutput::None);
    assert!(outcome.result.output_hash().is_none());
    assert!(outcome.result.receipt().is_none());
    assert_eq!(
        outcome.result.actual_budget_charge(),
        BudgetCharge {
            calls: 0,
            file_bytes: 0,
            network_bytes: 0,
        }
    );
    assert!(outcome.result.error_kind().is_some());
    assert!(outcome.result.reason_code().is_some());
    outcome.result.validate_against(reserved).unwrap();
    assert!(outcome.cleanup.is_none());
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

#[test]
fn monitor_only_simulates_valid_catalogued_proposals_without_side_effects() {
    let sandbox = tempfile::tempdir().expect("monitor sandbox");
    let observer = MonitorOnlyObserver;
    let baseline_request = catalog_email_request();
    let mut baseline_effect = None;

    for (decision, policy_label) in [
        (
            PolicyDecision::Allowed,
            b"monitor-policy-allowed".as_slice(),
        ),
        (PolicyDecision::Denied, b"monitor-policy-denied".as_slice()),
        (
            PolicyDecision::RequiresReview,
            b"monitor-policy-review".as_slice(),
        ),
    ] {
        let request = ProviderExecutionRequest {
            policy_snapshot_hash: Sha256Digest::from_bytes(policy_label),
            ..baseline_request.clone()
        };
        let evaluation = evaluation_for(&request, decision.clone());
        let observation = observer.observe(&evaluation, &request);

        assert_eq!(observation.shadow_policy_decision, decision);
        assert_eq!(
            observation.baseline_disposition,
            BaselineDisposition::SimulatedWouldExecute
        );
        assert_eq!(observation.side_effect_state, SideEffectState::Simulated);
        assert_eq!(observation.resource_claim, request.resource_claim);

        let effect = observation
            .simulated_effect
            .expect("valid catalogued proposals have a simulated effect");
        assert_eq!(effect.provider_id, request.provider);
        assert_eq!(effect.action, request.action);
        assert_eq!(effect.resource_claim_digest, request.resource_claim_hash);
        assert_eq!(effect.arguments_commitment, request.argument_hash);
        EventCode::try_from(effect.effect_kind.clone())
            .expect("effect kind must be a stable event code");

        let policy_independent_effect = (
            effect.provider_id,
            effect.action,
            effect.resource_claim_digest,
            effect.arguments_commitment,
            effect.effect_kind,
        );
        match &baseline_effect {
            Some(baseline) => assert_eq!(
                baseline, &policy_independent_effect,
                "changing only shadow policy must not change the simulated effect"
            ),
            None => baseline_effect = Some(policy_independent_effect),
        }
    }

    assert!(
        !sandbox.path().join("mail").exists(),
        "the assurance observer must never invoke the email implementation"
    );
}

#[test]
fn monitor_only_dispatch_covers_all_ten_typed_contest_providers() {
    let relative_path = |value: &str| WorkspaceRelativePath::try_from(value.to_owned()).unwrap();
    let cases = vec![
        (
            "external.mcp.filesystem.read_file",
            "read_file",
            json!({"path":"reports/q2.md"}),
            ResourceClaim::File {
                root: "contest-workspace".to_owned(),
                path: relative_path("reports/q2.md"),
                access: FileAccess::Read,
                classification: DataClass::Internal,
            },
            "file_read",
        ),
        (
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":"out/q2.md","content":"safe"}),
            ResourceClaim::File {
                root: "contest-workspace".to_owned(),
                path: relative_path("out/q2.md"),
                access: FileAccess::Write,
                classification: DataClass::Internal,
            },
            "file_write",
        ),
        (
            "external.email.send",
            "send",
            json!({"to":["finance@example.test"]}),
            ResourceClaim::Email {
                recipients: vec!["finance@example.test".to_owned()],
                classification: DataClass::Internal,
            },
            "email_send",
        ),
        (
            "external.api.request",
            "request",
            json!({"method":"POST","url":"https://api.example.test/v1"}),
            ResourceClaim::Network {
                method: "POST".to_owned(),
                origin: "https://api.example.test".to_owned(),
                classification: DataClass::Internal,
            },
            "network_request",
        ),
        (
            "external.mcp.browser.open_page",
            "open_page",
            json!({"url":"https://docs.example.test/x"}),
            ResourceClaim::Network {
                method: "GET".to_owned(),
                origin: "https://docs.example.test".to_owned(),
                classification: DataClass::Internal,
            },
            "browser_open_page",
        ),
        (
            "external.memory.read",
            "read",
            json!({"key":"quarter"}),
            ResourceClaim::Memory {
                namespace: "session-memory".to_owned(),
                key: "quarter".to_owned(),
                access: MemoryAccess::Read,
            },
            "memory_read",
        ),
        (
            "external.memory.write",
            "write",
            json!({"key":"quarter","value":"Q2"}),
            ResourceClaim::Memory {
                namespace: "session-memory".to_owned(),
                key: "quarter".to_owned(),
                access: MemoryAccess::Write,
            },
            "memory_write",
        ),
        (
            "external.knowledge.read",
            "read",
            json!({"key":"policy"}),
            ResourceClaim::Memory {
                namespace: "curated-knowledge".to_owned(),
                key: "policy".to_owned(),
                access: MemoryAccess::Read,
            },
            "knowledge_read",
        ),
        (
            "external.knowledge.write",
            "write",
            json!({"key":"policy","value":"safe"}),
            ResourceClaim::Memory {
                namespace: "curated-knowledge".to_owned(),
                key: "policy".to_owned(),
                access: MemoryAccess::Write,
            },
            "knowledge_write",
        ),
        (
            "runwarden.input.inspect",
            "inspect",
            json!({"input_text":"hello"}),
            ResourceClaim::InputInspection {
                source: "tool_input".to_owned(),
                content_hash: Sha256Digest::from_bytes(b"hello"),
                classification: DataClass::Internal,
            },
            "input_inspection",
        ),
    ];

    let observer = MonitorOnlyObserver;
    for (provider_id, action, arguments, claim, expected_effect) in cases {
        let request = request_for(&catalog_provider(provider_id), action, arguments, claim);
        let observation =
            observer.observe(&evaluation_for(&request, PolicyDecision::Allowed), &request);
        assert_eq!(
            observation.baseline_disposition,
            BaselineDisposition::SimulatedWouldExecute,
            "{provider_id}"
        );
        assert_eq!(
            observation
                .simulated_effect
                .as_ref()
                .map(|effect| effect.effect_kind.as_str()),
            Some(expected_effect),
            "{provider_id}"
        );
    }
}

#[test]
fn monitor_only_rejects_malformed_and_uncatalogued_frozen_requests() {
    let observer = MonitorOnlyObserver;
    let request = catalog_email_request();

    let stale_arguments = ProviderExecutionRequest {
        arguments: json!({
            "to": ["attacker@example.test"],
            "subject": "changed after policy evaluation"
        }),
        ..request.clone()
    };
    assert_not_executable(&observer.observe(
        &evaluation_for(&stale_arguments, PolicyDecision::Allowed),
        &stale_arguments,
    ));

    let stale_claim = ProviderExecutionRequest {
        resource_claim: ResourceClaim::Email {
            recipients: vec!["attacker@example.test".to_owned()],
            classification: DataClass::Internal,
        },
        ..request.clone()
    };
    assert_not_executable(&observer.observe(
        &evaluation_for(&stale_claim, PolicyDecision::Allowed),
        &stale_claim,
    ));

    let stale_provider_contract = ProviderExecutionRequest {
        provider_contract_hash: Sha256Digest::from_bytes(b"forged-provider-contract"),
        ..request.clone()
    };
    assert_not_executable(&observer.observe(
        &evaluation_for(&stale_provider_contract, PolicyDecision::Allowed),
        &stale_provider_contract,
    ));

    for malformed in [
        ProviderExecutionRequest {
            provider: "external.attacker.execute".to_owned(),
            ..request.clone()
        },
        ProviderExecutionRequest {
            provider: String::new(),
            ..request.clone()
        },
        ProviderExecutionRequest {
            action: "delete_without_review".to_owned(),
            ..request.clone()
        },
        ProviderExecutionRequest {
            action: String::new(),
            ..request.clone()
        },
    ] {
        assert_not_executable(&observer.observe(
            &evaluation_for(&malformed, PolicyDecision::Allowed),
            &malformed,
        ));
    }

    let opaque_claim = ResourceClaim::OpaqueLegacy {
        provider: request.provider.clone(),
        redacted_summary: "display-only legacy target".to_owned(),
    };
    let opaque = ProviderExecutionRequest {
        resource_claim_hash: opaque_claim.digest(),
        resource_claim: opaque_claim,
        ..request.clone()
    };
    assert_not_executable(
        &observer.observe(&evaluation_for(&opaque, PolicyDecision::Allowed), &opaque),
    );

    let mut wrong_resource_evaluation = evaluation_for(&request, PolicyDecision::Allowed);
    wrong_resource_evaluation.resource_claim_hash = Sha256Digest::from_bytes(b"another-resource");
    assert_not_executable(&observer.observe(&wrong_resource_evaluation, &request));

    let mut wrong_policy_evaluation = evaluation_for(&request, PolicyDecision::Allowed);
    wrong_policy_evaluation.policy_snapshot_hash = Sha256Digest::from_bytes(b"another-policy");
    assert_not_executable(&observer.observe(&wrong_policy_evaluation, &request));

    let original_evaluation = evaluation_for(&request, PolicyDecision::Allowed);
    let changed_arguments = json!({
        "to": ["finance@example.test"],
        "subject": "Q2",
        "body": "self-consistent changed body"
    });
    let rebound_request = ProviderExecutionRequest {
        argument_hash: canonical_argument_hash(&changed_arguments),
        arguments: changed_arguments,
        ..request.clone()
    };
    let rebound = observer.observe(&original_evaluation, &rebound_request);
    assert_not_executable(&rebound);
    assert!(matches!(
        rebound.baseline_disposition,
        BaselineDisposition::NotExecutable { ref reason_code }
            if reason_code == "evaluation_proposal_mismatch"
    ));

    let mut unverified = evaluation_for(&request, PolicyDecision::Denied);
    unverified.proposal_binding_verified = false;
    let unverified = observer.observe(&unverified, &request);
    assert_not_executable(&unverified);
    assert!(matches!(
        unverified.baseline_disposition,
        BaselineDisposition::NotExecutable { ref reason_code }
            if reason_code == "evaluation_binding_unverified"
    ));
}

#[test]
fn monitor_only_source_has_no_execution_or_tool_delegate_dependency() {
    let source = include_str!("../src/executor/monitor_only.rs");
    for forbidden in [
        "DefaultProviderExecutor",
        "ExecutionPermit",
        "PermitVerifier",
        "ExecutionLeaseId",
        "ApprovalLease",
        "ProviderExecutor",
        "demo_tools",
    ] {
        assert!(
            !source.contains(forbidden),
            "monitor-only observer must not reference {forbidden}"
        );
    }
}

#[test]
fn executor_config_validates_limits_and_redacts_the_process_verifier() {
    let root = tempfile::tempdir().expect("config root");
    let sandbox_root = root.path().join("sandbox");
    let runtime_root = root.path().join("runtime");
    fs::create_dir_all(&sandbox_root).unwrap();
    fs::create_dir_all(&runtime_root).unwrap();
    let (_, verifier) = PermitAuthority::generate().unwrap();

    let config = ExecutorConfig::new(
        sandbox_root.clone(),
        runtime_root.clone(),
        1_024,
        StdDuration::from_secs(1),
        verifier.clone(),
    )
    .expect("positive bounded configuration");
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("permit_key"));

    assert!(
        ExecutorConfig::new(
            sandbox_root.clone(),
            runtime_root.clone(),
            0,
            StdDuration::from_secs(1),
            verifier.clone(),
        )
        .is_err(),
        "zero output capacity is not a usable execution bound"
    );
    assert!(
        ExecutorConfig::new(
            sandbox_root,
            runtime_root,
            1_024,
            StdDuration::ZERO,
            verifier,
        )
        .is_err(),
        "zero timeout is not a usable execution bound"
    );
}

#[test]
fn default_executor_rejects_tampered_permits_before_any_dispatch() {
    let (root, issuer, executor) = executor_fixture();
    let request = catalog_email_request();
    let permit = issuer.seal(claims(&request)).unwrap();
    let tampered = ProviderExecutionRequest {
        arguments: json!({"to": ["attacker@example.test"]}),
        ..request.clone()
    };

    let outcome = executor.execute(&permit, &tampered, fixed_now());
    assert_blocked_without_output(&outcome, request.budget_charge);
    assert!(
        !root.path().join("sandbox/mail").exists(),
        "permit validation must precede provider dispatch"
    );
    assert!(matches!(
        executor.reconcile(&request).result,
        ReconciliationResult::NotExecuted
    ));

    let (other_issuer, _) = PermitAuthority::generate().unwrap();
    let foreign_permit = other_issuer.seal(claims(&request)).unwrap();
    let foreign = executor.execute(&foreign_permit, &request, fixed_now());
    assert_blocked_without_output(&foreign, request.budget_charge);
    assert!(!root.path().join("sandbox/mail").exists());
}

#[test]
fn default_executor_uses_the_canonical_catalog_and_exact_action_dispatch() {
    let (root, issuer, executor) = executor_fixture();

    let unknown_provider = KernelProvider {
        id: "external.attacker.execute".to_owned(),
        class: ProviderClass::External,
        kind: ProviderKind::Plugin,
        risk: ProviderRisk::Low,
        side_effects: vec![SideEffectKind::None],
        input_schema: json!({"type":"object"}),
        output_schema: json!({"type":"object"}),
        evidence_contract: json!({"obs_refs_required":false}),
        authority_requirements: json!({"approval_required":false}),
    };
    let unknown_request = request_for(
        &unknown_provider,
        "execute",
        json!({"payload":"ignored"}),
        ResourceClaim::Email {
            recipients: vec!["finance@example.test".to_owned()],
            classification: DataClass::Internal,
        },
    );
    let unknown_permit = issuer.seal(claims(&unknown_request)).unwrap();
    let unknown = executor.execute(&unknown_permit, &unknown_request, fixed_now());
    assert_blocked_without_output(&unknown, unknown_request.budget_charge);
    assert_eq!(unknown.result.reason_code(), Some("provider_unknown"));

    let wrong_action = ProviderExecutionRequest {
        action: "delete_without_review".to_owned(),
        ..catalog_email_request()
    };
    let wrong_action_permit = issuer.seal(claims(&wrong_action)).unwrap();
    let action_result = executor.execute(&wrong_action_permit, &wrong_action, fixed_now());
    assert_blocked_without_output(&action_result, wrong_action.budget_charge);
    assert_eq!(
        action_result.result.reason_code(),
        Some("unsupported_action")
    );

    let mut downgraded_email = catalog_provider("external.email.send");
    downgraded_email.risk = ProviderRisk::Low;
    downgraded_email.side_effects.clear();
    downgraded_email.authority_requirements = json!({"approval_required":false});
    let downgraded_request = request_for(
        &downgraded_email,
        "send",
        json!({"to":["finance@example.test"]}),
        ResourceClaim::Email {
            recipients: vec!["finance@example.test".to_owned()],
            classification: DataClass::Internal,
        },
    );
    let downgraded_permit = issuer.seal(claims(&downgraded_request)).unwrap();
    let downgraded = executor.execute(&downgraded_permit, &downgraded_request, fixed_now());
    assert_blocked_without_output(&downgraded, downgraded_request.budget_charge);

    assert!(!root.path().join("sandbox/mail").exists());
}

#[test]
fn default_executor_dispatches_permitted_email_through_the_private_tool() {
    let (root, issuer, executor) = executor_fixture();
    let request = catalog_email_request();
    let permit = issuer.seal(claims(&request)).unwrap();

    let outcome = executor.execute(&permit, &request, fixed_now());
    assert_eq!(
        outcome.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert_eq!(
        outcome.result.side_effect_state(),
        SideEffectState::Completed
    );
    assert!(matches!(
        outcome.result.output(),
        SafeProviderOutput::Email { .. }
    ));
    assert!(outcome.result.receipt().is_some());
    outcome
        .result
        .validate_against(request.budget_charge)
        .unwrap();
    assert!(
        root.path().join("sandbox/mail/receipts").is_dir(),
        "the private email implementation must persist reconciliation material"
    );
    assert!(matches!(
        executor.reconcile(&request).result,
        ReconciliationResult::Completed(_)
    ));
}

#[test]
fn code_claim_is_not_executable_before_the_task_nine_catalog_provider_exists() {
    let (root, issuer, executor) = executor_fixture();
    let unavailable_code_provider = KernelProvider {
        id: "external.code.python".to_owned(),
        class: ProviderClass::External,
        kind: ProviderKind::Plugin,
        risk: ProviderRisk::High,
        side_effects: vec![
            SideEffectKind::ProcessSpawn,
            SideEffectKind::FileRead,
            SideEffectKind::FileWrite,
        ],
        input_schema: json!({"type":"object"}),
        output_schema: json!({"type":"object"}),
        evidence_contract: json!({"obs_refs_required":true}),
        authority_requirements: json!({"approval_required":true}),
    };
    let request = request_for(
        &unavailable_code_provider,
        "execute",
        json!({"source":"print('must not run')"}),
        ResourceClaim::CodeExecution {
            runtime: "python3".to_owned(),
            workspace: "contest".to_owned(),
            network: NetworkCapability::None,
            limits: ExecutionLimits {
                wall_time_ms: 1_000,
                cpu_time_ms: 500,
                memory_bytes: 64 * 1_024 * 1_024,
                output_bytes: 4_096,
                process_count: 1,
            },
        },
    );
    let permit = issuer.seal(claims(&request)).unwrap();

    let outcome = executor.execute(&permit, &request, fixed_now());
    assert_blocked_without_output(&outcome, request.budget_charge);
    assert_eq!(outcome.result.reason_code(), Some("provider_unknown"));
    assert!(!root.path().join("sandbox").join("code").exists());
}
