use runwarden_kernel::resource::{DataClass, FileAccess, ResourceClaim};
use runwarden_kernel::story::EnforcementMode;
use runwarden_kernel::trace::canonical_json_v1;
use runwarden_kernel::{KernelProvider, SideEffectKind};
use runwarden_providers::catalog::{default_external_providers, default_first_party_providers};
use runwarden_providers::resource_claims::{
    BudgetDerivationLimits, ResourceExtractionContext, ResourceExtractorRegistry,
    derive_budget_charge,
};
use serde_json::{Value, json};

const FILE_CAP: u64 = 64 * 1024;
const NETWORK_RESPONSE_CAP: u64 = 128 * 1024;

fn provider(provider_id: &str) -> KernelProvider {
    default_first_party_providers()
        .into_iter()
        .chain(default_external_providers())
        .find(|candidate| candidate.id == provider_id)
        .unwrap_or_else(|| panic!("provider catalog is missing {provider_id}"))
}

fn context() -> ResourceExtractionContext {
    ResourceExtractionContext {
        filesystem_root: "contest-workspace".to_owned(),
        memory_namespace: "session-memory".to_owned(),
        knowledge_namespace: "curated-knowledge".to_owned(),
        default_classification: DataClass::Confidential,
    }
}

fn limits() -> BudgetDerivationLimits {
    BudgetDerivationLimits {
        max_file_bytes_per_call: FILE_CAP,
        max_network_response_bytes_per_call: NETWORK_RESPONSE_CAP,
    }
}

#[test]
fn authoritative_extraction_atomically_binds_claim_arguments_charge_and_mode() {
    let (registry, verifier) = ResourceExtractorRegistry::contest_authoritative()
        .expect("OS-backed binding authority should initialize");
    let provider = provider("external.mcp.filesystem.read_file");
    let arguments = json!({"path":"reports/q2.md"});
    let bound = registry
        .extract_bound(
            &provider,
            "read_file",
            &arguments,
            &context(),
            &limits(),
            EnforcementMode::Enforced,
        )
        .expect("canonical proposal should receive an authenticated binding");

    assert_eq!(
        bound.claim(),
        &ResourceClaim::File {
            root: "contest-workspace".to_owned(),
            path: runwarden_kernel::artifact::WorkspaceRelativePath::try_from(
                "reports/q2.md".to_owned(),
            )
            .unwrap(),
            access: FileAccess::Read,
            classification: DataClass::Confidential,
        }
    );
    assert_eq!(bound.budget_charge().calls, 1);
    assert_eq!(bound.budget_charge().file_bytes, FILE_CAP);
    assert_eq!(bound.budget_charge().network_bytes, 0);
    verifier
        .validate(
            bound.binding(),
            &provider,
            "read_file",
            &arguments,
            bound.claim(),
            bound.budget_charge(),
            EnforcementMode::Enforced,
        )
        .expect("the exact frozen proposal should validate");
}

#[test]
fn binding_rejects_argument_claim_provider_action_charge_and_mode_confusion() {
    let (registry, verifier) = ResourceExtractorRegistry::contest_authoritative().unwrap();
    let file_provider = provider("external.mcp.filesystem.read_file");
    let arguments = json!({"path":"reports/q2.md"});
    let bound = registry
        .extract_bound(
            &file_provider,
            "read_file",
            &arguments,
            &context(),
            &limits(),
            EnforcementMode::Enforced,
        )
        .unwrap();

    let attacker_arguments = json!({"path":"private/payroll.csv"});
    let attacker_claim = ResourceClaim::InputInspection {
        source: "tool_input".to_owned(),
        content_hash: runwarden_kernel::trace::Sha256Digest::from_bytes(b"different"),
        classification: DataClass::Public,
    };
    let mut forged_charge = *bound.budget_charge();
    forged_charge.file_bytes = 0;
    let email_provider = provider("external.email.send");

    assert!(
        verifier
            .validate(
                bound.binding(),
                &file_provider,
                "read_file",
                &attacker_arguments,
                bound.claim(),
                bound.budget_charge(),
                EnforcementMode::Enforced,
            )
            .is_err(),
        "arguments cannot be changed while retaining an allowed claim"
    );
    assert!(
        verifier
            .validate(
                bound.binding(),
                &file_provider,
                "read_file",
                &arguments,
                &attacker_claim,
                bound.budget_charge(),
                EnforcementMode::Enforced,
            )
            .is_err(),
        "a claim from another resource family cannot be substituted"
    );
    assert!(
        verifier
            .validate(
                bound.binding(),
                &email_provider,
                "read_file",
                &arguments,
                bound.claim(),
                bound.budget_charge(),
                EnforcementMode::Enforced,
            )
            .is_err(),
        "a same proposal cannot be replayed across providers"
    );
    assert!(
        verifier
            .validate(
                bound.binding(),
                &file_provider,
                "write_file",
                &arguments,
                bound.claim(),
                bound.budget_charge(),
                EnforcementMode::Enforced,
            )
            .is_err(),
        "a binding cannot be replayed across actions"
    );
    assert!(
        verifier
            .validate(
                bound.binding(),
                &file_provider,
                "read_file",
                &arguments,
                bound.claim(),
                &forged_charge,
                EnforcementMode::Enforced,
            )
            .is_err(),
        "the authenticated reservation cannot be undercharged"
    );
    assert!(
        verifier
            .validate(
                bound.binding(),
                &file_provider,
                "read_file",
                &arguments,
                bound.claim(),
                bound.budget_charge(),
                EnforcementMode::MonitorOnly,
            )
            .is_err(),
        "an enforced binding cannot be reused in monitor-only mode"
    );
}

#[test]
fn display_only_registry_cannot_issue_execution_bindings() {
    let registry = ResourceExtractorRegistry::contest_default();
    let result = registry.extract_bound(
        &provider("external.mcp.filesystem.read_file"),
        "read_file",
        &json!({"path":"reports/q2.md"}),
        &context(),
        &limits(),
        EnforcementMode::Enforced,
    );
    let error = match result {
        Ok(_) => panic!("display-only extraction must not mint an execution binding"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "binding_authority_unavailable");
}

#[test]
fn budget_derivation_is_conservative_for_declared_file_and_network_effects() {
    let cases = [
        (
            "external.mcp.filesystem.read_file",
            "read_file",
            json!({"path":"reports/q2.md"}),
        ),
        (
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":"out/q2.md","content":"x"}),
        ),
        (
            "external.memory.write",
            "write",
            json!({"key":"q2","value":"x"}),
        ),
        (
            "runwarden.input.inspect",
            "inspect",
            json!({"input_text":"hello"}),
        ),
    ];
    for (provider_id, action, arguments) in cases {
        let charge = derive_budget_charge(&provider(provider_id), action, &arguments, &limits())
            .unwrap_or_else(|error| panic!("{provider_id} charge derivation failed: {error}"));
        assert_eq!(charge.calls, 1, "{provider_id}");
        assert_eq!(charge.file_bytes, FILE_CAP, "{provider_id}");
        assert_eq!(charge.network_bytes, 0, "{provider_id}");
    }

    let network_arguments = json!({
        "method":"POST",
        "url":"https://api.example.test/v1",
        "body":{"approved":true}
    });
    let network = derive_budget_charge(
        &provider("external.api.request"),
        "request",
        &network_arguments,
        &limits(),
    )
    .unwrap();
    assert_eq!(network.calls, 1);
    assert_eq!(network.file_bytes, 0);
    assert_eq!(
        network.network_bytes,
        u64::try_from(canonical_json_v1(&network_arguments).len()).unwrap() + NETWORK_RESPONSE_CAP
    );
}

#[test]
fn budget_derivation_rejects_zero_caps_overflow_and_agent_charge_fields() {
    let file_arguments = json!({"path":"reports/q2.md"});
    let zero_file = derive_budget_charge(
        &provider("external.mcp.filesystem.read_file"),
        "read_file",
        &file_arguments,
        &BudgetDerivationLimits {
            max_file_bytes_per_call: 0,
            max_network_response_bytes_per_call: NETWORK_RESPONSE_CAP,
        },
    )
    .expect_err("a declared file effect needs a non-zero trusted cap");
    assert_eq!(zero_file.code(), "invalid_trusted_limit");

    let network_arguments = json!({
        "method":"GET",
        "url":"https://api.example.test/v1"
    });
    let zero_response = derive_budget_charge(
        &provider("external.api.request"),
        "request",
        &network_arguments,
        &BudgetDerivationLimits {
            max_file_bytes_per_call: FILE_CAP,
            max_network_response_bytes_per_call: 0,
        },
    )
    .expect_err("a network effect needs a non-zero trusted response cap");
    assert_eq!(zero_response.code(), "invalid_trusted_limit");

    let overflow = derive_budget_charge(
        &provider("external.api.request"),
        "request",
        &network_arguments,
        &BudgetDerivationLimits {
            max_file_bytes_per_call: FILE_CAP,
            max_network_response_bytes_per_call: u64::MAX,
        },
    )
    .expect_err("network request plus response reservation must use checked arithmetic");
    assert_eq!(overflow.code(), "budget_arithmetic_overflow");

    let supplied_charge = derive_budget_charge(
        &provider("external.mcp.filesystem.read_file"),
        "read_file",
        &json!({"path":"reports/q2.md","budget_charge":{"calls":1,"file_bytes":0}}),
        &limits(),
    )
    .expect_err("agent-supplied charge fields must never enter derivation");
    assert_eq!(supplied_charge.code(), "reserved_field");
}

#[test]
fn declared_effect_detection_does_not_depend_on_provider_name_prefixes() {
    let provider = KernelProvider {
        id: "custom.safe-name".to_owned(),
        class: runwarden_kernel::ProviderClass::FirstParty,
        kind: runwarden_kernel::ProviderKind::Input,
        risk: runwarden_kernel::ProviderRisk::Low,
        side_effects: vec![SideEffectKind::Network, SideEffectKind::ArtifactWrite],
        input_schema: Value::Object(Default::default()),
        output_schema: Value::Object(Default::default()),
        evidence_contract: Value::Object(Default::default()),
        authority_requirements: Value::Object(Default::default()),
    };
    let arguments = json!({"payload":"x"});
    let charge = derive_budget_charge(&provider, "invoke", &arguments, &limits()).unwrap();

    assert_eq!(charge.calls, 1);
    assert_eq!(charge.file_bytes, FILE_CAP);
    assert_eq!(
        charge.network_bytes,
        u64::try_from(canonical_json_v1(&arguments).len()).unwrap() + NETWORK_RESPONSE_CAP
    );
}
