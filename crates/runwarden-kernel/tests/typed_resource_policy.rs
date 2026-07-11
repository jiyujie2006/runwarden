use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::kernel::{ProviderRegistry, ProviderRegistryError};
use runwarden_kernel::operation::{PolicyCheck, PolicyCheckStatus};
use runwarden_kernel::policy::{PolicyEvaluation, SessionContext, evaluate_proposal};
use runwarden_kernel::resource::{
    DataClass, ExecutionLimits, FileAccess, MemoryAccess, NetworkCapability, ResourceClaim,
};
use runwarden_kernel::resource_binding::{
    ResourceBindingAuthority, ResourceBindingIssuer, ResourceBindingProof,
    ResourceBindingValidationError, ResourceBindingVerifier,
};
use runwarden_kernel::session::{
    ArtifactAuthority, AuthoritySnapshot, BudgetCharge, BudgetSnapshot, BudgetUsageSnapshot,
    CodeAuthority, EmailAuthority, EvidenceAuthority, FileAuthority, InputAuthority,
    NetworkAuthority, StoreAuthority,
};
use runwarden_kernel::story::{EnforcementMode, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use runwarden_kernel::{
    KernelProvider, PolicyDecision, ProviderCall, ProviderClass, ProviderKind, ProviderRisk,
    SideEffectKind,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

const FILE_PROVIDER: &str = "external.mcp.filesystem.read_file";
const EMAIL_PROVIDER: &str = "external.email.send";
const NETWORK_PROVIDER: &str = "external.api.request";
const BROWSER_PROVIDER: &str = "external.mcp.browser.open_page";
const MEMORY_PROVIDER: &str = "external.memory.read";
const CODE_PROVIDER: &str = "external.code.python";
const INPUT_PROVIDER: &str = "runwarden.input.inspect";
const EVIDENCE_PROVIDER: &str = "runwarden.evidence.read";
const ARTIFACT_PROVIDER: &str = "runwarden.report.render";

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn path(value: &str) -> WorkspaceRelativePath {
    WorkspaceRelativePath::try_from(value.to_owned()).unwrap()
}

fn provider(id: &str, risk: ProviderRisk, side_effects: Vec<SideEffectKind>) -> KernelProvider {
    KernelProvider {
        id: id.to_owned(),
        class: ProviderClass::External,
        kind: ProviderKind::Mcp,
        risk,
        side_effects,
        input_schema: json!({"type": "object", "provider": id}),
        output_schema: json!({"type": "object"}),
        evidence_contract: json!({"obs_refs_required": true}),
        authority_requirements: json!({"kernel_mediation_required": true}),
    }
}

fn canonical_providers() -> Vec<KernelProvider> {
    vec![
        provider(
            FILE_PROVIDER,
            ProviderRisk::Low,
            vec![SideEffectKind::FileRead],
        ),
        provider(
            EMAIL_PROVIDER,
            ProviderRisk::CredentialUse,
            vec![SideEffectKind::Network, SideEffectKind::CredentialUse],
        ),
        provider(
            NETWORK_PROVIDER,
            ProviderRisk::NetworkActive,
            vec![SideEffectKind::Network],
        ),
        provider(
            BROWSER_PROVIDER,
            ProviderRisk::NetworkActive,
            vec![SideEffectKind::Network],
        ),
        provider(MEMORY_PROVIDER, ProviderRisk::Low, vec![]),
        provider(
            CODE_PROVIDER,
            ProviderRisk::High,
            vec![SideEffectKind::ProcessSpawn, SideEffectKind::FileWrite],
        ),
        provider(INPUT_PROVIDER, ProviderRisk::Low, vec![]),
        provider(EVIDENCE_PROVIDER, ProviderRisk::Low, vec![]),
        provider(
            ARTIFACT_PROVIDER,
            ProviderRisk::ReportClaim,
            vec![SideEffectKind::ArtifactWrite],
        ),
    ]
}

fn maximum_code_limits() -> ExecutionLimits {
    ExecutionLimits {
        wall_time_ms: 5_000,
        cpu_time_ms: 2_000,
        memory_bytes: 128 * 1024 * 1024,
        output_bytes: 16 * 1024,
        process_count: 2,
    }
}

fn allowed_code_limits() -> ExecutionLimits {
    ExecutionLimits {
        wall_time_ms: 1_000,
        cpu_time_ms: 500,
        memory_bytes: 64 * 1024 * 1024,
        output_bytes: 4 * 1024,
        process_count: 1,
    }
}

fn authority(session_id: SessionId, evidence_operation: OperationId) -> AuthoritySnapshot {
    AuthoritySnapshot {
        session_id,
        actor_id: "agent-1".to_owned(),
        authz_id: "authz-active".to_owned(),
        authz_state: "active".to_owned(),
        expires_at: fixed_now() + Duration::hours(1),
        allowed_providers: canonical_providers()
            .into_iter()
            .map(|provider| provider.id)
            .collect(),
        files: vec![FileAuthority {
            root: "workspace".to_owned(),
            path_prefix: "reports".to_owned(),
            access: vec![FileAccess::Read],
            maximum_classification: DataClass::Confidential,
        }],
        networks: vec![NetworkAuthority {
            provider: NETWORK_PROVIDER.to_owned(),
            allowed_origins: vec!["https://api.example.test".to_owned()],
            maximum_classification: DataClass::Internal,
        }],
        email: Some(EmailAuthority {
            allowed_recipients: vec![
                "finance@example.test".to_owned(),
                "reviewer@example.test".to_owned(),
            ],
            maximum_classification: DataClass::Internal,
        }),
        stores: vec![StoreAuthority {
            namespace: "session-memory".to_owned(),
            key_prefix: "story/".to_owned(),
            access: vec![MemoryAccess::Read],
        }],
        code: Some(CodeAuthority {
            allowed_runtimes: vec!["python3".to_owned()],
            workspace: "sandbox".to_owned(),
            network: NetworkCapability::None,
            maximum_limits: maximum_code_limits(),
        }),
        inputs: vec![InputAuthority {
            allowed_sources: vec!["scenario.prompt".to_owned()],
            maximum_classification: DataClass::Confidential,
        }],
        evidence: EvidenceAuthority {
            current_story_only: true,
            allowed_operations: vec![evidence_operation],
        },
        artifacts: vec![ArtifactAuthority {
            path_prefix: path("exports/stories"),
            allowed_formats: vec!["json".to_owned(), "html".to_owned()],
        }],
        budgets: BudgetSnapshot {
            max_argument_bytes: 4_096,
            max_file_bytes: 1_000,
            max_network_bytes: 2_000,
            max_calls: 100,
            max_wall_time_ms: 2_000,
            max_model_calls: 10,
            max_model_input_bytes: 32_768,
            max_model_output_bytes: 8_192,
        },
        policy_snapshot_hash: Sha256Digest::from_bytes(b"typed-policy-v1")
            .as_str()
            .to_owned(),
    }
}

struct Fixture {
    story_id: StoryId,
    session_id: SessionId,
    evidence_operation: OperationId,
    registry: ProviderRegistry,
    binding_issuer: ResourceBindingIssuer,
    binding_verifier: ResourceBindingVerifier,
    session: SessionContext,
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_mode(EnforcementMode::Enforced)
    }

    fn new_with_mode(enforcement_mode: EnforcementMode) -> Self {
        let story_id = StoryId::new();
        let session_id = SessionId::new();
        let evidence_operation = OperationId::new();
        let mut registry = ProviderRegistry::default();
        for provider in canonical_providers() {
            registry.register(provider).unwrap();
        }
        let (binding_issuer, binding_verifier) =
            ResourceBindingAuthority::generate().expect("resource binding authority");
        let session = SessionContext::from_authority(
            story_id,
            authority(session_id, evidence_operation),
            &registry,
            enforcement_mode,
            binding_verifier.clone(),
        )
        .unwrap();
        Self {
            story_id,
            session_id,
            evidence_operation,
            registry,
            binding_issuer,
            binding_verifier,
            session,
        }
    }

    fn provider(&self, id: &str) -> &KernelProvider {
        self.registry
            .get(id)
            .expect("fixture provider is registered")
    }

    fn call(&self, provider: &str, action: &str, arguments: Value) -> ProviderCall {
        ProviderCall {
            session_id: self.session_id.to_string(),
            provider: provider.to_owned(),
            action: action.to_owned(),
            arguments,
            actor_id: Some("agent-1".to_owned()),
            authz_id: Some("authz-active".to_owned()),
            approval_id: None,
        }
    }

    fn context_with(&self, mutate: impl FnOnce(&mut AuthoritySnapshot)) -> SessionContext {
        let mut authority = self.session.authority.clone();
        mutate(&mut authority);
        SessionContext::from_authority(
            self.story_id,
            authority,
            &self.registry,
            self.session.enforcement_mode,
            self.binding_verifier.clone(),
        )
        .unwrap()
    }

    fn bind(
        &self,
        session: &SessionContext,
        charge: &BudgetCharge,
        provider: &KernelProvider,
        call: &ProviderCall,
        claim: &ResourceClaim,
    ) -> ResourceBindingProof {
        self.binding_issuer
            .seal(
                provider,
                &call.action,
                &call.arguments,
                claim,
                charge,
                session.enforcement_mode,
            )
            .expect("fixture proposal has a valid resource binding")
    }
}

fn usage(version: u64) -> BudgetUsageSnapshot {
    BudgetUsageSnapshot {
        version,
        calls_reserved: 0,
        calls_committed: 0,
        file_bytes_reserved: 0,
        file_bytes_committed: 0,
        network_bytes_reserved: 0,
        network_bytes_committed: 0,
    }
}

fn charge(calls: u64, file_bytes: u64, network_bytes: u64) -> BudgetCharge {
    BudgetCharge {
        calls,
        file_bytes,
        network_bytes,
    }
}

fn conservative_charge(provider_id: &str) -> BudgetCharge {
    match provider_id {
        FILE_PROVIDER | CODE_PROVIDER | ARTIFACT_PROVIDER => charge(1, 1, 0),
        EMAIL_PROVIDER | NETWORK_PROVIDER | BROWSER_PROVIDER => charge(1, 0, 1),
        _ => charge(1, 0, 0),
    }
}

fn file_claim(path_value: &str, access: FileAccess, classification: DataClass) -> ResourceClaim {
    ResourceClaim::File {
        root: "workspace".to_owned(),
        path: path(path_value),
        access,
        classification,
    }
}

fn code_claim(limits: ExecutionLimits) -> ResourceClaim {
    ResourceClaim::CodeExecution {
        runtime: "python3".to_owned(),
        workspace: "sandbox".to_owned(),
        network: NetworkCapability::None,
        limits,
    }
}

fn evaluate(
    fixture: &Fixture,
    session: &SessionContext,
    usage: &BudgetUsageSnapshot,
    charge: &BudgetCharge,
    provider: &KernelProvider,
    call: &ProviderCall,
    claim: &ResourceClaim,
) -> PolicyEvaluation {
    let proof = fixture.bind(session, charge, provider, call, claim);
    evaluate_with_proof(session, usage, charge, provider, call, claim, &proof)
}

fn evaluate_with_proof(
    session: &SessionContext,
    usage: &BudgetUsageSnapshot,
    charge: &BudgetCharge,
    provider: &KernelProvider,
    call: &ProviderCall,
    claim: &ResourceClaim,
    proof: &ResourceBindingProof,
) -> PolicyEvaluation {
    evaluate_proposal(
        session,
        usage,
        charge,
        provider,
        call,
        claim,
        proof,
        fixed_now(),
    )
}

fn check_ids(checks: &[PolicyCheck]) -> Vec<&str> {
    checks.iter().map(|check| check.check_id.as_str()).collect()
}

fn assert_short_circuit(
    evaluation: &PolicyEvaluation,
    terminal_index: usize,
    terminal_status: PolicyCheckStatus,
) {
    assert_eq!(
        check_ids(&evaluation.checks),
        [
            "session", "provider", "authz", "resource", "budget", "approval"
        ]
    );
    for (index, check) in evaluation.checks.iter().enumerate() {
        let expected = if index < terminal_index {
            PolicyCheckStatus::Passed
        } else if index == terminal_index {
            terminal_status.clone()
        } else {
            PolicyCheckStatus::NotEvaluated
        };
        assert_eq!(
            check.status, expected,
            "unexpected status for ordered check {}",
            check.check_id
        );
    }
}

fn assert_resource_binding_denial(name: &str, evaluation: &PolicyEvaluation) {
    assert_eq!(evaluation.decision, PolicyDecision::Denied, "{name}");
    assert_eq!(
        evaluation.denial_kind.as_deref(),
        Some("resource_binding_invalid"),
        "{name}"
    );
    assert_short_circuit(evaluation, 3, PolicyCheckStatus::Failed);
}

#[test]
fn policy_records_the_exact_order_for_allow_deny_and_review() {
    let fixture = Fixture::new();
    let zero_usage = usage(17);
    let file_charge = conservative_charge(FILE_PROVIDER);
    let email_charge = conservative_charge(EMAIL_PROVIDER);

    let file_provider = fixture.provider(FILE_PROVIDER);
    let file_call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let file_claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let allowed = evaluate(
        &fixture,
        &fixture.session,
        &zero_usage,
        &file_charge,
        file_provider,
        &file_call,
        &file_claim,
    );
    assert_eq!(allowed.decision, PolicyDecision::Allowed);
    assert_eq!(allowed.denial_kind, None);
    assert_eq!(
        check_ids(&allowed.checks),
        [
            "session", "provider", "authz", "resource", "budget", "approval"
        ]
    );
    assert!(
        allowed
            .checks
            .iter()
            .all(|check| check.status == PolicyCheckStatus::Passed)
    );
    assert_eq!(allowed.resource_claim_hash, file_claim.digest());
    assert_eq!(
        allowed.policy_snapshot_hash,
        Sha256Digest::try_from(fixture.session.authority.policy_snapshot_hash.clone()).unwrap()
    );
    assert_eq!(allowed.budget_usage_version, 17);
    assert_eq!(allowed.budget_charge, file_charge);

    let email_provider = fixture.provider(EMAIL_PROVIDER);
    let email_call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["finance@example.test"], "subject": "Q2"}),
    );
    let attacker_email = ResourceClaim::Email {
        recipients: vec!["attacker@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    let exfil = evaluate(
        &fixture,
        &fixture.session,
        &zero_usage,
        &email_charge,
        email_provider,
        &email_call,
        &attacker_email,
    );
    assert_eq!(exfil.decision, PolicyDecision::Denied);
    assert_eq!(exfil.denial_kind.as_deref(), Some("recipient_not_allowed"));
    assert_short_circuit(&exfil, 3, PolicyCheckStatus::Failed);

    let finance_email = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    let review = evaluate(
        &fixture,
        &fixture.session,
        &zero_usage,
        &email_charge,
        email_provider,
        &email_call,
        &finance_email,
    );
    assert_eq!(review.decision, PolicyDecision::RequiresReview);
    assert_eq!(review.denial_kind, None);
    assert_short_circuit(&review, 5, PolicyCheckStatus::RequiresReview);
}

#[test]
fn each_ordered_layer_fails_closed_and_marks_later_checks_not_evaluated() {
    let fixture = Fixture::new();
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let base_call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let one_call = conservative_charge(FILE_PROVIDER);

    let mut wrong_session = base_call.clone();
    wrong_session.session_id = SessionId::new().to_string();
    let session_denial = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &one_call,
        fixture.provider(FILE_PROVIDER),
        &wrong_session,
        &claim,
    );

    let provider_context = fixture.context_with(|authority| {
        authority
            .allowed_providers
            .retain(|provider| provider != FILE_PROVIDER);
    });
    let provider_denial = evaluate(
        &fixture,
        &provider_context,
        &usage(0),
        &one_call,
        fixture.provider(FILE_PROVIDER),
        &base_call,
        &claim,
    );

    let mut wrong_actor = base_call.clone();
    wrong_actor.actor_id = Some("different-agent".to_owned());
    let authz_denial = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &one_call,
        fixture.provider(FILE_PROVIDER),
        &wrong_actor,
        &claim,
    );

    let outside_claim = file_claim(
        "reports-private/q2.md",
        FileAccess::Read,
        DataClass::Internal,
    );
    let resource_denial = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &one_call,
        fixture.provider(FILE_PROVIDER),
        &base_call,
        &outside_claim,
    );

    let exhausted = BudgetUsageSnapshot {
        calls_committed: fixture.session.authority.budgets.max_calls,
        ..usage(9)
    };
    let budget_denial = evaluate(
        &fixture,
        &fixture.session,
        &exhausted,
        &one_call,
        fixture.provider(FILE_PROVIDER),
        &base_call,
        &claim,
    );

    for (name, evaluation, index, kind) in [
        ("session", session_denial, 0, "session_mismatch"),
        ("provider", provider_denial, 1, "provider_not_allowed"),
        ("authz", authz_denial, 2, "actor_mismatch"),
        ("resource", resource_denial, 3, "path_not_allowed"),
        ("budget", budget_denial, 4, "call_budget_exceeded"),
    ] {
        assert_eq!(evaluation.decision, PolicyDecision::Denied, "{name}");
        assert_eq!(evaluation.denial_kind.as_deref(), Some(kind), "{name}");
        assert_short_circuit(&evaluation, index, PolicyCheckStatus::Failed);
    }
}

#[test]
fn session_expiry_is_closed_at_the_exact_boundary() {
    let fixture = Fixture::new();
    let expired = fixture.context_with(|authority| authority.expires_at = fixed_now());
    let call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);

    let evaluation = evaluate(
        &fixture,
        &expired,
        &usage(0),
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Denied);
    assert_eq!(evaluation.denial_kind.as_deref(), Some("session_expired"));
    assert_short_circuit(&evaluation, 0, PolicyCheckStatus::Failed);
}

#[test]
fn actor_authz_identity_and_authz_state_are_exact() {
    let fixture = Fixture::new();
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let base_call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));

    let mut wrong_authz = base_call.clone();
    wrong_authz.authz_id = Some("authz-for-different-session".to_owned());
    let authz_mismatch = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &wrong_authz,
        &claim,
    );

    let inactive_context = fixture.context_with(|authority| {
        authority.authz_state = "revoked".to_owned();
    });
    let authz_inactive = evaluate(
        &fixture,
        &inactive_context,
        &usage(0),
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &base_call,
        &claim,
    );

    for (name, evaluation, denial_kind) in [
        ("authz id", authz_mismatch, "authz_mismatch"),
        ("authz state", authz_inactive, "authz_inactive"),
    ] {
        assert_eq!(evaluation.decision, PolicyDecision::Denied, "{name}");
        assert_eq!(
            evaluation.denial_kind.as_deref(),
            Some(denial_kind),
            "{name}"
        );
        assert_short_circuit(&evaluation, 2, PolicyCheckStatus::Failed);
    }
}

#[test]
fn every_typed_resource_variant_has_an_authorized_boundary() {
    let fixture = Fixture::new();
    let cases = vec![
        (
            "file",
            FILE_PROVIDER,
            "read_file",
            file_claim("reports/q2.md", FileAccess::Read, DataClass::Confidential),
            PolicyDecision::Allowed,
        ),
        (
            "network",
            NETWORK_PROVIDER,
            "request",
            ResourceClaim::Network {
                method: "GET".to_owned(),
                origin: "https://api.example.test".to_owned(),
                classification: DataClass::Internal,
            },
            PolicyDecision::RequiresReview,
        ),
        (
            "email",
            EMAIL_PROVIDER,
            "send",
            ResourceClaim::Email {
                recipients: vec![
                    "finance@example.test".to_owned(),
                    "reviewer@example.test".to_owned(),
                ],
                classification: DataClass::Internal,
            },
            PolicyDecision::RequiresReview,
        ),
        (
            "memory",
            MEMORY_PROVIDER,
            "read",
            ResourceClaim::Memory {
                namespace: "session-memory".to_owned(),
                key: "story/q2".to_owned(),
                access: MemoryAccess::Read,
            },
            PolicyDecision::Allowed,
        ),
        (
            "code",
            CODE_PROVIDER,
            "execute",
            code_claim(allowed_code_limits()),
            PolicyDecision::RequiresReview,
        ),
        (
            "input",
            INPUT_PROVIDER,
            "inspect",
            ResourceClaim::InputInspection {
                source: "scenario.prompt".to_owned(),
                content_hash: Sha256Digest::from_bytes(b"prompt"),
                classification: DataClass::Confidential,
            },
            PolicyDecision::Allowed,
        ),
        (
            "evidence",
            EVIDENCE_PROVIDER,
            "read",
            ResourceClaim::Evidence {
                story_id: fixture.story_id,
                operation_id: fixture.evidence_operation,
            },
            PolicyDecision::Allowed,
        ),
        (
            "artifact",
            ARTIFACT_PROVIDER,
            "render",
            ResourceClaim::Artifact {
                relative_path: path("exports/stories/story.json"),
                format: "json".to_owned(),
            },
            PolicyDecision::RequiresReview,
        ),
    ];

    for (name, provider_id, action, claim, expected) in cases {
        let call = fixture.call(provider_id, action, json!({"case": name}));
        let evaluation = evaluate(
            &fixture,
            &fixture.session,
            &usage(4),
            &conservative_charge(provider_id),
            fixture.provider(provider_id),
            &call,
            &claim,
        );
        assert_eq!(evaluation.decision, expected, "{name}");
        assert_eq!(evaluation.resource_claim_hash, claim.digest(), "{name}");
        let terminal = if expected == PolicyDecision::RequiresReview {
            PolicyCheckStatus::RequiresReview
        } else {
            PolicyCheckStatus::Passed
        };
        assert_short_circuit(&evaluation, 5, terminal);
    }
}

#[test]
fn typed_resource_authority_rejects_every_variant_escape() {
    let fixture = Fixture::new();
    let mut code_runtime = allowed_code_limits();
    let mut code_workspace = allowed_code_limits();
    let mut code_network = allowed_code_limits();
    let mut wall_over = maximum_code_limits();
    wall_over.wall_time_ms += 1;
    let mut cpu_over = maximum_code_limits();
    cpu_over.cpu_time_ms += 1;
    let mut memory_over = maximum_code_limits();
    memory_over.memory_bytes += 1;
    let mut output_over = maximum_code_limits();
    output_over.output_bytes += 1;
    let mut process_over = maximum_code_limits();
    process_over.process_count += 1;
    // Keep these named separately so each mutated authority dimension is clear below.
    code_runtime.wall_time_ms = allowed_code_limits().wall_time_ms;
    code_workspace.wall_time_ms = allowed_code_limits().wall_time_ms;
    code_network.wall_time_ms = allowed_code_limits().wall_time_ms;

    let cases = vec![
        (
            "file root",
            FILE_PROVIDER,
            ResourceClaim::File {
                root: "host".to_owned(),
                path: path("reports/q2.md"),
                access: FileAccess::Read,
                classification: DataClass::Internal,
            },
            "file_root_not_allowed",
        ),
        (
            "file component prefix",
            FILE_PROVIDER,
            file_claim(
                "reports-private/q2.md",
                FileAccess::Read,
                DataClass::Internal,
            ),
            "path_not_allowed",
        ),
        (
            "file access",
            FILE_PROVIDER,
            ResourceClaim::File {
                root: "workspace".to_owned(),
                path: path("reports/q2.md"),
                access: FileAccess::Write,
                classification: DataClass::Internal,
            },
            "file_access_not_allowed",
        ),
        (
            "file classification",
            FILE_PROVIDER,
            file_claim("reports/q2.md", FileAccess::Read, DataClass::Restricted),
            "classification_not_allowed",
        ),
        (
            "network provider binding",
            BROWSER_PROVIDER,
            ResourceClaim::Network {
                method: "GET".to_owned(),
                origin: "https://api.example.test".to_owned(),
                classification: DataClass::Public,
            },
            "network_provider_not_allowed",
        ),
        (
            "network origin",
            NETWORK_PROVIDER,
            ResourceClaim::Network {
                method: "GET".to_owned(),
                origin: "https://attacker.example.test".to_owned(),
                classification: DataClass::Public,
            },
            "origin_not_allowed",
        ),
        (
            "network classification",
            NETWORK_PROVIDER,
            ResourceClaim::Network {
                method: "POST".to_owned(),
                origin: "https://api.example.test".to_owned(),
                classification: DataClass::Confidential,
            },
            "classification_not_allowed",
        ),
        (
            "empty email recipients",
            EMAIL_PROVIDER,
            ResourceClaim::Email {
                recipients: vec![],
                classification: DataClass::Public,
            },
            "recipient_not_allowed",
        ),
        (
            "email recipient",
            EMAIL_PROVIDER,
            ResourceClaim::Email {
                recipients: vec!["attacker@example.test".to_owned()],
                classification: DataClass::Public,
            },
            "recipient_not_allowed",
        ),
        (
            "email classification",
            EMAIL_PROVIDER,
            ResourceClaim::Email {
                recipients: vec!["finance@example.test".to_owned()],
                classification: DataClass::Confidential,
            },
            "classification_not_allowed",
        ),
        (
            "memory namespace",
            MEMORY_PROVIDER,
            ResourceClaim::Memory {
                namespace: "admin".to_owned(),
                key: "story/q2".to_owned(),
                access: MemoryAccess::Read,
            },
            "namespace_not_allowed",
        ),
        (
            "memory key prefix",
            MEMORY_PROVIDER,
            ResourceClaim::Memory {
                namespace: "session-memory".to_owned(),
                key: "admin/q2".to_owned(),
                access: MemoryAccess::Read,
            },
            "key_not_allowed",
        ),
        (
            "memory access",
            MEMORY_PROVIDER,
            ResourceClaim::Memory {
                namespace: "session-memory".to_owned(),
                key: "story/q2".to_owned(),
                access: MemoryAccess::Write,
            },
            "memory_access_not_allowed",
        ),
        (
            "code runtime",
            CODE_PROVIDER,
            ResourceClaim::CodeExecution {
                runtime: "node".to_owned(),
                workspace: "sandbox".to_owned(),
                network: NetworkCapability::None,
                limits: code_runtime,
            },
            "runtime_not_allowed",
        ),
        (
            "code workspace",
            CODE_PROVIDER,
            ResourceClaim::CodeExecution {
                runtime: "python3".to_owned(),
                workspace: "host".to_owned(),
                network: NetworkCapability::None,
                limits: code_workspace,
            },
            "workspace_not_allowed",
        ),
        (
            "code network",
            CODE_PROVIDER,
            ResourceClaim::CodeExecution {
                runtime: "python3".to_owned(),
                workspace: "sandbox".to_owned(),
                network: NetworkCapability::Brokered,
                limits: code_network,
            },
            "network_capability_not_allowed",
        ),
        (
            "code wall time",
            CODE_PROVIDER,
            code_claim(wall_over),
            "execution_limit_exceeded",
        ),
        (
            "code cpu time",
            CODE_PROVIDER,
            code_claim(cpu_over),
            "execution_limit_exceeded",
        ),
        (
            "code memory",
            CODE_PROVIDER,
            code_claim(memory_over),
            "execution_limit_exceeded",
        ),
        (
            "code output",
            CODE_PROVIDER,
            code_claim(output_over),
            "execution_limit_exceeded",
        ),
        (
            "code process count",
            CODE_PROVIDER,
            code_claim(process_over),
            "execution_limit_exceeded",
        ),
        (
            "input source",
            INPUT_PROVIDER,
            ResourceClaim::InputInspection {
                source: "ambient.environment".to_owned(),
                content_hash: Sha256Digest::from_bytes(b"prompt"),
                classification: DataClass::Public,
            },
            "input_source_not_allowed",
        ),
        (
            "input classification",
            INPUT_PROVIDER,
            ResourceClaim::InputInspection {
                source: "scenario.prompt".to_owned(),
                content_hash: Sha256Digest::from_bytes(b"prompt"),
                classification: DataClass::Restricted,
            },
            "classification_not_allowed",
        ),
        (
            "evidence story",
            EVIDENCE_PROVIDER,
            ResourceClaim::Evidence {
                story_id: StoryId::new(),
                operation_id: fixture.evidence_operation,
            },
            "evidence_story_not_allowed",
        ),
        (
            "evidence operation",
            EVIDENCE_PROVIDER,
            ResourceClaim::Evidence {
                story_id: fixture.story_id,
                operation_id: OperationId::new(),
            },
            "evidence_operation_not_allowed",
        ),
        (
            "artifact component prefix",
            ARTIFACT_PROVIDER,
            ResourceClaim::Artifact {
                relative_path: path("exports/stories-escape/story.json"),
                format: "json".to_owned(),
            },
            "artifact_path_not_allowed",
        ),
        (
            "artifact format",
            ARTIFACT_PROVIDER,
            ResourceClaim::Artifact {
                relative_path: path("exports/stories/story.exe"),
                format: "exe".to_owned(),
            },
            "artifact_format_not_allowed",
        ),
        (
            "legacy",
            FILE_PROVIDER,
            ResourceClaim::OpaqueLegacy {
                provider: FILE_PROVIDER.to_owned(),
                redacted_summary: "legacy request".to_owned(),
            },
            "legacy_claim_not_executable",
        ),
    ];

    for (name, provider_id, claim, denial_kind) in cases {
        let call = fixture.call(provider_id, "test", json!({"case": name}));
        let evaluation = evaluate(
            &fixture,
            &fixture.session,
            &usage(0),
            &conservative_charge(provider_id),
            fixture.provider(provider_id),
            &call,
            &claim,
        );
        assert_eq!(evaluation.decision, PolicyDecision::Denied, "{name}");
        assert_eq!(
            evaluation.denial_kind.as_deref(),
            Some(denial_kind),
            "{name}"
        );
        assert_short_circuit(&evaluation, 3, PolicyCheckStatus::Failed);
    }
}

#[test]
fn argument_and_wall_time_budgets_accept_exact_boundaries_and_deny_one_over() {
    let fixture = Fixture::new();
    let arguments = json!({"padding": "abcdefgh", "path": "reports/q2.md"});
    let argument_bytes = canonical_json_v1(&arguments).len() as u64;
    let call = fixture.call(FILE_PROVIDER, "read_file", arguments);
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);

    let exact_arguments = fixture.context_with(|authority| {
        authority.budgets.max_argument_bytes = argument_bytes;
    });
    let exact = evaluate(
        &fixture,
        &exact_arguments,
        &usage(31),
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &call,
        &claim,
    );
    assert_eq!(exact.decision, PolicyDecision::Allowed);
    assert_eq!(exact.budget_usage_version, 31);

    let one_argument_byte_over = fixture.context_with(|authority| {
        authority.budgets.max_argument_bytes = argument_bytes - 1;
    });
    let over = evaluate(
        &fixture,
        &one_argument_byte_over,
        &usage(31),
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &call,
        &claim,
    );
    assert_eq!(over.decision, PolicyDecision::Denied);
    assert_eq!(
        over.denial_kind.as_deref(),
        Some("argument_budget_exceeded")
    );
    assert_short_circuit(&over, 4, PolicyCheckStatus::Failed);

    let wall_context = fixture.context_with(|authority| {
        authority.budgets.max_wall_time_ms = 2_000;
        authority.code.as_mut().unwrap().maximum_limits.wall_time_ms = 10_000;
    });
    let code_call = fixture.call(CODE_PROVIDER, "execute", json!({"source": "print(1)"}));
    let mut exact_limits = allowed_code_limits();
    exact_limits.wall_time_ms = 2_000;
    let exact_wall = evaluate(
        &fixture,
        &wall_context,
        &usage(0),
        &conservative_charge(CODE_PROVIDER),
        fixture.provider(CODE_PROVIDER),
        &code_call,
        &code_claim(exact_limits.clone()),
    );
    assert_eq!(exact_wall.decision, PolicyDecision::RequiresReview);

    exact_limits.wall_time_ms += 1;
    let over_wall = evaluate(
        &fixture,
        &wall_context,
        &usage(0),
        &conservative_charge(CODE_PROVIDER),
        fixture.provider(CODE_PROVIDER),
        &code_call,
        &code_claim(exact_limits),
    );
    assert_eq!(over_wall.decision, PolicyDecision::Denied);
    assert_eq!(
        over_wall.denial_kind.as_deref(),
        Some("wall_time_budget_exceeded")
    );
    assert_short_circuit(&over_wall, 4, PolicyCheckStatus::Failed);
}

#[test]
fn cumulative_budgets_include_committed_and_concurrent_reserved_usage() {
    let fixture = Fixture::new();
    let file_call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let base_file_claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);

    let exact_calls = BudgetUsageSnapshot {
        calls_reserved: 39,
        calls_committed: 60,
        ..usage(41)
    };
    let allowed_call = evaluate(
        &fixture,
        &fixture.session,
        &exact_calls,
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &file_call,
        &base_file_claim,
    );
    assert_eq!(allowed_call.decision, PolicyDecision::Allowed);
    let denied_call = evaluate(
        &fixture,
        &fixture.session,
        &exact_calls,
        &charge(2, 1, 0),
        fixture.provider(FILE_PROVIDER),
        &file_call,
        &base_file_claim,
    );
    assert_eq!(
        denied_call.denial_kind.as_deref(),
        Some("call_budget_exceeded")
    );

    let file_usage = BudgetUsageSnapshot {
        file_bytes_reserved: 400,
        file_bytes_committed: 300,
        ..usage(42)
    };
    let exact_file = evaluate(
        &fixture,
        &fixture.session,
        &file_usage,
        &charge(1, 300, 0),
        fixture.provider(FILE_PROVIDER),
        &file_call,
        &base_file_claim,
    );
    assert_eq!(exact_file.decision, PolicyDecision::Allowed);
    assert_eq!(exact_file.budget_charge, charge(1, 300, 0));
    let file_over = evaluate(
        &fixture,
        &fixture.session,
        &file_usage,
        &charge(1, 301, 0),
        fixture.provider(FILE_PROVIDER),
        &file_call,
        &base_file_claim,
    );
    assert_eq!(
        file_over.denial_kind.as_deref(),
        Some("file_budget_exceeded")
    );

    let network_call = fixture.call(
        NETWORK_PROVIDER,
        "request",
        json!({"method": "GET", "url": "https://api.example.test/v1"}),
    );
    let network_claim = ResourceClaim::Network {
        method: "GET".to_owned(),
        origin: "https://api.example.test".to_owned(),
        classification: DataClass::Public,
    };
    let network_usage = BudgetUsageSnapshot {
        network_bytes_reserved: 700,
        network_bytes_committed: 500,
        ..usage(43)
    };
    let exact_network = evaluate(
        &fixture,
        &fixture.session,
        &network_usage,
        &charge(1, 0, 800),
        fixture.provider(NETWORK_PROVIDER),
        &network_call,
        &network_claim,
    );
    assert_eq!(exact_network.decision, PolicyDecision::RequiresReview);
    let network_over = evaluate(
        &fixture,
        &fixture.session,
        &network_usage,
        &charge(1, 0, 801),
        fixture.provider(NETWORK_PROVIDER),
        &network_call,
        &network_claim,
    );
    assert_eq!(
        network_over.denial_kind.as_deref(),
        Some("network_budget_exceeded")
    );

    for evaluation in [denied_call, file_over, network_over] {
        assert_eq!(evaluation.decision, PolicyDecision::Denied);
        assert_short_circuit(&evaluation, 4, PolicyCheckStatus::Failed);
    }
}

#[test]
fn budget_arithmetic_overflow_is_denied_instead_of_wrapping() {
    let fixture = Fixture::new();
    let unlimited = fixture.context_with(|authority| authority.budgets.max_calls = u64::MAX);
    let call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let overflowed = BudgetUsageSnapshot {
        calls_reserved: u64::MAX,
        ..usage(99)
    };

    let evaluation = evaluate(
        &fixture,
        &unlimited,
        &overflowed,
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Denied);
    assert_eq!(
        evaluation.denial_kind.as_deref(),
        Some("budget_arithmetic_overflow")
    );
    assert_short_circuit(&evaluation, 4, PolicyCheckStatus::Failed);
}

#[test]
fn zero_call_budget_charge_is_rejected_before_lease_reservation() {
    let fixture = Fixture::new();
    let call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);

    let evaluation = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &charge(0, 1, 0),
        fixture.provider(FILE_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Denied);
    assert_eq!(
        evaluation.denial_kind.as_deref(),
        Some("invalid_budget_charge")
    );
    assert_short_circuit(&evaluation, 4, PolicyCheckStatus::Failed);
}

#[test]
fn duplicate_provider_registration_fails_and_preserves_the_canonical_provider() {
    let mut registry = ProviderRegistry::default();
    let original = provider(
        FILE_PROVIDER,
        ProviderRisk::Low,
        vec![SideEffectKind::FileRead],
    );
    registry.register(original.clone()).unwrap();

    let forged_replacement = provider(FILE_PROVIDER, ProviderRisk::Low, vec![]);
    let error = registry.register(forged_replacement).unwrap_err();

    assert_eq!(
        error,
        ProviderRegistryError::DuplicateId(FILE_PROVIDER.to_owned())
    );
    assert_eq!(registry.get(FILE_PROVIDER), Some(&original));
}

#[test]
fn provider_identity_is_bound_to_the_server_registered_canonical_contract() {
    let fixture = Fixture::new();
    let call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["finance@example.test"]}),
    );
    let claim = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    let mut forged = fixture.provider(EMAIL_PROVIDER).clone();
    forged.risk = ProviderRisk::Low;
    forged.side_effects.clear();

    let evaluation = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &conservative_charge(EMAIL_PROVIDER),
        &forged,
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Denied);
    assert_eq!(
        evaluation.denial_kind.as_deref(),
        Some("provider_contract_mismatch")
    );
    assert_short_circuit(&evaluation, 1, PolicyCheckStatus::Failed);
}

#[test]
fn call_provider_must_exactly_match_the_canonical_provider_identity() {
    let fixture = Fixture::new();
    let call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["finance@example.test"]}),
    );
    let claim = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
        classification: DataClass::Internal,
    };

    let evaluation = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &conservative_charge(FILE_PROVIDER),
        fixture.provider(FILE_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Denied);
    assert_eq!(
        evaluation.denial_kind.as_deref(),
        Some("provider_identity_mismatch")
    );
    assert_short_circuit(&evaluation, 1, PolicyCheckStatus::Failed);
}

#[test]
fn one_resource_binding_proof_rejects_every_substituted_extraction_input() {
    let fixture = Fixture::new();
    let file_provider = fixture.provider(FILE_PROVIDER);
    let file_call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let base_file_claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let file_charge = conservative_charge(FILE_PROVIDER);
    let file_proof = fixture.bind(
        &fixture.session,
        &file_charge,
        file_provider,
        &file_call,
        &base_file_claim,
    );

    let changed_path_call =
        fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q3.md"}));
    let changed_path_claim = file_claim("reports/q3.md", FileAccess::Read, DataClass::Internal);
    let changed_variant = ResourceClaim::Memory {
        namespace: "session-memory".to_owned(),
        key: "story/q2".to_owned(),
        access: MemoryAccess::Read,
    };
    let changed_provider_call = fixture.call(
        MEMORY_PROVIDER,
        &file_call.action,
        file_call.arguments.clone(),
    );
    let mut changed_action_call = file_call.clone();
    changed_action_call.action = "read_file_v2".to_owned();
    let changed_charge = charge(1, 2, 0);

    for (name, provider, call, claim, proposed_charge) in [
        (
            "path arguments",
            file_provider,
            &changed_path_call,
            &base_file_claim,
            file_charge,
        ),
        (
            "path claim",
            file_provider,
            &file_call,
            &changed_path_claim,
            file_charge,
        ),
        (
            "claim variant",
            file_provider,
            &file_call,
            &changed_variant,
            file_charge,
        ),
        (
            "provider contract and id",
            fixture.provider(MEMORY_PROVIDER),
            &changed_provider_call,
            &base_file_claim,
            file_charge,
        ),
        (
            "action",
            file_provider,
            &changed_action_call,
            &base_file_claim,
            file_charge,
        ),
        (
            "budget charge",
            file_provider,
            &file_call,
            &base_file_claim,
            changed_charge,
        ),
    ] {
        let evaluation = evaluate_with_proof(
            &fixture.session,
            &usage(0),
            &proposed_charge,
            provider,
            call,
            claim,
            &file_proof,
        );
        assert_resource_binding_denial(name, &evaluation);
    }

    let monitor_session = SessionContext::from_authority(
        fixture.story_id,
        fixture.session.authority.clone(),
        &fixture.registry,
        EnforcementMode::MonitorOnly,
        fixture.binding_verifier.clone(),
    )
    .unwrap();
    let changed_mode = evaluate_with_proof(
        &monitor_session,
        &usage(0),
        &file_charge,
        file_provider,
        &file_call,
        &base_file_claim,
        &file_proof,
    );
    assert_resource_binding_denial("enforcement mode", &changed_mode);

    let network_provider = fixture.provider(NETWORK_PROVIDER);
    let network_call = fixture.call(
        NETWORK_PROVIDER,
        "request",
        json!({"method": "GET", "url": "https://api.example.test/v1"}),
    );
    let network_claim = ResourceClaim::Network {
        method: "GET".to_owned(),
        origin: "https://api.example.test".to_owned(),
        classification: DataClass::Public,
    };
    let network_charge = conservative_charge(NETWORK_PROVIDER);
    let network_proof = fixture.bind(
        &fixture.session,
        &network_charge,
        network_provider,
        &network_call,
        &network_claim,
    );
    let changed_url_call = fixture.call(
        NETWORK_PROVIDER,
        "request",
        json!({"method": "GET", "url": "https://api.example.test/v2"}),
    );
    let changed_url = evaluate_with_proof(
        &fixture.session,
        &usage(0),
        &network_charge,
        network_provider,
        &changed_url_call,
        &network_claim,
        &network_proof,
    );
    assert_resource_binding_denial("url arguments", &changed_url);

    let email_provider = fixture.provider(EMAIL_PROVIDER);
    let email_call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["finance@example.test"]}),
    );
    let email_claim = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    let email_charge = conservative_charge(EMAIL_PROVIDER);
    let email_proof = fixture.bind(
        &fixture.session,
        &email_charge,
        email_provider,
        &email_call,
        &email_claim,
    );
    let changed_recipient_call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["reviewer@example.test"]}),
    );
    let changed_recipient_claim = ResourceClaim::Email {
        recipients: vec!["reviewer@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    let changed_recipient_arguments = evaluate_with_proof(
        &fixture.session,
        &usage(0),
        &email_charge,
        email_provider,
        &changed_recipient_call,
        &email_claim,
        &email_proof,
    );
    assert_resource_binding_denial("email recipient arguments", &changed_recipient_arguments);
    let changed_recipient_claim_only = evaluate_with_proof(
        &fixture.session,
        &usage(0),
        &email_charge,
        email_provider,
        &email_call,
        &changed_recipient_claim,
        &email_proof,
    );
    assert_resource_binding_denial("email recipient claim", &changed_recipient_claim_only);
    let changed_classification = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
        classification: DataClass::Public,
    };
    let changed_classification = evaluate_with_proof(
        &fixture.session,
        &usage(0),
        &email_charge,
        email_provider,
        &email_call,
        &changed_classification,
        &email_proof,
    );
    assert_resource_binding_denial("classification", &changed_classification);
}

#[test]
fn proof_from_another_process_authority_is_rejected_without_an_oracle() {
    let fixture = Fixture::new();
    let provider = fixture.provider(FILE_PROVIDER);
    let call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let proposed_charge = conservative_charge(FILE_PROVIDER);
    let proof = fixture.bind(&fixture.session, &proposed_charge, provider, &call, &claim);
    let (_, foreign_verifier) =
        ResourceBindingAuthority::generate().expect("foreign resource binding authority");

    assert_eq!(
        foreign_verifier.validate(
            &proof,
            provider,
            &call.action,
            &call.arguments,
            &claim,
            &proposed_charge,
            fixture.session.enforcement_mode,
        ),
        Err(ResourceBindingValidationError::AuthenticationFailed)
    );

    let foreign_session = SessionContext::from_authority(
        fixture.story_id,
        fixture.session.authority.clone(),
        &fixture.registry,
        fixture.session.enforcement_mode,
        foreign_verifier,
    )
    .unwrap();
    let evaluation = evaluate_with_proof(
        &foreign_session,
        &usage(0),
        &proposed_charge,
        provider,
        &call,
        &claim,
        &proof,
    );
    assert_resource_binding_denial("foreign verifier", &evaluation);
}

#[test]
fn post_construction_session_context_mutation_always_fails_at_the_session_layer() {
    let fixture = Fixture::new();
    let provider = fixture.provider(FILE_PROVIDER);
    let call = fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"}));
    let claim = file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal);
    let proposed_charge = conservative_charge(FILE_PROVIDER);
    let proof = fixture.bind(&fixture.session, &proposed_charge, provider, &call, &claim);

    let mut story = fixture.session.clone();
    story.story_id = StoryId::new();
    let mut session = fixture.session.clone();
    session.session_id = SessionId::new();
    let mut authority = fixture.session.clone();
    authority.authority.actor_id = "attacker".to_owned();
    let mut enforcement_mode = fixture.session.clone();
    enforcement_mode.enforcement_mode = EnforcementMode::MonitorOnly;

    for (name, context) in [
        ("story id", story),
        ("session id", session),
        ("authority snapshot", authority),
        ("enforcement mode", enforcement_mode),
    ] {
        let evaluation = evaluate_with_proof(
            &context,
            &usage(0),
            &proposed_charge,
            provider,
            &call,
            &claim,
            &proof,
        );
        assert_eq!(evaluation.decision, PolicyDecision::Denied, "{name}");
        assert_eq!(
            evaluation.denial_kind.as_deref(),
            Some("session_mismatch"),
            "{name}"
        );
        assert_short_circuit(&evaluation, 0, PolicyCheckStatus::Failed);
    }
}

#[test]
fn canonical_http_token_punctuation_from_the_extractor_is_policy_compatible() {
    let fixture = Fixture::new();
    let call = fixture.call(
        NETWORK_PROVIDER,
        "request",
        json!({"method": "custom!", "url": "https://api.example.test/v1"}),
    );
    let claim = ResourceClaim::Network {
        method: "CUSTOM!".to_owned(),
        origin: "https://api.example.test".to_owned(),
        classification: DataClass::Public,
    };

    let evaluation = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &conservative_charge(NETWORK_PROVIDER),
        fixture.provider(NETWORK_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::RequiresReview);
    assert_short_circuit(&evaluation, 5, PolicyCheckStatus::RequiresReview);
}

#[test]
fn declared_file_network_and_artifact_side_effects_require_nonzero_reservations() {
    let fixture = Fixture::new();
    let cases = [
        (
            "file read",
            FILE_PROVIDER,
            fixture.call(FILE_PROVIDER, "read_file", json!({"path": "reports/q2.md"})),
            file_claim("reports/q2.md", FileAccess::Read, DataClass::Internal),
        ),
        (
            "network",
            NETWORK_PROVIDER,
            fixture.call(
                NETWORK_PROVIDER,
                "request",
                json!({"method": "GET", "url": "https://api.example.test/v1"}),
            ),
            ResourceClaim::Network {
                method: "GET".to_owned(),
                origin: "https://api.example.test".to_owned(),
                classification: DataClass::Public,
            },
        ),
        (
            "artifact write",
            ARTIFACT_PROVIDER,
            fixture.call(ARTIFACT_PROVIDER, "render", json!({"format": "json"})),
            ResourceClaim::Artifact {
                relative_path: path("exports/stories/story.json"),
                format: "json".to_owned(),
            },
        ),
    ];

    for (name, provider_id, call, claim) in cases {
        let zero_side_effect_charge = charge(1, 0, 0);
        let evaluation = evaluate(
            &fixture,
            &fixture.session,
            &usage(0),
            &zero_side_effect_charge,
            fixture.provider(provider_id),
            &call,
            &claim,
        );
        assert_eq!(evaluation.decision, PolicyDecision::Denied, "{name}");
        assert_eq!(
            evaluation.denial_kind.as_deref(),
            Some("invalid_budget_charge"),
            "{name}"
        );
        assert_short_circuit(&evaluation, 4, PolicyCheckStatus::Failed);
    }
}

#[test]
fn store_key_prefix_is_a_literal_kv_byte_prefix_not_a_path_component() {
    let fixture = Fixture::new();
    let context = fixture.context_with(|authority| {
        authority.stores[0].key_prefix = "story".to_owned();
    });
    let call = fixture.call(MEMORY_PROVIDER, "read", json!({"key": "storyevil"}));
    let claim = ResourceClaim::Memory {
        namespace: "session-memory".to_owned(),
        key: "storyevil".to_owned(),
        access: MemoryAccess::Read,
    };

    let evaluation = evaluate(
        &fixture,
        &context,
        &usage(0),
        &conservative_charge(MEMORY_PROVIDER),
        fixture.provider(MEMORY_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Allowed);
}

#[test]
fn resource_binding_proof_source_has_no_copy_log_or_wire_traits() {
    let source = include_str!("../src/resource_binding.rs");
    let declaration = source
        .find("pub struct ResourceBindingProof")
        .expect("resource binding proof declaration");
    let declaration_prefix = &source[declaration.saturating_sub(160)..declaration];

    assert!(!declaration_prefix.contains("#[derive"));
    for forbidden in [
        "impl Clone for ResourceBindingProof",
        "impl Copy for ResourceBindingProof",
        "impl fmt::Debug for ResourceBindingProof",
        "impl Serialize for ResourceBindingProof",
        "impl serde::Serialize for ResourceBindingProof",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden proof trait: {forbidden}"
        );
    }
}

#[test]
fn pure_policy_never_consumes_or_trusts_a_caller_supplied_approval_id() {
    let fixture = Fixture::new();
    let mut call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["finance@example.test"]}),
    );
    call.approval_id = Some("caller-forged-approval".to_owned());
    let claim = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_owned()],
        classification: DataClass::Internal,
    };
    let before_authority = fixture.session.authority.clone();
    let before_usage = usage(55);
    let proposed_charge = conservative_charge(EMAIL_PROVIDER);

    let first = evaluate(
        &fixture,
        &fixture.session,
        &before_usage,
        &proposed_charge,
        fixture.provider(EMAIL_PROVIDER),
        &call,
        &claim,
    );
    let second = evaluate(
        &fixture,
        &fixture.session,
        &before_usage,
        &proposed_charge,
        fixture.provider(EMAIL_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(first.decision, PolicyDecision::RequiresReview);
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
    assert_eq!(fixture.session.authority, before_authority);
    assert_eq!(first.budget_usage_version, before_usage.version);
    assert_eq!(first.budget_charge, proposed_charge);
}

#[test]
fn monitor_only_context_does_not_weaken_the_typed_policy_decision() {
    let fixture = Fixture::new_with_mode(EnforcementMode::MonitorOnly);
    let call = fixture.call(
        EMAIL_PROVIDER,
        "send",
        json!({"to": ["attacker@example.test"]}),
    );
    let claim = ResourceClaim::Email {
        recipients: vec!["attacker@example.test".to_owned()],
        classification: DataClass::Public,
    };

    let evaluation = evaluate(
        &fixture,
        &fixture.session,
        &usage(0),
        &conservative_charge(EMAIL_PROVIDER),
        fixture.provider(EMAIL_PROVIDER),
        &call,
        &claim,
    );

    assert_eq!(evaluation.decision, PolicyDecision::Denied);
    assert_eq!(
        evaluation.denial_kind.as_deref(),
        Some("recipient_not_allowed")
    );
}

#[test]
fn typed_policy_source_never_scans_argument_key_names() {
    let source = include_str!("../src/policy.rs");

    assert!(!source.contains("collect_argument_strings"));
    assert!(!source.contains("validate_roots"));
    assert!(!source.contains("validate_egress"));
    assert!(!source.contains("contains(\"url\")"));
    assert!(!source.contains("ends_with(\"path\")"));
}
