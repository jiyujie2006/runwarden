//! Pure typed policy evaluation for native provider proposals.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::artifact::WorkspaceRelativePath;
use crate::contracts::{
    KernelProvider, PolicyDecision, ProviderCall, SideEffectKind, provider_requires_approval,
};
use crate::kernel::ProviderRegistry;
use crate::operation::{PolicyCheck, PolicyCheckStatus};
use crate::resource::{
    DataClass, ExecutionLimits, FileAccess, MemoryAccess, NetworkCapability, ResourceClaim,
    canonical_provider_contract_hash,
};
use crate::resource_binding::{ResourceBindingProof, ResourceBindingVerifier};
use crate::session::{AuthoritySnapshot, BudgetCharge, BudgetUsageSnapshot};
use crate::story::{EnforcementMode, SessionId, StoryId};
use crate::trace::{Sha256Digest, canonical_json_v1};

/// Server-owned immutable inputs to typed policy evaluation.
///
/// The public fields preserve the story contract's projection API. Private
/// commitments make later mutation fail closed and bind every allowed id to
/// the complete provider object that the server registered at construction.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub authority: AuthoritySnapshot,
    pub enforcement_mode: EnforcementMode,
    bound_story_id: StoryId,
    bound_session_id: SessionId,
    bound_enforcement_mode: EnforcementMode,
    authority_snapshot_hash: Sha256Digest,
    policy_snapshot_hash: Sha256Digest,
    provider_contract_hashes: BTreeMap<String, Sha256Digest>,
    resource_binding_verifier: ResourceBindingVerifier,
}

impl SessionContext {
    pub fn from_authority(
        story_id: StoryId,
        authority: AuthoritySnapshot,
        registry: &ProviderRegistry,
        enforcement_mode: EnforcementMode,
        resource_binding_verifier: ResourceBindingVerifier,
    ) -> Result<Self, SessionContextError> {
        let policy_snapshot_hash = Sha256Digest::try_from(authority.policy_snapshot_hash.clone())
            .map_err(|_| SessionContextError::InvalidPolicySnapshotHash)?;
        let mut provider_contract_hashes = BTreeMap::new();
        for provider_id in &authority.allowed_providers {
            let provider = registry
                .get(provider_id)
                .ok_or_else(|| SessionContextError::AllowedProviderMissing(provider_id.clone()))?;
            provider_contract_hashes.insert(
                provider_id.clone(),
                canonical_provider_contract_hash(provider),
            );
        }
        let session_id = authority.session_id;
        let authority_snapshot_hash = authority_digest(&authority);
        Ok(Self {
            story_id,
            session_id,
            authority,
            enforcement_mode,
            bound_story_id: story_id,
            bound_session_id: session_id,
            bound_enforcement_mode: enforcement_mode,
            authority_snapshot_hash,
            policy_snapshot_hash,
            provider_contract_hashes,
            resource_binding_verifier,
        })
    }

    pub fn registered_provider_contract_hash(&self, provider_id: &str) -> Option<&Sha256Digest> {
        self.provider_contract_hashes.get(provider_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionContextError {
    #[error("authority policy snapshot hash is not a canonical SHA-256 digest")]
    InvalidPolicySnapshotHash,
    #[error("allowed provider is missing from the server registry: {0}")]
    AllowedProviderMissing(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub denial_kind: Option<String>,
    pub reason: String,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub budget_usage_version: u64,
    pub budget_charge: BudgetCharge,
    pub checks: Vec<PolicyCheck>,
}

/// Evaluates one frozen proposal without reading approvals, reserving budget,
/// mutating session state, or performing a side effect.
#[allow(clippy::too_many_arguments)] // Frozen security-boundary tuple; every item is authenticated.
pub fn evaluate_proposal(
    session: &SessionContext,
    usage: &BudgetUsageSnapshot,
    charge: &BudgetCharge,
    provider: &KernelProvider,
    call: &ProviderCall,
    claim: &ResourceClaim,
    binding_proof: &ResourceBindingProof,
    now: OffsetDateTime,
) -> PolicyEvaluation {
    let mut checks = Vec::with_capacity(6);
    let mut terminal = None;

    record_check(&mut checks, &mut terminal, "session", "session", || {
        check_session(session, call, now)
    });
    record_check(&mut checks, &mut terminal, "provider", "provider", || {
        check_provider(session, provider, call)
    });
    record_check(&mut checks, &mut terminal, "authz", "authorization", || {
        check_authorization(session, call)
    });
    record_check(&mut checks, &mut terminal, "resource", "resource", || {
        check_resource(session, provider, call, claim, charge, binding_proof)
    });
    record_check(&mut checks, &mut terminal, "budget", "budget", || {
        check_budget(session, usage, charge, provider, call, claim)
    });
    record_check(&mut checks, &mut terminal, "approval", "approval", || {
        check_approval(provider)
    });

    let (decision, denial_kind, reason) = match terminal {
        Some(Terminal::Denied(failure)) => (
            PolicyDecision::Denied,
            Some(failure.kind.to_owned()),
            failure.reason.to_owned(),
        ),
        Some(Terminal::Review(reason)) => (PolicyDecision::RequiresReview, None, reason.to_owned()),
        None => (
            PolicyDecision::Allowed,
            None,
            "typed policy allows the proposal before any side effect".to_owned(),
        ),
    };

    PolicyEvaluation {
        decision,
        denial_kind,
        reason,
        resource_claim_hash: claim.digest(),
        policy_snapshot_hash: session.policy_snapshot_hash.clone(),
        budget_usage_version: usage.version,
        budget_charge: *charge,
        checks,
    }
}

#[derive(Debug, Clone, Copy)]
struct Failure {
    kind: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone, Copy)]
enum StageOutcome {
    Passed(&'static str),
    Failed(Failure),
    Review(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum Terminal {
    Denied(Failure),
    Review(&'static str),
}

fn record_check(
    checks: &mut Vec<PolicyCheck>,
    terminal: &mut Option<Terminal>,
    check_id: &'static str,
    layer: &'static str,
    evaluate: impl FnOnce() -> StageOutcome,
) {
    if terminal.is_some() {
        checks.push(policy_check(
            check_id,
            layer,
            PolicyCheckStatus::NotEvaluated,
            "not evaluated after an earlier terminal policy result",
        ));
        return;
    }

    match evaluate() {
        StageOutcome::Passed(reason) => checks.push(policy_check(
            check_id,
            layer,
            PolicyCheckStatus::Passed,
            reason,
        )),
        StageOutcome::Failed(failure) => {
            checks.push(policy_check(
                check_id,
                layer,
                PolicyCheckStatus::Failed,
                failure.reason,
            ));
            *terminal = Some(Terminal::Denied(failure));
        }
        StageOutcome::Review(reason) => {
            checks.push(policy_check(
                check_id,
                layer,
                PolicyCheckStatus::RequiresReview,
                reason,
            ));
            *terminal = Some(Terminal::Review(reason));
        }
    }
}

fn policy_check(
    check_id: &str,
    layer: &str,
    status: PolicyCheckStatus,
    reason: &str,
) -> PolicyCheck {
    PolicyCheck {
        check_id: check_id.to_owned(),
        layer: layer.to_owned(),
        status,
        reason: reason.to_owned(),
        observation_ref: None,
    }
}

fn pass(reason: &'static str) -> StageOutcome {
    StageOutcome::Passed(reason)
}

fn fail(kind: &'static str, reason: &'static str) -> StageOutcome {
    StageOutcome::Failed(Failure { kind, reason })
}

fn check_session(
    session: &SessionContext,
    call: &ProviderCall,
    now: OffsetDateTime,
) -> StageOutcome {
    if session.story_id != session.bound_story_id
        || session.session_id != session.bound_session_id
        || session.enforcement_mode != session.bound_enforcement_mode
        || session.authority.session_id != session.bound_session_id
        || authority_digest(&session.authority) != session.authority_snapshot_hash
        || session.authority.policy_snapshot_hash != session.policy_snapshot_hash.as_str()
        || call.session_id != session.bound_session_id.to_string()
    {
        return fail(
            "session_mismatch",
            "proposal does not match the immutable story and session context",
        );
    }
    if now >= session.authority.expires_at {
        return fail(
            "session_expired",
            "session authority expired before policy evaluation",
        );
    }
    pass("proposal matches an unexpired immutable session")
}

fn check_provider(
    session: &SessionContext,
    provider: &KernelProvider,
    call: &ProviderCall,
) -> StageOutcome {
    if call.provider != provider.id {
        return fail(
            "provider_identity_mismatch",
            "proposal provider id does not match the evaluated provider",
        );
    }
    if !session
        .authority
        .allowed_providers
        .iter()
        .any(|allowed| allowed == &provider.id)
    {
        return fail(
            "provider_not_allowed",
            "provider is outside the session allowlist",
        );
    }
    let Some(expected) = session.provider_contract_hashes.get(&provider.id) else {
        return fail(
            "provider_contract_mismatch",
            "provider has no server-registered contract commitment",
        );
    };
    if expected != &canonical_provider_contract_hash(provider) {
        return fail(
            "provider_contract_mismatch",
            "provider contract differs from the server-registered contract",
        );
    }
    pass("provider id, allowlist, and canonical contract match")
}

fn check_authorization(session: &SessionContext, call: &ProviderCall) -> StageOutcome {
    if session.authority.authz_state != "active" {
        return fail("authz_inactive", "session authorization is not active");
    }
    if call.actor_id.as_deref() != Some(session.authority.actor_id.as_str()) {
        return fail(
            "actor_mismatch",
            "proposal actor does not match the session",
        );
    }
    if call.authz_id.as_deref() != Some(session.authority.authz_id.as_str()) {
        return fail(
            "authz_mismatch",
            "proposal authorization does not match the session",
        );
    }
    pass("actor and active authorization match the session")
}

fn check_resource(
    session: &SessionContext,
    provider: &KernelProvider,
    call: &ProviderCall,
    claim: &ResourceClaim,
    charge: &BudgetCharge,
    binding_proof: &ResourceBindingProof,
) -> StageOutcome {
    if session
        .resource_binding_verifier
        .validate(
            binding_proof,
            provider,
            &call.action,
            &call.arguments,
            claim,
            charge,
            session.enforcement_mode,
        )
        .is_err()
    {
        return fail(
            "resource_binding_invalid",
            "resource extraction binding does not match the frozen proposal",
        );
    }
    match claim {
        ResourceClaim::File {
            root,
            path,
            access,
            classification,
        } => check_file(session, root, path, *access, *classification),
        ResourceClaim::Network {
            method,
            origin,
            classification,
        } => check_network(session, call, method, origin, *classification),
        ResourceClaim::Email {
            recipients,
            classification,
        } => check_email(session, recipients, *classification),
        ResourceClaim::Memory {
            namespace,
            key,
            access,
        } => check_memory(session, namespace, key, *access),
        ResourceClaim::CodeExecution {
            runtime,
            workspace,
            network,
            limits,
        } => check_code(session, runtime, workspace, *network, limits),
        ResourceClaim::InputInspection {
            source,
            classification,
            ..
        } => check_input(session, source, *classification),
        ResourceClaim::Evidence {
            story_id,
            operation_id,
        } => {
            if story_id != &session.story_id || !session.authority.evidence.current_story_only {
                fail(
                    "evidence_story_not_allowed",
                    "evidence claim is not bound to the current story",
                )
            } else if !session
                .authority
                .evidence
                .allowed_operations
                .contains(operation_id)
            {
                fail(
                    "evidence_operation_not_allowed",
                    "evidence operation is outside the session authority",
                )
            } else {
                pass("evidence story and operation are authorized")
            }
        }
        ResourceClaim::Artifact {
            relative_path,
            format,
        } => check_artifact(session, relative_path, format),
        ResourceClaim::OpaqueLegacy { .. } => fail(
            "legacy_claim_not_executable",
            "opaque legacy resource claims are display-only",
        ),
    }
}

fn check_file(
    session: &SessionContext,
    root: &str,
    path: &WorkspaceRelativePath,
    access: FileAccess,
    classification: DataClass,
) -> StageOutcome {
    let roots = session
        .authority
        .files
        .iter()
        .filter(|authority| authority.root == root)
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return fail(
            "file_root_not_allowed",
            "file root is outside the session authority",
        );
    }
    let paths = roots
        .into_iter()
        .filter(|authority| relative_prefix_matches(&authority.path_prefix, path.as_str()))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return fail(
            "path_not_allowed",
            "file path is outside the authorized component prefix",
        );
    }
    let accesses = paths
        .into_iter()
        .filter(|authority| authority.access.contains(&access))
        .collect::<Vec<_>>();
    if accesses.is_empty() {
        return fail(
            "file_access_not_allowed",
            "file access mode is outside the session authority",
        );
    }
    if !accesses
        .iter()
        .any(|authority| classification.is_within(&authority.maximum_classification))
    {
        return fail(
            "classification_not_allowed",
            "file classification exceeds the session ceiling",
        );
    }
    pass("typed file root, path, access, and classification are authorized")
}

fn check_network(
    session: &SessionContext,
    call: &ProviderCall,
    method: &str,
    origin: &str,
    classification: DataClass,
) -> StageOutcome {
    let providers = session
        .authority
        .networks
        .iter()
        .filter(|authority| authority.provider == call.provider)
        .collect::<Vec<_>>();
    if providers.is_empty() {
        return fail(
            "network_provider_not_allowed",
            "network authority is not granted to this provider",
        );
    }
    if !is_canonical_http_method(method) || !is_canonical_origin(origin) {
        return fail(
            "origin_not_allowed",
            "network method or origin is not canonical",
        );
    }
    let origins = providers
        .into_iter()
        .filter(|authority| {
            authority
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
        })
        .collect::<Vec<_>>();
    if origins.is_empty() {
        return fail(
            "origin_not_allowed",
            "network origin is outside the provider-specific authority",
        );
    }
    if !origins
        .iter()
        .any(|authority| classification.is_within(&authority.maximum_classification))
    {
        return fail(
            "classification_not_allowed",
            "network classification exceeds the session ceiling",
        );
    }
    pass("typed network provider, origin, and classification are authorized")
}

fn check_email(
    session: &SessionContext,
    recipients: &[String],
    classification: DataClass,
) -> StageOutcome {
    let Some(authority) = session.authority.email.as_ref() else {
        return fail(
            "recipient_not_allowed",
            "session grants no email recipient authority",
        );
    };
    if recipients.is_empty()
        || !recipients_are_canonical(recipients)
        || recipients.iter().any(|recipient| {
            !authority
                .allowed_recipients
                .iter()
                .any(|allowed| allowed == recipient)
        })
    {
        return fail(
            "recipient_not_allowed",
            "one or more email recipients are outside the session authority",
        );
    }
    if !classification.is_within(&authority.maximum_classification) {
        return fail(
            "classification_not_allowed",
            "email classification exceeds the session ceiling",
        );
    }
    pass("every canonical email recipient and classification are authorized")
}

fn check_memory(
    session: &SessionContext,
    namespace: &str,
    key: &str,
    access: MemoryAccess,
) -> StageOutcome {
    let namespaces = session
        .authority
        .stores
        .iter()
        .filter(|authority| authority.namespace == namespace)
        .collect::<Vec<_>>();
    if namespaces.is_empty() {
        return fail(
            "namespace_not_allowed",
            "memory namespace is outside the session authority",
        );
    }
    let keys = namespaces
        .into_iter()
        .filter(|authority| !key.is_empty() && key.starts_with(&authority.key_prefix))
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return fail(
            "key_not_allowed",
            "memory key is outside the authorized prefix",
        );
    }
    if !keys
        .iter()
        .any(|authority| authority.access.contains(&access))
    {
        return fail(
            "memory_access_not_allowed",
            "memory access mode is outside the session authority",
        );
    }
    pass("typed memory namespace, key, and access are authorized")
}

fn check_code(
    session: &SessionContext,
    runtime: &str,
    workspace: &str,
    network: NetworkCapability,
    limits: &ExecutionLimits,
) -> StageOutcome {
    let Some(authority) = session.authority.code.as_ref() else {
        return fail("runtime_not_allowed", "session grants no code authority");
    };
    if !authority
        .allowed_runtimes
        .iter()
        .any(|allowed| allowed == runtime)
    {
        return fail(
            "runtime_not_allowed",
            "code runtime is outside the session authority",
        );
    }
    if workspace != authority.workspace {
        return fail(
            "workspace_not_allowed",
            "code workspace is outside the session authority",
        );
    }
    if !network_is_within(network, authority.network) {
        return fail(
            "network_capability_not_allowed",
            "code network capability exceeds the session authority",
        );
    }
    if !execution_limits_are_within(limits, &authority.maximum_limits) {
        return fail(
            "execution_limit_exceeded",
            "one or more code execution limits exceed the session authority",
        );
    }
    pass("typed code runtime, workspace, network, and limits are authorized")
}

fn check_input(session: &SessionContext, source: &str, classification: DataClass) -> StageOutcome {
    let sources = session
        .authority
        .inputs
        .iter()
        .filter(|authority| {
            authority
                .allowed_sources
                .iter()
                .any(|allowed| allowed == source)
        })
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return fail(
            "input_source_not_allowed",
            "input source is outside the session authority",
        );
    }
    if !sources
        .iter()
        .any(|authority| classification.is_within(&authority.maximum_classification))
    {
        return fail(
            "classification_not_allowed",
            "input classification exceeds the session ceiling",
        );
    }
    pass("typed input source and classification are authorized")
}

fn check_artifact(
    session: &SessionContext,
    relative_path: &WorkspaceRelativePath,
    format: &str,
) -> StageOutcome {
    let paths = session
        .authority
        .artifacts
        .iter()
        .filter(|authority| {
            relative_prefix_matches(authority.path_prefix.as_str(), relative_path.as_str())
        })
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return fail(
            "artifact_path_not_allowed",
            "artifact path is outside the authorized component prefix",
        );
    }
    if format.is_empty()
        || !paths.iter().any(|authority| {
            authority
                .allowed_formats
                .iter()
                .any(|allowed| allowed == format)
        })
    {
        return fail(
            "artifact_format_not_allowed",
            "artifact format is outside the session authority",
        );
    }
    pass("typed artifact path and format are authorized")
}

fn check_budget(
    session: &SessionContext,
    usage: &BudgetUsageSnapshot,
    charge: &BudgetCharge,
    provider: &KernelProvider,
    call: &ProviderCall,
    claim: &ResourceClaim,
) -> StageOutcome {
    if charge.calls == 0 {
        return fail(
            "invalid_budget_charge",
            "an executable provider proposal must reserve at least one call",
        );
    }
    if provider.side_effects.iter().any(|side_effect| {
        matches!(
            side_effect,
            SideEffectKind::FileRead | SideEffectKind::FileWrite | SideEffectKind::ArtifactWrite
        )
    }) && charge.file_bytes == 0
    {
        return fail(
            "invalid_budget_charge",
            "a file side effect must reserve a positive file-byte charge",
        );
    }
    if provider.side_effects.contains(&SideEffectKind::Network) && charge.network_bytes == 0 {
        return fail(
            "invalid_budget_charge",
            "a network side effect must reserve a positive network-byte charge",
        );
    }
    let argument_bytes = match u64::try_from(canonical_json_v1(&call.arguments).len()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return fail(
                "budget_arithmetic_overflow",
                "canonical argument byte length cannot be represented",
            );
        }
    };
    if argument_bytes > session.authority.budgets.max_argument_bytes {
        return fail(
            "argument_budget_exceeded",
            "canonical argument bytes exceed the per-operation ceiling",
        );
    }
    if let ResourceClaim::CodeExecution { limits, .. } = claim
        && limits.wall_time_ms > session.authority.budgets.max_wall_time_ms
    {
        return fail(
            "wall_time_budget_exceeded",
            "requested wall time exceeds the per-operation ceiling",
        );
    }
    for (reserved, committed, requested, maximum, kind, label) in [
        (
            usage.calls_reserved,
            usage.calls_committed,
            charge.calls,
            session.authority.budgets.max_calls,
            "call_budget_exceeded",
            "call",
        ),
        (
            usage.file_bytes_reserved,
            usage.file_bytes_committed,
            charge.file_bytes,
            session.authority.budgets.max_file_bytes,
            "file_budget_exceeded",
            "file byte",
        ),
        (
            usage.network_bytes_reserved,
            usage.network_bytes_committed,
            charge.network_bytes,
            session.authority.budgets.max_network_bytes,
            "network_budget_exceeded",
            "network byte",
        ),
    ] {
        match cumulative_usage(reserved, committed, requested) {
            Some(total) if total <= maximum => {}
            Some(_) => {
                return fail(
                    kind,
                    match label {
                        "call" => "cumulative call usage exceeds the session budget",
                        "file byte" => "cumulative file byte usage exceeds the session budget",
                        _ => "cumulative network byte usage exceeds the session budget",
                    },
                );
            }
            None => {
                return fail(
                    "budget_arithmetic_overflow",
                    "cumulative committed, reserved, and proposed usage overflowed",
                );
            }
        }
    }
    pass("canonical arguments, wall time, and cumulative budgets are within bounds")
}

fn check_approval(provider: &KernelProvider) -> StageOutcome {
    if provider_requires_approval(provider) {
        StageOutcome::Review("canonical provider contract requires one-shot reviewer approval")
    } else {
        pass("canonical provider contract does not require reviewer approval")
    }
}

fn authority_digest(authority: &AuthoritySnapshot) -> Sha256Digest {
    let value = serde_json::to_value(authority).expect("authority snapshot serializes");
    Sha256Digest::from_bytes(&canonical_json_v1(&value))
}

fn relative_prefix_matches(prefix: &str, candidate: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if WorkspaceRelativePath::try_from(prefix.to_owned()).is_err() {
        return false;
    }
    candidate == prefix
        || candidate
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_canonical_http_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && method.is_ascii()
        && method.bytes().all(|byte| {
            byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_canonical_origin(origin: &str) -> bool {
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https")
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.origin().ascii_serialization() == origin
}

fn recipients_are_canonical(recipients: &[String]) -> bool {
    recipients.iter().all(|recipient| {
        let mut parts = recipient.split('@');
        let Some(local) = parts.next() else {
            return false;
        };
        let Some(domain) = parts.next() else {
            return false;
        };
        parts.next().is_none()
            && !local.is_empty()
            && !domain.is_empty()
            && recipient.is_ascii()
            && recipient
                .bytes()
                .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
            && domain.bytes().all(|byte| !byte.is_ascii_uppercase())
    }) && recipients.windows(2).all(|pair| pair[0] < pair[1])
}

fn network_is_within(requested: NetworkCapability, maximum: NetworkCapability) -> bool {
    matches!(
        (requested, maximum),
        (NetworkCapability::None, _) | (NetworkCapability::Brokered, NetworkCapability::Brokered)
    )
}

fn execution_limits_are_within(requested: &ExecutionLimits, maximum: &ExecutionLimits) -> bool {
    requested.wall_time_ms <= maximum.wall_time_ms
        && requested.cpu_time_ms <= maximum.cpu_time_ms
        && requested.memory_bytes <= maximum.memory_bytes
        && requested.output_bytes <= maximum.output_bytes
        && requested.process_count <= maximum.process_count
}

fn cumulative_usage(reserved: u64, committed: u64, requested: u64) -> Option<u64> {
    reserved
        .checked_add(committed)
        .and_then(|current| current.checked_add(requested))
}
