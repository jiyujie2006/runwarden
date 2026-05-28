use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::authority::{ApprovalBinding, ApprovalRecord, ApprovalState, ApprovalTransitionError};
use crate::contracts::{
    ErrorKind, KernelProvider, PolicyDecision, ProviderCall, ProviderOutcome, ProviderRisk,
    SideEffectKind,
};
use crate::evidence::hex_sha256;

#[derive(Debug, Default)]
pub struct ProviderRegistry {
    providers: BTreeMap<String, KernelProvider>,
}

impl ProviderRegistry {
    pub fn register(&mut self, provider: KernelProvider) {
        self.providers.insert(provider.id.clone(), provider);
    }

    pub fn get(&self, id: &str) -> Option<&KernelProvider> {
        self.providers.get(id)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.providers.contains_key(id)
    }
}

pub fn enforce_provider_exists(
    registry: &ProviderRegistry,
    call: &ProviderCall,
) -> Result<(), Box<ProviderOutcome>> {
    if registry.contains(&call.provider) {
        Ok(())
    } else {
        Err(Box::new(ProviderOutcome::before_side_effect(
            PolicyDecision::Denied,
            call,
            "provider_registry",
            "provider is not registered",
            Some(ErrorKind::ProviderUnknown),
        )))
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AuthzState {
    Active,
    Expired,
    Revoked,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedRoot {
    pub name: String,
    pub path: PathBuf,
}

impl ScopedRoot {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KernelPolicy {
    provider_allowlist: BTreeSet<String>,
    scoped_roots: BTreeMap<String, PathBuf>,
    allowed_egress_hosts: BTreeSet<String>,
    deny_private_egress: bool,
    pub max_argument_bytes: Option<usize>,
    pub require_active_assessment: bool,
    pub active_assessment: bool,
    pub require_authz: bool,
    authz: BTreeMap<String, AuthzState>,
}

impl Default for KernelPolicy {
    fn default() -> Self {
        Self {
            provider_allowlist: BTreeSet::new(),
            scoped_roots: BTreeMap::new(),
            allowed_egress_hosts: BTreeSet::new(),
            deny_private_egress: true,
            max_argument_bytes: None,
            require_active_assessment: true,
            active_assessment: false,
            require_authz: false,
            authz: BTreeMap::new(),
        }
    }
}

impl KernelPolicy {
    pub fn allow_provider(&mut self, provider_id: impl Into<String>) {
        self.provider_allowlist.insert(provider_id.into());
    }

    pub fn add_scoped_root(&mut self, root: ScopedRoot) {
        self.scoped_roots
            .insert(root.name, normalize_path(&root.path));
    }

    pub fn allow_egress_host(&mut self, host: impl Into<String>) {
        self.allowed_egress_hosts
            .insert(normalize_host(&host.into()));
    }

    pub fn add_authz(&mut self, authz_id: impl Into<String>, state: AuthzState) {
        self.authz.insert(authz_id.into(), state);
    }

    fn provider_allowed(&self, provider_id: &str) -> bool {
        self.provider_allowlist.contains(provider_id)
    }
}

#[derive(Debug)]
pub struct KernelEnforcer {
    registry: ProviderRegistry,
    policy: KernelPolicy,
    approvals: BTreeMap<String, ApprovalRecord>,
}

impl KernelEnforcer {
    pub fn new(registry: ProviderRegistry, policy: KernelPolicy) -> Self {
        Self {
            registry,
            policy,
            approvals: BTreeMap::new(),
        }
    }

    pub fn add_approval(&mut self, approval: ApprovalRecord) {
        self.approvals
            .insert(approval.approval_id.clone(), approval);
    }

    pub fn approval_state(&self, approval_id: &str) -> Option<ApprovalState> {
        self.approvals
            .get(approval_id)
            .map(|approval| approval.state.clone())
    }

    pub fn approval_binding_for_call(&self, call: &ProviderCall) -> ApprovalBinding {
        ApprovalBinding {
            session_id: call.session_id.clone(),
            provider: call.provider.clone(),
            action: call.action.clone(),
            argument_hash: argument_hash(&call.arguments),
            authz_id: call.authz_id.clone(),
            actor_id: call.actor_id.clone(),
        }
    }

    pub fn evaluate_call(&mut self, call: &ProviderCall) -> ProviderOutcome {
        let Some(provider) = self.registry.get(&call.provider) else {
            return deny(
                call,
                "provider_registry",
                ErrorKind::ProviderUnknown,
                "provider is not registered",
            );
        };

        if !self.policy.provider_allowed(&call.provider) {
            return deny(
                call,
                "provider_allowlist",
                ErrorKind::ProviderNotAllowed,
                "provider is not allowed for this session",
            );
        }

        if let Some(outcome) = self.validate_roots(call) {
            return outcome;
        }

        if let Some(outcome) = self.validate_egress(call) {
            return outcome;
        }

        if let Some(max_bytes) = self.policy.max_argument_bytes {
            let argument_bytes = serde_json::to_vec(&call.arguments)
                .expect("provider call arguments must serialize")
                .len();
            if argument_bytes > max_bytes {
                return deny(
                    call,
                    "budget",
                    ErrorKind::BudgetExceeded,
                    "provider call arguments exceed the session budget",
                );
            }
        }

        if self.policy.require_active_assessment && !self.policy.active_assessment {
            return deny(
                call,
                "active_assessment",
                ErrorKind::ActiveAssessmentRequired,
                "an active assessment is required before provider calls",
            );
        }

        if let Some(outcome) = self.validate_authz(call) {
            return outcome;
        }

        if provider_requires_approval(provider) {
            return self.validate_approval(call);
        }

        allow(
            call,
            "provider_policy",
            "provider call is allowed before side effect",
        )
    }

    fn validate_roots(&self, call: &ProviderCall) -> Option<ProviderOutcome> {
        let root_name = call.arguments.get("root").and_then(Value::as_str);

        let root_path = match root_name {
            Some(name) => match self.policy.scoped_roots.get(name) {
                Some(root) => Some(root),
                None => {
                    return Some(deny(
                        call,
                        "scope",
                        ErrorKind::ScopeViolation,
                        "requested root is outside the session scope",
                    ));
                }
            },
            None => None,
        };

        let mut paths = Vec::new();
        collect_argument_strings(&call.arguments, &mut |key, value| {
            if key.ends_with("path") || key == "path" {
                paths.push(value.to_string());
            }
        });

        for path in paths {
            let path = PathBuf::from(path);
            let allowed = if let Some(root) = root_path {
                path_is_within_root(&path, root)
            } else {
                self.policy
                    .scoped_roots
                    .values()
                    .any(|root| path_is_within_root(&path, root))
            };

            if !allowed {
                return Some(deny(
                    call,
                    "root",
                    ErrorKind::RootEscape,
                    "requested path escapes the configured root",
                ));
            }
        }

        None
    }

    fn validate_egress(&self, call: &ProviderCall) -> Option<ProviderOutcome> {
        let mut urls = Vec::new();
        collect_argument_strings(&call.arguments, &mut |key, value| {
            if key.contains("url") && value.contains("://") {
                urls.push(value.to_string());
            }
        });

        for url in urls {
            let Some(host) = extract_url_host(&url) else {
                return Some(deny(
                    call,
                    "egress",
                    ErrorKind::EgressDenied,
                    "egress URL does not include a valid host",
                ));
            };

            if self.policy.deny_private_egress && is_private_or_local_host(&host) {
                return Some(deny(
                    call,
                    "egress",
                    ErrorKind::EgressDenied,
                    "private or local network egress is denied",
                ));
            }

            if !self.policy.allowed_egress_hosts.is_empty()
                && !self.policy.allowed_egress_hosts.contains(&host)
            {
                return Some(deny(
                    call,
                    "egress",
                    ErrorKind::EgressDenied,
                    "egress host is not allowlisted",
                ));
            }
        }

        None
    }

    fn validate_authz(&self, call: &ProviderCall) -> Option<ProviderOutcome> {
        if !self.policy.require_authz {
            return None;
        }

        let Some(authz_id) = call.authz_id.as_deref() else {
            return Some(deny(
                call,
                "authz",
                ErrorKind::AuthzInvalid,
                "provider call requires an authz id",
            ));
        };

        match self.policy.authz.get(authz_id) {
            Some(AuthzState::Active) => None,
            Some(_) | None => Some(deny(
                call,
                "authz",
                ErrorKind::AuthzInvalid,
                "authz id is missing, expired, revoked, or denied",
            )),
        }
    }

    fn validate_approval(&mut self, call: &ProviderCall) -> ProviderOutcome {
        let Some(approval_id) = call.approval_id.as_deref() else {
            return requires_review(
                call,
                "approval",
                ErrorKind::ApprovalInvalid,
                "high-risk provider requires reviewer approval",
            );
        };

        let binding = self.approval_binding_for_call(call);
        let Some(approval) = self.approvals.get_mut(approval_id) else {
            return deny(
                call,
                "approval",
                ErrorKind::ApprovalInvalid,
                "approval id was not found",
            );
        };

        match approval.state {
            ApprovalState::Pending => requires_review(
                call,
                "approval",
                ErrorKind::ApprovalInvalid,
                "approval is still pending reviewer decision",
            ),
            ApprovalState::Approved => match approval.consume_once(&binding) {
                Ok(()) => allow(
                    call,
                    "approval",
                    "bound approval consumed before side effect",
                ),
                Err(ApprovalTransitionError::BindingMismatch) => deny(
                    call,
                    "approval",
                    ErrorKind::ApprovalInvalid,
                    "approval binding does not match this provider call",
                ),
                Err(ApprovalTransitionError::AlreadyConsumed) => deny(
                    call,
                    "approval",
                    ErrorKind::ApprovalConsumed,
                    "approval was already consumed",
                ),
                Err(ApprovalTransitionError::InvalidState) => deny(
                    call,
                    "approval",
                    ErrorKind::ApprovalInvalid,
                    "approval cannot be consumed from its current state",
                ),
            },
            ApprovalState::Consumed => deny(
                call,
                "approval",
                ErrorKind::ApprovalConsumed,
                "approval was already consumed",
            ),
            ApprovalState::Expired => deny(
                call,
                "approval",
                ErrorKind::ApprovalExpired,
                "approval is expired",
            ),
            ApprovalState::Denied | ApprovalState::Revoked => deny(
                call,
                "approval",
                ErrorKind::ApprovalInvalid,
                "approval is denied or revoked",
            ),
        }
    }
}

fn allow(call: &ProviderCall, gate_id: &str, reason: &str) -> ProviderOutcome {
    ProviderOutcome::before_side_effect(PolicyDecision::Allowed, call, gate_id, reason, None)
}

fn deny(call: &ProviderCall, gate_id: &str, kind: ErrorKind, reason: &str) -> ProviderOutcome {
    ProviderOutcome::before_side_effect(PolicyDecision::Denied, call, gate_id, reason, Some(kind))
}

fn requires_review(
    call: &ProviderCall,
    gate_id: &str,
    kind: ErrorKind,
    reason: &str,
) -> ProviderOutcome {
    ProviderOutcome::before_side_effect(
        PolicyDecision::RequiresReview,
        call,
        gate_id,
        reason,
        Some(kind),
    )
}

fn provider_requires_approval(provider: &KernelProvider) -> bool {
    matches!(
        provider.risk,
        ProviderRisk::High
            | ProviderRisk::NetworkActive
            | ProviderRisk::FileWrite
            | ProviderRisk::CredentialUse
            | ProviderRisk::Destructive
            | ProviderRisk::ReportClaim
    ) || provider.side_effects.iter().any(|side_effect| {
        matches!(
            side_effect,
            SideEffectKind::FileWrite
                | SideEffectKind::ProcessSpawn
                | SideEffectKind::CredentialUse
                | SideEffectKind::Destructive
                | SideEffectKind::ArtifactWrite
        )
    })
}

fn argument_hash(arguments: &Value) -> String {
    let bytes = serde_json::to_vec(arguments).expect("provider arguments must serialize");
    hex_sha256(&bytes)
}

fn collect_argument_strings(value: &Value, visitor: &mut impl FnMut(&str, &str)) {
    fn walk(value: &Value, current_key: Option<&str>, visitor: &mut impl FnMut(&str, &str)) {
        match value {
            Value::String(text) => {
                if let Some(key) = current_key {
                    visitor(key, text);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, current_key, visitor);
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    walk(value, Some(key.as_str()), visitor);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    walk(value, None, visitor);
}

fn path_is_within_root(path: &Path, root: &Path) -> bool {
    let candidate = if path.is_absolute() {
        normalize_path(path)
    } else {
        normalize_path(&root.join(path))
    };
    candidate.starts_with(normalize_path(root))
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn extract_url_host(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return None;
    }

    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };

    if host.is_empty() {
        None
    } else {
        Some(normalize_host(host))
    }
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_private_or_local_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }

    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };

    match ip {
        IpAddr::V4(addr) => {
            addr.is_private()
                || addr.is_loopback()
                || addr.is_link_local()
                || addr.is_unspecified()
                || is_carrier_grade_nat(addr)
        }
        IpAddr::V6(addr) => {
            addr.is_loopback()
                || addr.is_unspecified()
                || addr.is_unique_local()
                || addr.is_unicast_link_local()
        }
    }
}

fn is_carrier_grade_nat(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}
