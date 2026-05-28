use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::evidence::hex_sha256;
use crate::kernel::{AuthzState, KernelPolicy, ScopedRoot};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssessmentManifest {
    pub version: String,
    pub name: String,
    pub mode: String,
    #[serde(default)]
    pub provider_allowlist: Vec<String>,
    #[serde(default)]
    pub roots: Vec<RootManifest>,
    #[serde(default)]
    pub targets: Vec<TargetManifest>,
    #[serde(default)]
    pub budgets: BudgetManifest,
    pub authorization: Option<AuthorizationManifest>,
    pub actor: Option<ActorManifest>,
    #[serde(default)]
    pub active_assessment: ActiveAssessmentManifest,
}

impl AssessmentManifest {
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn manifest_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("assessment manifest serializes");
        hex_sha256(&canonical)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootManifest {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetManifest {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct BudgetManifest {
    pub max_argument_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorizationManifest {
    pub id: String,
    #[serde(default)]
    pub state: AuthzManifestState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthzManifestState {
    #[default]
    Active,
    Expired,
    Revoked,
    Denied,
}

impl From<AuthzManifestState> for AuthzState {
    fn from(value: AuthzManifestState) -> Self {
        match value {
            AuthzManifestState::Active => AuthzState::Active,
            AuthzManifestState::Expired => AuthzState::Expired,
            AuthzManifestState::Revoked => AuthzState::Revoked,
            AuthzManifestState::Denied => AuthzState::Denied,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActorManifest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActiveAssessmentManifest {
    pub enabled: bool,
}

impl Default for ActiveAssessmentManifest {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionManifest {
    pub session_id: String,
    pub schema_version: String,
    pub manifest_hash: String,
    pub authz_id: Option<String>,
    pub actor_id: Option<String>,
    pub mode: String,
    pub roots: Vec<RootManifest>,
    pub targets: Vec<TargetManifest>,
    pub allowed_providers: Vec<String>,
    pub budgets: BudgetManifest,
    pub active_assessment: bool,
    pub governance_state: AuthzManifestState,
    pub trace_path: Option<PathBuf>,
    #[schemars(with = "String")]
    pub created_at: OffsetDateTime,
}

impl SessionManifest {
    pub fn from_assessment(session_id: impl Into<String>, assessment: &AssessmentManifest) -> Self {
        Self {
            session_id: session_id.into(),
            schema_version: assessment.version.clone(),
            manifest_hash: assessment.manifest_hash(),
            authz_id: assessment
                .authorization
                .as_ref()
                .map(|authorization| authorization.id.clone()),
            actor_id: assessment.actor.as_ref().map(|actor| actor.id.clone()),
            mode: assessment.mode.clone(),
            roots: assessment.roots.clone(),
            targets: assessment.targets.clone(),
            allowed_providers: assessment.provider_allowlist.clone(),
            budgets: assessment.budgets.clone(),
            active_assessment: assessment.active_assessment.enabled,
            governance_state: assessment
                .authorization
                .as_ref()
                .map(|authorization| authorization.state)
                .unwrap_or_default(),
            trace_path: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    pub fn to_kernel_policy(&self) -> KernelPolicy {
        let mut policy = KernelPolicy::default();
        for provider in &self.allowed_providers {
            policy.allow_provider(provider);
        }
        for root in &self.roots {
            policy.add_scoped_root(ScopedRoot::new(root.name.clone(), root.path.clone()));
        }
        policy.max_argument_bytes = self.budgets.max_argument_bytes;
        policy.require_authz = self.authz_id.is_some();
        policy.active_assessment = self.active_assessment;
        if let Some(authz_id) = &self.authz_id {
            policy.add_authz(authz_id.clone(), self.governance_state.into());
        }
        policy
    }
}
