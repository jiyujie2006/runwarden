use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::artifact::WorkspaceRelativePath;
use crate::resource::{DataClass, ExecutionLimits, FileAccess, MemoryAccess, NetworkCapability};
use crate::story::{OperationId, SessionId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileAuthority {
    pub root: String,
    pub path_prefix: String,
    pub access: Vec<FileAccess>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkAuthority {
    pub provider: String,
    pub allowed_origins: Vec<String>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailAuthority {
    pub allowed_recipients: Vec<String>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoreAuthority {
    pub namespace: String,
    pub key_prefix: String,
    pub access: Vec<MemoryAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeAuthority {
    pub allowed_runtimes: Vec<String>,
    pub workspace: String,
    pub network: NetworkCapability,
    pub maximum_limits: ExecutionLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InputAuthority {
    pub allowed_sources: Vec<String>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAuthority {
    pub current_story_only: bool,
    pub allowed_operations: Vec<OperationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAuthority {
    pub path_prefix: WorkspaceRelativePath,
    pub allowed_formats: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub max_argument_bytes: u64,
    pub max_file_bytes: u64,
    pub max_network_bytes: u64,
    pub max_calls: u64,
    pub max_wall_time_ms: u64,
    pub max_model_calls: u64,
    pub max_model_input_bytes: u64,
    pub max_model_output_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetCharge {
    pub calls: u64,
    pub file_bytes: u64,
    pub network_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsageSnapshot {
    pub version: u64,
    pub calls_reserved: u64,
    pub calls_committed: u64,
    pub file_bytes_reserved: u64,
    pub file_bytes_committed: u64,
    pub network_bytes_reserved: u64,
    pub network_bytes_committed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    pub session_id: SessionId,
    pub actor_id: String,
    pub authz_id: String,
    pub authz_state: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    pub expires_at: OffsetDateTime,
    pub allowed_providers: Vec<String>,
    pub files: Vec<FileAuthority>,
    pub networks: Vec<NetworkAuthority>,
    pub email: Option<EmailAuthority>,
    pub stores: Vec<StoreAuthority>,
    pub code: Option<CodeAuthority>,
    pub inputs: Vec<InputAuthority>,
    pub evidence: EvidenceAuthority,
    pub artifacts: Vec<ArtifactAuthority>,
    pub budgets: BudgetSnapshot,
    pub policy_snapshot_hash: String,
}
