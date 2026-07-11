use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::WorkspaceRelativePath;
use crate::contracts::KernelProvider;
use crate::story::{OperationId, StoryId};
use crate::trace::{Sha256Digest, canonical_json_v1};

const PROVIDER_CONTRACT_DOMAIN_V1: &str = "runwarden.kernel-provider-contract.v1";

/// Commits to the complete kernel-owned provider contract, not only its id.
///
/// Policy contexts use this digest to prove that the provider evaluated for a
/// call is the exact provider registered by the server. In particular, a
/// caller cannot substitute a same-id provider with downgraded risk or side
/// effects to bypass review.
pub fn canonical_provider_contract_hash(provider: &KernelProvider) -> Sha256Digest {
    #[derive(Serialize)]
    struct ContractMaterial<'a> {
        domain: &'static str,
        provider: &'a KernelProvider,
    }

    let material = serde_json::to_value(ContractMaterial {
        domain: PROVIDER_CONTRACT_DOMAIN_V1,
        provider,
    })
    .expect("kernel provider contract serializes");
    Sha256Digest::from_bytes(&canonical_json_v1(&material))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DataClass {
    pub fn is_within(&self, maximum: &Self) -> bool {
        fn rank(value: &DataClass) -> u8 {
            match value {
                DataClass::Public => 0,
                DataClass::Internal => 1,
                DataClass::Confidential => 2,
                DataClass::Restricted => 3,
            }
        }

        rank(self) <= rank(maximum)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCapability {
    None,
    Brokered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub wall_time_ms: u64,
    pub cpu_time_ms: u64,
    pub memory_bytes: u64,
    pub output_bytes: u64,
    pub process_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceClaim {
    File {
        root: String,
        path: WorkspaceRelativePath,
        access: FileAccess,
        classification: DataClass,
    },
    Network {
        method: String,
        origin: String,
        classification: DataClass,
    },
    Email {
        recipients: Vec<String>,
        classification: DataClass,
    },
    Memory {
        namespace: String,
        key: String,
        access: MemoryAccess,
    },
    CodeExecution {
        runtime: String,
        workspace: String,
        network: NetworkCapability,
        limits: ExecutionLimits,
    },
    InputInspection {
        source: String,
        content_hash: Sha256Digest,
        classification: DataClass,
    },
    Evidence {
        story_id: StoryId,
        operation_id: OperationId,
    },
    Artifact {
        relative_path: WorkspaceRelativePath,
        format: String,
    },
    OpaqueLegacy {
        provider: String,
        redacted_summary: String,
    },
}

impl ResourceClaim {
    pub fn digest(&self) -> Sha256Digest {
        let value = serde_json::to_value(self).expect("resource claim serializes");
        let bytes = crate::trace::canonical_json_v1(&value);
        Sha256Digest::from_bytes(&bytes)
    }
}
