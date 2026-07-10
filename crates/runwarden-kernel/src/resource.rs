use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::WorkspaceRelativePath;
use crate::story::{OperationId, StoryId};
use crate::trace::Sha256Digest;

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
