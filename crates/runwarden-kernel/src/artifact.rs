use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactManifest {
    pub schema_version: String,
    pub artifacts: Vec<ArtifactManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactManifestEntry {
    pub artifact_id: String,
    #[schemars(
        length(min = 1),
        regex(pattern = r"^(?!/)(?![A-Za-z]:[\\/])(?!.*(^|[\\/])\.\.([\\/]|$)).+$")
    )]
    pub relative_path: String,
    pub sha256: Option<String>,
    #[schemars(
        length(min = 1),
        regex(pattern = r"^(?!/)(?![A-Za-z]:[\\/])(?!.*(^|[\\/])\.\.([\\/]|$)).+$")
    )]
    pub redaction_sidecar_path: Option<String>,
    pub redaction_sidecar_sha256: Option<String>,
    pub obs_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RedactionSidecar {
    pub artifact_id: String,
    pub redaction_applied: bool,
    pub redacted_patterns: Vec<String>,
    pub original_sha256: String,
    pub redacted_sha256: String,
}
