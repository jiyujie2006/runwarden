use std::fs;
use std::path::{Component, Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(with = "String")]
pub struct WorkspaceRelativePath(String);

impl WorkspaceRelativePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for WorkspaceRelativePath {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("workspace-relative path must not be empty".to_string());
        }
        if value.starts_with('/') {
            return Err("workspace-relative path must be relative".to_string());
        }
        if value.contains('\\') || value.contains(':') || value.contains('\0') {
            return Err(
                "workspace-relative path must not contain a platform prefix, backslash, colon, or NUL"
                    .to_string(),
            );
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(
                "workspace-relative path must contain only non-empty relative components"
                    .to_string(),
            );
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for WorkspaceRelativePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactPathError {
    #[error("artifact path must not be empty")]
    Empty,
    #[error("artifact path must be relative")]
    NotRelative,
    #[error("artifact path must not contain parent traversal")]
    ParentTraversal,
    #[error("artifact path escapes workspace root")]
    RootEscape,
    #[error("workspace root is unavailable: {0}")]
    RootUnavailable(String),
    #[error("artifact path canonicalization failed: {0}")]
    CanonicalizationFailed(String),
}

pub fn resolve_workspace_relative_path(
    root: &Path,
    requested: &Path,
) -> Result<PathBuf, ArtifactPathError> {
    if requested.as_os_str().is_empty() {
        return Err(ArtifactPathError::Empty);
    }

    let mut relative = PathBuf::new();
    for component in requested.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => relative.push(segment),
            Component::ParentDir => return Err(ArtifactPathError::ParentTraversal),
            Component::RootDir | Component::Prefix(_) => {
                return Err(ArtifactPathError::NotRelative);
            }
        }
    }

    let resolved = if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    ensure_workspace_containment(root, &resolved)?;
    Ok(resolved)
}

fn ensure_workspace_containment(root: &Path, resolved: &Path) -> Result<(), ArtifactPathError> {
    if !resolved.starts_with(root) {
        return Err(ArtifactPathError::RootEscape);
    }

    let canonical_root = root
        .canonicalize()
        .map_err(|error| ArtifactPathError::RootUnavailable(error.to_string()))?;
    let mut probe = resolved.to_path_buf();

    loop {
        match fs::symlink_metadata(&probe) {
            Ok(_) => {
                let canonical_probe = probe.canonicalize().map_err(|error| {
                    ArtifactPathError::CanonicalizationFailed(error.to_string())
                })?;
                if canonical_probe.starts_with(&canonical_root) {
                    return Ok(());
                }
                return Err(ArtifactPathError::RootEscape);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !probe.pop() || !probe.starts_with(root) {
                    return Err(ArtifactPathError::RootEscape);
                }
            }
            Err(error) => {
                return Err(ArtifactPathError::CanonicalizationFailed(error.to_string()));
            }
        }
    }
}

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
