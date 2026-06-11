mod events;
mod state;

use std::path::{Path, PathBuf};

pub use events::PlatformEvent;
pub use state::PlatformState;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("platform IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("platform JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact output path must be a relative path inside the workspace")]
    InvalidArtifactOutputPath,
    #[error("artifact output path must not contain symlink components")]
    ArtifactOutputSymlink,
    #[error("platform state path must stay under .runwarden")]
    InvalidStatePath,
    #[error("platform state path must not contain symlink components")]
    StatePathSymlink,
}

#[derive(Debug, Clone)]
pub struct RunwardenPlatform {
    state: PlatformState,
}

impl RunwardenPlatform {
    pub fn open(workspace_root: impl Into<PathBuf>) -> Result<Self, PlatformError> {
        Ok(Self {
            state: PlatformState::open(workspace_root.into())?,
        })
    }

    pub fn state(&self) -> &PlatformState {
        &self.state
    }

    pub fn validate_artifact_output_path(
        &self,
        requested: impl AsRef<Path>,
    ) -> Result<PathBuf, PlatformError> {
        self.state.validate_artifact_output_path(requested)
    }
}
