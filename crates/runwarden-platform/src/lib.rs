mod events;
mod executor;
mod state;

use std::path::{Path, PathBuf};

use runwarden_kernel::authority::ApprovalRecord;
use runwarden_kernel::manifest::SessionManifest;

pub use events::PlatformEvent;
pub use executor::{ProviderExecutionRequest, ProviderExecutionResult};
pub use state::{ApprovalListFilter, PlatformState, validate_record_id, validate_session_id};

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
    #[error("invalid session id: {0}")]
    InvalidSessionId(String),
    #[error("invalid record id: {0}")]
    InvalidRecordId(String),
    #[error("provider execution failed: {0}")]
    ProviderExecution(String),
    #[error("approval transition failed: {0}")]
    ApprovalTransition(#[from] runwarden_kernel::authority::ApprovalTransitionError),
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

    pub fn write_session(&self, session: &SessionManifest) -> Result<(), PlatformError> {
        self.state.write_session(session)
    }

    pub fn read_session(&self, session_id: &str) -> Result<SessionManifest, PlatformError> {
        self.state.read_session(session_id)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionManifest>, PlatformError> {
        self.state.list_sessions()
    }

    pub fn write_approval(&self, approval: &ApprovalRecord) -> Result<(), PlatformError> {
        self.state.write_approval(approval)
    }

    pub fn read_approval(&self, approval_id: &str) -> Result<ApprovalRecord, PlatformError> {
        self.state.read_approval(approval_id)
    }

    pub fn list_approvals(
        &self,
        filter: ApprovalListFilter,
    ) -> Result<Vec<ApprovalRecord>, PlatformError> {
        self.state.list_approvals(filter)
    }
}
