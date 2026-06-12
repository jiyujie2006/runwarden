use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use runwarden_kernel::authority::{ApprovalRecord, ApprovalState};
use runwarden_kernel::manifest::SessionManifest;

use crate::{PlatformError, PlatformEvent};

const STATE_DIR: &str = ".runwarden";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalListFilter {
    All,
    Pending,
}

#[derive(Debug, Clone)]
pub struct PlatformState {
    workspace_root: PathBuf,
}

impl PlatformState {
    pub(crate) fn open(workspace_root: PathBuf) -> Result<Self, PlatformError> {
        Ok(Self {
            workspace_root: workspace_root.canonicalize()?,
        })
    }

    pub(crate) fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn ensure_layout(&self) -> Result<(), PlatformError> {
        for (relative_path, dir) in [
            (PathBuf::from(STATE_DIR), self.state_dir()),
            (state_relative_path("sessions"), self.sessions_dir()),
            (state_relative_path("approvals"), self.approvals_dir()),
            (
                state_relative_path("provider-calls"),
                self.provider_calls_dir(),
            ),
            (
                state_relative_path("provider-catalog"),
                self.provider_catalog_dir(),
            ),
            (state_relative_path("traces"), self.traces_dir()),
            (state_relative_path("artifacts"), self.artifacts_dir()),
        ] {
            self.reject_state_path_symlink_components(&relative_path)?;
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn append_event(&self, event: &PlatformEvent) -> Result<(), PlatformError> {
        self.reject_state_path_symlink_components(Path::new(STATE_DIR))?;
        fs::create_dir_all(self.state_dir())?;
        self.reject_state_path_symlink_components(Path::new(STATE_DIR).join("events.jsonl"))?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.events_path())?;
        file.write_all(&line)?;
        Ok(())
    }

    pub(crate) fn write_session(&self, session: &SessionManifest) -> Result<(), PlatformError> {
        validate_session_id(&session.session_id)?;
        self.reject_state_path_symlink_components(state_relative_path("sessions"))?;
        fs::create_dir_all(self.sessions_dir())?;
        let path = self.session_path(&session.session_id)?;
        fs::write(path, serde_json::to_string_pretty(session)?)?;
        Ok(())
    }

    pub(crate) fn read_session(&self, session_id: &str) -> Result<SessionManifest, PlatformError> {
        let body = fs::read_to_string(self.session_path(session_id)?)?;
        Ok(serde_json::from_str(&body)?)
    }

    pub(crate) fn list_sessions(&self) -> Result<Vec<SessionManifest>, PlatformError> {
        self.reject_state_path_symlink_components(Path::new(STATE_DIR))?;
        let dir = self.sessions_dir();
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(PlatformError::Io(err)),
        }
        self.reject_state_path_symlink_components(state_relative_path("sessions"))?;

        let mut sessions = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            self.reject_state_path_symlink_components(
                state_relative_path("sessions").join(entry.file_name()),
            )?;
            let body = fs::read_to_string(entry.path())?;
            sessions.push(serde_json::from_str(&body)?);
        }
        sessions.sort_by(|left: &SessionManifest, right: &SessionManifest| {
            left.session_id.cmp(&right.session_id)
        });
        Ok(sessions)
    }

    pub(crate) fn write_approval(&self, approval: &ApprovalRecord) -> Result<(), PlatformError> {
        validate_record_id(&approval.approval_id)?;
        self.reject_state_path_symlink_components(state_relative_path("approvals"))?;
        fs::create_dir_all(self.approvals_dir())?;
        let path = self.approval_path(&approval.approval_id)?;
        fs::write(path, serde_json::to_string_pretty(approval)?)?;
        Ok(())
    }

    pub(crate) fn read_approval(&self, approval_id: &str) -> Result<ApprovalRecord, PlatformError> {
        let body = fs::read_to_string(self.approval_path(approval_id)?)?;
        Ok(serde_json::from_str(&body)?)
    }

    pub(crate) fn list_approvals(
        &self,
        filter: ApprovalListFilter,
    ) -> Result<Vec<ApprovalRecord>, PlatformError> {
        self.reject_state_path_symlink_components(Path::new(STATE_DIR))?;
        let dir = self.approvals_dir();
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(PlatformError::Io(err)),
        }
        self.reject_state_path_symlink_components(state_relative_path("approvals"))?;

        let mut approvals = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            self.reject_state_path_symlink_components(
                state_relative_path("approvals").join(entry.file_name()),
            )?;
            let body = fs::read_to_string(entry.path())?;
            let approval: ApprovalRecord = serde_json::from_str(&body)?;
            if filter == ApprovalListFilter::All || approval.state == ApprovalState::Pending {
                approvals.push(approval);
            }
        }
        approvals.sort_by(|left: &ApprovalRecord, right: &ApprovalRecord| {
            left.approval_id.cmp(&right.approval_id)
        });
        Ok(approvals)
    }

    pub(crate) fn write_provider_call_record(
        &self,
        record_id: &str,
        record: &serde_json::Value,
    ) -> Result<PathBuf, PlatformError> {
        let file_name = format!("{}.json", validate_record_id(record_id)?);
        self.reject_state_path_symlink_components(state_relative_path("provider-calls"))?;
        fs::create_dir_all(self.provider_calls_dir())?;
        self.reject_state_path_symlink_components(
            state_relative_path("provider-calls").join(&file_name),
        )?;
        let path = self.provider_calls_dir().join(file_name);
        fs::write(&path, serde_json::to_string_pretty(record)?)?;
        Ok(path)
    }

    pub fn sessions_dir(&self) -> PathBuf {
        self.state_dir().join("sessions")
    }

    pub fn approvals_dir(&self) -> PathBuf {
        self.state_dir().join("approvals")
    }

    pub fn provider_calls_dir(&self) -> PathBuf {
        self.state_dir().join("provider-calls")
    }

    pub fn provider_catalog_dir(&self) -> PathBuf {
        self.state_dir().join("provider-catalog")
    }

    pub fn traces_dir(&self) -> PathBuf {
        self.state_dir().join("traces")
    }

    pub fn artifacts_dir(&self) -> PathBuf {
        self.state_dir().join("artifacts")
    }

    pub fn validate_artifact_output_path(
        &self,
        requested: impl AsRef<Path>,
    ) -> Result<PathBuf, PlatformError> {
        let requested = requested.as_ref();
        if requested.as_os_str().is_empty()
            || requested.is_absolute()
            || requested.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::Prefix(_) | Component::RootDir
                )
            })
        {
            return Err(PlatformError::InvalidArtifactOutputPath);
        }

        self.reject_symlink_components(requested)?;
        let output_path = self.workspace_root.join(requested);
        if !path_is_within_root(&output_path, &self.workspace_root) {
            return Err(PlatformError::InvalidArtifactOutputPath);
        }
        Ok(output_path)
    }

    fn state_dir(&self) -> PathBuf {
        self.workspace_root.join(STATE_DIR)
    }

    fn events_path(&self) -> PathBuf {
        self.state_dir().join("events.jsonl")
    }

    fn session_path(&self, session_id: &str) -> Result<PathBuf, PlatformError> {
        let file_name = format!("{}.json", validate_session_id(session_id)?);
        self.reject_state_path_symlink_components(
            state_relative_path("sessions").join(&file_name),
        )?;
        Ok(self.state_dir().join("sessions").join(file_name))
    }

    fn approval_path(&self, approval_id: &str) -> Result<PathBuf, PlatformError> {
        let file_name = format!("{}.json", validate_record_id(approval_id)?);
        self.reject_state_path_symlink_components(
            state_relative_path("approvals").join(&file_name),
        )?;
        Ok(self.state_dir().join("approvals").join(file_name))
    }

    fn reject_symlink_components(&self, requested: &Path) -> Result<(), PlatformError> {
        let mut current = self.workspace_root.clone();
        for component in requested.components() {
            let Component::Normal(part) = component else {
                return Err(PlatformError::InvalidArtifactOutputPath);
            };
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(PlatformError::ArtifactOutputSymlink);
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(PlatformError::Io(err)),
            }
        }
        Ok(())
    }

    fn reject_state_path_symlink_components(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<(), PlatformError> {
        let relative_path = relative_path.as_ref();
        if relative_path.is_absolute() {
            return Err(PlatformError::InvalidStatePath);
        }

        let mut components = relative_path.components();
        if components.next() != Some(Component::Normal(STATE_DIR.as_ref())) {
            return Err(PlatformError::InvalidStatePath);
        }

        let mut current = self.workspace_root.clone();
        for component in relative_path.components() {
            let Component::Normal(part) = component else {
                return Err(PlatformError::InvalidStatePath);
            };
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(PlatformError::StatePathSymlink);
                }
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(PlatformError::Io(err)),
            }
        }
        Ok(())
    }
}

fn state_relative_path(child: &str) -> PathBuf {
    Path::new(STATE_DIR).join(child)
}

pub fn validate_session_id(session_id: &str) -> Result<&str, PlatformError> {
    if is_safe_record_id(session_id) {
        Ok(session_id)
    } else {
        Err(PlatformError::InvalidSessionId(session_id.to_string()))
    }
}

pub fn validate_record_id(record_id: &str) -> Result<&str, PlatformError> {
    if is_safe_record_id(record_id) {
        Ok(record_id)
    } else {
        Err(PlatformError::InvalidRecordId(record_id.to_string()))
    }
}

fn is_safe_record_id(record_id: &str) -> bool {
    !record_id.is_empty()
        && record_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn path_is_within_root(candidate: &Path, root: &Path) -> bool {
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    match candidate.canonicalize() {
        Ok(canonical_candidate) => canonical_candidate.starts_with(&canonical_root),
        Err(_) => canonical_existing_parent(candidate)
            .map(|parent| parent.starts_with(&canonical_root))
            .unwrap_or(false),
    }
}

fn canonical_existing_parent(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent()?;
    loop {
        if let Ok(canonical) = current.canonicalize() {
            return Some(canonical);
        }
        current = current.parent()?;
    }
}
