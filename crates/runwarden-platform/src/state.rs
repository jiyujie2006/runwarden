use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::{PlatformError, PlatformEvent};

const STATE_DIR: &str = ".runwarden";

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
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.events_path())?;
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
        Ok(())
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
