use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::SafeProviderOutput;
use runwarden_kernel::resource::{FileAccess, ResourceClaim};
use runwarden_kernel::trace::Sha256Digest;
use serde_json::Value;

use super::{
    ToolError, ToolExecution, canonical_sandbox_root, ensure_private_directory, one_call_charge,
    random_suffix, sync_directory, validate_regular_file,
};
use crate::resource_claims::canonicalize_file_path;

pub(crate) fn read_file(
    sandbox_root: &Path,
    arguments: &Value,
    claim: &ResourceClaim,
    max_file_bytes: u64,
) -> Result<ToolExecution, ToolError> {
    let path = file_claim_path(claim, FileAccess::Read)?;
    require_argument_path(arguments, path)?;
    reject_private_tool_state(path)?;
    if max_file_bytes == 0 {
        return Err(ToolError::LimitExceeded);
    }

    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let requested = canonical_root.join(path.as_str());
    reject_symlink_components(&canonical_root, path)?;
    validate_regular_file(&canonical_root, &requested, true)?;

    let mut file = open_read_no_follow(&requested)?;
    verify_open_descriptor(&file, &canonical_root)?;
    let metadata = file.metadata().map_err(|_| ToolError::IoBeforeSideEffect)?;
    if !metadata.is_file() || metadata.len() > max_file_bytes {
        return Err(ToolError::LimitExceeded);
    }
    let read_limit = max_file_bytes
        .checked_add(1)
        .ok_or(ToolError::LimitExceeded)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ToolError::ExecutedWithError)?;
    let length = u64::try_from(bytes.len()).map_err(|_| ToolError::LimitExceeded)?;
    if length > max_file_bytes {
        return Err(ToolError::LimitExceeded);
    }

    Ok(ToolExecution::completed(
        SafeProviderOutput::File {
            bytes: length,
            content_hash: Sha256Digest::from_bytes(&bytes),
        },
        one_call_charge(length, 0),
    ))
}

pub(crate) fn write_file(
    sandbox_root: &Path,
    arguments: &Value,
    claim: &ResourceClaim,
    max_file_bytes: u64,
) -> Result<ToolExecution, ToolError> {
    let path = file_claim_path(claim, FileAccess::Write)?;
    require_argument_path(arguments, path)?;
    reject_private_tool_state(path)?;
    let content = arguments
        .get("content")
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    let content_length = u64::try_from(content.len()).map_err(|_| ToolError::LimitExceeded)?;
    if max_file_bytes == 0 || content_length > max_file_bytes {
        return Err(ToolError::LimitExceeded);
    }

    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let parent = ensure_parent_directory(&canonical_root, path)?;
    let file_name = path
        .as_str()
        .rsplit('/')
        .next()
        .ok_or(ToolError::InvalidRequest)?;
    let target = parent.join(file_name);
    if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(ToolError::SymlinkDenied);
    }
    validate_regular_file(&canonical_root, &target, false)?;

    let temp = parent.join(format!(".runwarden-write-{}.tmp", random_suffix()?));
    let mut file = open_unique_write_no_follow(&temp)?;
    verify_open_descriptor(&file, &canonical_root)?;
    if let Err(error) = file
        .write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = fs::remove_file(&temp);
        let _ = error;
        return Err(ToolError::IoBeforeSideEffect);
    }
    drop(file);

    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| ToolError::IoBeforeSideEffect)?;
    if !canonical_parent.starts_with(&canonical_root) {
        let _ = fs::remove_file(&temp);
        return Err(ToolError::PathDenied);
    }
    if fs::rename(&temp, &target).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(ToolError::IoBeforeSideEffect);
    }
    if validate_regular_file(&canonical_root, &target, true).is_err() {
        return Err(ToolError::OutcomeUnknown);
    }
    sync_directory(&parent)?;

    Ok(ToolExecution::completed(
        SafeProviderOutput::File {
            bytes: content_length,
            content_hash: Sha256Digest::from_bytes(content.as_bytes()),
        },
        one_call_charge(content_length, 0),
    ))
}

fn file_claim_path(
    claim: &ResourceClaim,
    expected_access: FileAccess,
) -> Result<&WorkspaceRelativePath, ToolError> {
    let ResourceClaim::File {
        root, path, access, ..
    } = claim
    else {
        return Err(ToolError::ClaimMismatch);
    };
    if root.is_empty() || *access != expected_access {
        return Err(ToolError::ClaimMismatch);
    }
    Ok(path)
}

fn require_argument_path(
    arguments: &Value,
    claim_path: &WorkspaceRelativePath,
) -> Result<(), ToolError> {
    let raw = arguments
        .get("path")
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    let canonical = canonicalize_file_path(raw).map_err(|_| ToolError::InvalidRequest)?;
    if &canonical != claim_path {
        return Err(ToolError::ClaimMismatch);
    }
    Ok(())
}

fn reject_private_tool_state(path: &WorkspaceRelativePath) -> Result<(), ToolError> {
    let first = path.as_str().split('/').next().unwrap_or_default();
    if matches!(first, "mail" | "stores" | ".runwarden") {
        return Err(ToolError::PathDenied);
    }
    Ok(())
}

fn ensure_parent_directory(
    root: &Path,
    path: &WorkspaceRelativePath,
) -> Result<PathBuf, ToolError> {
    let Some((parent, _)) = path.as_str().rsplit_once('/') else {
        return canonical_sandbox_root(root);
    };
    let parent = WorkspaceRelativePath::try_from(parent.to_owned())
        .map_err(|_| ToolError::InvalidRequest)?;
    ensure_private_directory(root, &parent)
}

fn reject_symlink_components(root: &Path, path: &WorkspaceRelativePath) -> Result<(), ToolError> {
    let mut current = root.to_path_buf();
    for component in path.as_str().split('/') {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|_| ToolError::IoBeforeSideEffect)?;
        if metadata.file_type().is_symlink() {
            return Err(ToolError::SymlinkDenied);
        }
    }
    Ok(())
}

fn open_read_no_follow(path: &Path) -> Result<File, ToolError> {
    let mut options = OpenOptions::new();
    options.read(true);
    set_no_follow(&mut options);
    options
        .open(path)
        .map_err(|_| ToolError::IoBeforeSideEffect)
}

fn open_unique_write_no_follow(path: &Path) -> Result<File, ToolError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_no_follow(&mut options);
    options
        .open(path)
        .map_err(|_| ToolError::IoBeforeSideEffect)
}

#[cfg(target_os = "linux")]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    const O_NOFOLLOW: i32 = 0x20_000;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(not(target_os = "linux"))]
fn set_no_follow(_options: &mut OpenOptions) {}

#[cfg(target_os = "linux")]
fn verify_open_descriptor(file: &File, root: &Path) -> Result<(), ToolError> {
    use std::os::fd::AsRawFd;

    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let actual = descriptor_path
        .canonicalize()
        .map_err(|_| ToolError::IoBeforeSideEffect)?;
    if !actual.starts_with(root) {
        return Err(ToolError::PathDenied);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_open_descriptor(_file: &File, _root: &Path) -> Result<(), ToolError> {
    Ok(())
}
