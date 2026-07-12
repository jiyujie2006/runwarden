//! Private, bounded contest business-tool implementations.

mod email;
mod file;
mod inspection;
mod simulated_network;
mod store;

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::SafeProviderOutput;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::OperationId;
use runwarden_kernel::trace::Sha256Digest;

use crate::executor::CleanupFileIdentity;

pub use email::mailbox_view_for_test;
pub(crate) use email::{
    EmailOperationBinding, EmailReconciliation, finalize_email_cleanup, send_email, verify_email,
};
pub(crate) use file::{read_file, write_file};
pub(crate) use inspection::inspect_bounded_input;
pub(crate) use simulated_network::{simulate_api_request, simulate_browser_open};
pub(crate) use store::{StoreClass, read_store, write_store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolExecutionState {
    Completed,
    Simulated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolReceipt {
    pub(crate) operation_id: OperationId,
    pub(crate) kind: String,
    pub(crate) relative_path: WorkspaceRelativePath,
    pub(crate) sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolCleanup {
    pub(crate) relative_path: WorkspaceRelativePath,
    pub(crate) sha256: Sha256Digest,
    pub(crate) file_identity: CleanupFileIdentity,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolExecution {
    pub(crate) state: ToolExecutionState,
    pub(crate) output: SafeProviderOutput,
    pub(crate) actual_budget_charge: BudgetCharge,
    pub(crate) receipt: Option<ToolReceipt>,
    pub(crate) cleanup: Option<ToolCleanup>,
}

impl ToolExecution {
    pub(crate) fn completed(
        output: SafeProviderOutput,
        actual_budget_charge: BudgetCharge,
    ) -> Self {
        Self {
            state: ToolExecutionState::Completed,
            output,
            actual_budget_charge,
            receipt: None,
            cleanup: None,
        }
    }

    pub(crate) fn simulated(output: SafeProviderOutput) -> Self {
        Self {
            state: ToolExecutionState::Simulated,
            output,
            actual_budget_charge: zero_charge(),
            receipt: None,
            cleanup: None,
        }
    }

    pub(crate) fn with_receipt(mut self, receipt: ToolReceipt) -> Self {
        self.receipt = Some(receipt);
        self
    }

    pub(crate) fn with_cleanup(mut self, cleanup: ToolCleanup) -> Self {
        self.cleanup = Some(cleanup);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolFailureStage {
    BeforeSideEffect,
    ExecutedWithError,
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ToolError {
    #[error("tool request is malformed")]
    InvalidRequest,
    #[error("tool request does not match its frozen claim")]
    ClaimMismatch,
    #[error("tool path is outside the trusted sandbox")]
    PathDenied,
    #[error("tool path contains a symbolic link")]
    SymlinkDenied,
    #[error("tool resource limit was exceeded")]
    LimitExceeded,
    #[error("tool reconciliation material failed integrity checks")]
    Integrity,
    #[error("operation is already bound to different immutable receipt values")]
    BindingConflict,
    #[error("email receipt is malformed or cannot be verified")]
    ReceiptIntegrity,
    #[error("trusted random source is unavailable")]
    EntropyUnavailable,
    #[error("tool state lock is unavailable")]
    LockUnavailable,
    #[error("tool failed before a side effect")]
    IoBeforeSideEffect,
    #[error("tool failed after a side effect")]
    ExecutedWithError,
    #[error("tool durability outcome is unknown")]
    OutcomeUnknown,
}

impl ToolError {
    pub(crate) fn error_kind(self) -> &'static str {
        match self {
            Self::InvalidRequest | Self::ClaimMismatch => "tool_request_invalid",
            Self::PathDenied | Self::SymlinkDenied => "sandbox_path_denied",
            Self::LimitExceeded => "resource_limit_exceeded",
            Self::Integrity => "reconciliation_integrity_error",
            Self::BindingConflict => "integrity_error",
            Self::ReceiptIntegrity => "receipt_integrity_error",
            Self::EntropyUnavailable => "trusted_entropy_unavailable",
            Self::LockUnavailable => "tool_state_unavailable",
            Self::IoBeforeSideEffect => "tool_io_error",
            Self::ExecutedWithError => "tool_execution_error",
            Self::OutcomeUnknown => "tool_outcome_unknown",
        }
    }

    pub(crate) fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "request_shape_invalid",
            Self::ClaimMismatch => "claim_argument_mismatch",
            Self::PathDenied => "path_outside_sandbox",
            Self::SymlinkDenied => "symlink_path_denied",
            Self::LimitExceeded => "bounded_output_exceeded",
            Self::Integrity => "immutable_binding_mismatch",
            Self::BindingConflict => "operation_binding_mismatch",
            Self::ReceiptIntegrity => "receipt_integrity_mismatch",
            Self::EntropyUnavailable => "entropy_unavailable",
            Self::LockUnavailable => "state_lock_unavailable",
            Self::IoBeforeSideEffect => "io_failed_before_side_effect",
            Self::ExecutedWithError => "io_failed_after_side_effect",
            Self::OutcomeUnknown => "durability_outcome_unknown",
        }
    }

    pub(crate) fn failure_stage(self) -> ToolFailureStage {
        match self {
            Self::ExecutedWithError => ToolFailureStage::ExecutedWithError,
            Self::OutcomeUnknown | Self::ReceiptIntegrity => ToolFailureStage::OutcomeUnknown,
            _ => ToolFailureStage::BeforeSideEffect,
        }
    }
}

pub(super) fn zero_charge() -> BudgetCharge {
    BudgetCharge {
        calls: 0,
        file_bytes: 0,
        network_bytes: 0,
    }
}

pub(super) fn one_call_charge(file_bytes: u64, network_bytes: u64) -> BudgetCharge {
    BudgetCharge {
        calls: 1,
        file_bytes,
        network_bytes,
    }
}

pub(super) fn canonical_sandbox_root(root: &Path) -> Result<PathBuf, ToolError> {
    if !root.is_absolute() {
        return Err(ToolError::PathDenied);
    }
    let canonical = root
        .canonicalize()
        .map_err(|_| ToolError::IoBeforeSideEffect)?;
    if canonical != root || !canonical.is_dir() {
        return Err(ToolError::PathDenied);
    }
    Ok(canonical)
}

pub(super) fn ensure_private_directory(
    root: &Path,
    relative: &WorkspaceRelativePath,
) -> Result<PathBuf, ToolError> {
    let canonical_root = canonical_sandbox_root(root)?;
    let mut current = canonical_root.clone();
    for component in relative.as_str().split('/') {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ToolError::SymlinkDenied);
                }
                if !metadata.is_dir() {
                    return Err(ToolError::PathDenied);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(ToolError::IoBeforeSideEffect),
                }
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| ToolError::IoBeforeSideEffect)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ToolError::SymlinkDenied);
                }
            }
            Err(_) => return Err(ToolError::IoBeforeSideEffect),
        }
        let canonical = current
            .canonicalize()
            .map_err(|_| ToolError::IoBeforeSideEffect)?;
        if !canonical.starts_with(&canonical_root) {
            return Err(ToolError::PathDenied);
        }
        current = canonical;
    }
    Ok(current)
}

pub(super) fn validate_regular_file(
    root: &Path,
    path: &Path,
    missing_is_error: bool,
) -> Result<Option<PathBuf>, ToolError> {
    let canonical_root = canonical_sandbox_root(root)?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !missing_is_error => {
            return Ok(None);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ToolError::IoBeforeSideEffect);
        }
        Err(_) => return Err(ToolError::IoBeforeSideEffect),
    };
    if metadata.file_type().is_symlink() {
        return Err(ToolError::SymlinkDenied);
    }
    if !metadata.is_file() {
        return Err(ToolError::PathDenied);
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| ToolError::IoBeforeSideEffect)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(ToolError::PathDenied);
    }
    Ok(Some(canonical))
}

pub(super) fn random_suffix() -> Result<String, ToolError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ToolError::EntropyUnavailable)?;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(encoded)
}

pub(super) fn sync_directory(directory: &Path) -> Result<(), ToolError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| ToolError::OutcomeUnknown)
}
