use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use runwarden_kernel::kernel::ProviderRegistry;
use runwarden_kernel::resource::{FileAccess, MemoryAccess, ResourceClaim};
use runwarden_kernel::story::OperationId;
use time::OffsetDateTime;

use crate::catalog::full_provider_registry;

use super::{
    CleanupDisposition, CleanupError, CleanupToken, ExecutionPermit, PermitVerifier,
    ProviderExecutionOutcome, ProviderExecutionRequest, ProviderExecutionResult, ProviderExecutor,
    ReconciliationResult, canonical_provider_contract_hash,
};

const MAX_EXECUTOR_OUTPUT_BYTES: usize = 1_048_576;
const MAX_EXECUTOR_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct ExecutorConfig {
    sandbox_root: PathBuf,
    trusted_runtime_root: PathBuf,
    max_output_bytes: usize,
    timeout: Duration,
    permit_verifier: PermitVerifier,
}

impl ExecutorConfig {
    pub fn new(
        sandbox_root: PathBuf,
        trusted_runtime_root: PathBuf,
        max_output_bytes: usize,
        timeout: Duration,
        permit_verifier: PermitVerifier,
    ) -> Result<Self, ExecutorConfigError> {
        let sandbox_root = canonical_directory(
            &sandbox_root,
            ExecutorConfigError::SandboxRootNotAbsolute,
            ExecutorConfigError::SandboxRootUnavailable,
        )?;
        let trusted_runtime_root = canonical_directory(
            &trusted_runtime_root,
            ExecutorConfigError::TrustedRuntimeRootNotAbsolute,
            ExecutorConfigError::TrustedRuntimeRootUnavailable,
        )?;
        if roots_overlap(&sandbox_root, &trusted_runtime_root) {
            return Err(ExecutorConfigError::RootsOverlap);
        }
        if max_output_bytes == 0 || max_output_bytes > MAX_EXECUTOR_OUTPUT_BYTES {
            return Err(ExecutorConfigError::InvalidOutputLimit);
        }
        if timeout.is_zero() || timeout > MAX_EXECUTOR_TIMEOUT {
            return Err(ExecutorConfigError::InvalidTimeout);
        }

        Ok(Self {
            sandbox_root,
            trusted_runtime_root,
            max_output_bytes,
            timeout,
            permit_verifier,
        })
    }

    pub fn sandbox_root(&self) -> &Path {
        &self.sandbox_root
    }

    pub fn trusted_runtime_root(&self) -> &Path {
        &self.trusted_runtime_root
    }

    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Debug for ExecutorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutorConfig")
            .field("sandbox_root", &self.sandbox_root)
            .field("trusted_runtime_root", &self.trusted_runtime_root)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("timeout", &self.timeout)
            .field("permit_verifier", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecutorConfigError {
    #[error("sandbox root must be an absolute path")]
    SandboxRootNotAbsolute,
    #[error("sandbox root must identify an existing directory")]
    SandboxRootUnavailable,
    #[error("trusted runtime root must be an absolute path")]
    TrustedRuntimeRootNotAbsolute,
    #[error("trusted runtime root must identify an existing directory")]
    TrustedRuntimeRootUnavailable,
    #[error("sandbox and trusted runtime roots must not overlap")]
    RootsOverlap,
    #[error("executor output limit must be positive and bounded")]
    InvalidOutputLimit,
    #[error("executor timeout must be positive and bounded")]
    InvalidTimeout,
}

#[derive(Debug)]
pub struct DefaultProviderExecutor {
    config: ExecutorConfig,
    catalog: ProviderRegistry,
}

impl DefaultProviderExecutor {
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            config,
            catalog: full_provider_registry(),
        }
    }
}

impl ProviderExecutor for DefaultProviderExecutor {
    fn execute(
        &self,
        permit: &ExecutionPermit,
        request: &ProviderExecutionRequest,
        now: OffsetDateTime,
    ) -> ProviderExecutionOutcome {
        // The verifier requires the current Rust-owned contract as an input.
        // This read-only lookup does not accept or dispatch the provider; the
        // authenticated permit is still the first executable gate.
        let Some(validation_provider) = self.catalog.get(&request.provider) else {
            return blocked("provider_unavailable", "provider_unknown");
        };
        if self
            .config
            .permit_verifier
            .validate(permit, request, validation_provider, now)
            .is_err()
        {
            return blocked("execution_permit_invalid", "permit_validation_failed");
        }

        // Reconfirm the catalog identity after authentication. This remains a
        // pure in-memory comparison and cannot reach a provider implementation.
        let Some(canonical_provider) = self.catalog.get(&request.provider) else {
            return blocked("provider_unavailable", "provider_unknown");
        };
        let contract_matches = canonical_provider_contract_hash(canonical_provider)
            .is_ok_and(|digest| digest == request.provider_contract_hash);
        if canonical_provider.id != request.provider || !contract_matches {
            return blocked("provider_contract_invalid", "provider_contract_mismatch");
        }

        let expected_family = match expected_claim_family(&request.provider, &request.action) {
            Ok(family) => family,
            Err(DispatchValidationError::UnsupportedAction) => {
                return blocked("provider_action_invalid", "unsupported_action");
            }
            Err(DispatchValidationError::NotMigrated) => {
                return blocked("provider_unavailable", "provider_not_migrated");
            }
        };
        if !expected_family.matches(&request.resource_claim) {
            return blocked("resource_claim_invalid", "claim_family_mismatch");
        }

        // Task 5 owns the first private business-tool dispatch. Until then a
        // fully valid permit is truthful authorization evidence, but it is not
        // an implementation and cannot produce a side effect.
        blocked("provider_unavailable", "provider_not_migrated")
    }

    fn reconcile(&self, _operation_id: OperationId) -> ReconciliationResult {
        ReconciliationResult::NotExecuted
    }

    fn finalize_cleanup(
        &self,
        _token: CleanupToken,
        _disposition: CleanupDisposition,
    ) -> Result<(), CleanupError> {
        // Task 4 never returns a cleanup token or creates reconciliation
        // material, so accepting any token here would hide an integrity error.
        Err(CleanupError::UnknownToken)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimFamily {
    FileRead,
    FileWrite,
    Email,
    Network,
    BrowserNetwork,
    MemoryRead,
    MemoryWrite,
    InputInspection,
}

impl ClaimFamily {
    fn matches(self, claim: &ResourceClaim) -> bool {
        match (self, claim) {
            (
                Self::FileRead,
                ResourceClaim::File {
                    access: FileAccess::Read,
                    ..
                },
            )
            | (
                Self::FileWrite,
                ResourceClaim::File {
                    access: FileAccess::Write,
                    ..
                },
            )
            | (Self::Email, ResourceClaim::Email { .. })
            | (Self::Network, ResourceClaim::Network { .. })
            | (
                Self::MemoryRead,
                ResourceClaim::Memory {
                    access: MemoryAccess::Read,
                    ..
                },
            )
            | (
                Self::MemoryWrite,
                ResourceClaim::Memory {
                    access: MemoryAccess::Write,
                    ..
                },
            ) => true,
            (Self::BrowserNetwork, ResourceClaim::Network { method, .. }) => method == "GET",
            (Self::InputInspection, ResourceClaim::InputInspection { source, .. }) => {
                source == "tool_input"
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchValidationError {
    UnsupportedAction,
    NotMigrated,
}

fn expected_claim_family(
    provider: &str,
    action: &str,
) -> Result<ClaimFamily, DispatchValidationError> {
    let (expected_action, family) = match provider {
        "external.mcp.filesystem.read_file" => ("read_file", ClaimFamily::FileRead),
        "external.mcp.filesystem.write_file" => ("write_file", ClaimFamily::FileWrite),
        "external.email.send" => ("send", ClaimFamily::Email),
        "external.api.request" => ("request", ClaimFamily::Network),
        "external.mcp.browser.open_page" => ("open_page", ClaimFamily::BrowserNetwork),
        "external.memory.read" | "external.knowledge.read" => ("read", ClaimFamily::MemoryRead),
        "external.memory.write" | "external.knowledge.write" => ("write", ClaimFamily::MemoryWrite),
        "runwarden.input.inspect" => ("inspect", ClaimFamily::InputInspection),
        _ => return Err(DispatchValidationError::NotMigrated),
    };
    if action != expected_action {
        return Err(DispatchValidationError::UnsupportedAction);
    }
    Ok(family)
}

fn canonical_directory(
    requested: &Path,
    relative_error: ExecutorConfigError,
    unavailable_error: ExecutorConfigError,
) -> Result<PathBuf, ExecutorConfigError> {
    if !requested.is_absolute() {
        return Err(relative_error);
    }
    let canonical = fs::canonicalize(requested).map_err(|_| unavailable_error)?;
    if !canonical.is_dir() {
        return Err(unavailable_error);
    }
    Ok(canonical)
}

fn roots_overlap(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

fn blocked(error_kind: &str, reason_code: &str) -> ProviderExecutionOutcome {
    ProviderExecutionOutcome {
        result: ProviderExecutionResult::blocked(error_kind, reason_code),
        cleanup: None,
    }
}
