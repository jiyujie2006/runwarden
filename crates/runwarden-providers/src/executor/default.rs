use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use runwarden_kernel::kernel::ProviderRegistry;
use runwarden_kernel::operation::ProviderExecutionStatus;
use runwarden_kernel::resource::{DataClass, FileAccess, MemoryAccess, ResourceClaim};
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{OperationId, SessionId, StoryId};
use runwarden_kernel::trace::Sha256Digest;
use time::OffsetDateTime;

use crate::catalog::full_provider_registry;
use crate::demo_tools::{
    EmailReconciliation, StoreClass, ToolError, ToolExecution, ToolExecutionState,
    ToolFailureStage, finalize_email_cleanup, read_file, read_store, reconcile_email, send_email,
    simulate_api_request, simulate_browser_open, verify_email, write_file, write_store,
};
use crate::resource_claims::{ResourceExtractionContext, ResourceExtractorRegistry};

use super::{
    CleanupDisposition, CleanupError, CleanupToken, ExecutionPermit, ExecutionReceipt,
    PermitVerifier, ProviderExecutionOutcome, ProviderExecutionRequest, ProviderExecutionResult,
    ProviderExecutor, ReconciliationResult, canonical_provider_contract_hash,
};

const MAX_EXECUTOR_OUTPUT_BYTES: usize = 1_048_576;
const MAX_EXECUTOR_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OPERATION_REGISTRY_ENTRIES: usize = 4_096;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> std::io::Result<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity;

#[cfg(not(unix))]
fn directory_identity(path: &Path) -> std::io::Result<DirectoryIdentity> {
    fs::metadata(path).map(|_| DirectoryIdentity)
}

#[derive(Clone)]
pub struct ExecutorConfig {
    sandbox_root: PathBuf,
    sandbox_identity: DirectoryIdentity,
    trusted_runtime_root: PathBuf,
    trusted_runtime_identity: DirectoryIdentity,
    max_output_bytes: usize,
    timeout: Duration,
    permit_verifier: PermitVerifier,
    resource_context: ResourceExtractionContext,
}

impl ExecutorConfig {
    pub fn new(
        sandbox_root: PathBuf,
        trusted_runtime_root: PathBuf,
        max_output_bytes: usize,
        timeout: Duration,
        permit_verifier: PermitVerifier,
    ) -> Result<Self, ExecutorConfigError> {
        Self::new_scoped(
            sandbox_root,
            trusted_runtime_root,
            max_output_bytes,
            timeout,
            permit_verifier,
            ResourceExtractionContext {
                filesystem_root: "contest-workspace".to_owned(),
                memory_namespace: "session-memory".to_owned(),
                knowledge_namespace: "curated-knowledge".to_owned(),
                default_classification: DataClass::Internal,
            },
        )
    }

    pub fn new_scoped(
        sandbox_root: PathBuf,
        trusted_runtime_root: PathBuf,
        max_output_bytes: usize,
        timeout: Duration,
        permit_verifier: PermitVerifier,
        resource_context: ResourceExtractionContext,
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
        if !valid_context_value(&resource_context.filesystem_root)
            || !valid_context_value(&resource_context.memory_namespace)
            || !valid_context_value(&resource_context.knowledge_namespace)
        {
            return Err(ExecutorConfigError::InvalidResourceScope);
        }
        let sandbox_identity = directory_identity(&sandbox_root)
            .map_err(|_| ExecutorConfigError::SandboxRootUnavailable)?;
        let trusted_runtime_identity = directory_identity(&trusted_runtime_root)
            .map_err(|_| ExecutorConfigError::TrustedRuntimeRootUnavailable)?;

        Ok(Self {
            sandbox_root,
            sandbox_identity,
            trusted_runtime_root,
            trusted_runtime_identity,
            max_output_bytes,
            timeout,
            permit_verifier,
            resource_context,
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

    pub fn resource_context(&self) -> &ResourceExtractionContext {
        &self.resource_context
    }

    fn roots_are_pinned(&self) -> bool {
        self.sandbox_root
            .canonicalize()
            .is_ok_and(|path| path == self.sandbox_root)
            && self
                .trusted_runtime_root
                .canonicalize()
                .is_ok_and(|path| path == self.trusted_runtime_root)
            && directory_identity(&self.sandbox_root)
                .is_ok_and(|identity| identity == self.sandbox_identity)
            && directory_identity(&self.trusted_runtime_root)
                .is_ok_and(|identity| identity == self.trusted_runtime_identity)
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
            .field("resource_context", &self.resource_context)
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
    #[error("executor resource scope must contain bounded trusted identifiers")]
    InvalidResourceScope,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OperationKey {
    operation_id: OperationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperationBinding {
    story_id: StoryId,
    session_id: SessionId,
    provider: String,
    action: String,
    argument_hash: Sha256Digest,
    resource_claim_hash: Sha256Digest,
    policy_snapshot_hash: Sha256Digest,
    provider_contract_hash: Sha256Digest,
    budget_charge: BudgetCharge,
    sandbox_root: PathBuf,
    sandbox_identity: DirectoryIdentity,
    trusted_runtime_root: PathBuf,
    trusted_runtime_identity: DirectoryIdentity,
}

impl OperationBinding {
    fn from_request(request: &ProviderExecutionRequest, config: &ExecutorConfig) -> Self {
        Self {
            story_id: request.story_id,
            session_id: request.session_id,
            provider: request.provider.clone(),
            action: request.action.clone(),
            argument_hash: request.argument_hash.clone(),
            resource_claim_hash: request.resource_claim_hash.clone(),
            policy_snapshot_hash: request.policy_snapshot_hash.clone(),
            provider_contract_hash: request.provider_contract_hash.clone(),
            budget_charge: request.budget_charge,
            sandbox_root: config.sandbox_root.clone(),
            sandbox_identity: config.sandbox_identity,
            trusted_runtime_root: config.trusted_runtime_root.clone(),
            trusted_runtime_identity: config.trusted_runtime_identity,
        }
    }
}

struct CachedOperation {
    binding: OperationBinding,
    result: ProviderExecutionResult,
}

#[derive(Default)]
struct OperationRegistry {
    entries: BTreeMap<OperationKey, CachedOperation>,
}

fn operation_registry() -> &'static Mutex<OperationRegistry> {
    static REGISTRY: OnceLock<Mutex<OperationRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(OperationRegistry::default()))
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
        if !self.config.roots_are_pinned() {
            return blocked("sandbox_path_denied", "executor_root_identity_changed");
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

        if !claim_matches_arguments(&self.config, canonical_provider, request) {
            return blocked("resource_claim_invalid", "claim_argument_mismatch");
        }
        if request.provider == "runwarden.input.inspect" {
            return blocked("provider_unavailable", "provider_not_migrated");
        }

        let key = OperationKey {
            operation_id: request.operation_id,
        };
        let binding = OperationBinding::from_request(request, &self.config);
        let mut registry = match operation_registry().lock() {
            Ok(registry) => registry,
            Err(_) => return blocked("executor_state_unavailable", "operation_registry_poisoned"),
        };
        if let Some(cached) = registry.entries.get(&key) {
            if cached.binding != binding {
                return blocked("integrity_error", "operation_binding_mismatch");
            }
            if request.provider == "external.email.send" {
                return match verify_email(
                    &self.config.sandbox_root,
                    request.operation_id,
                    &request.argument_hash,
                    &request.arguments,
                    &request.resource_claim,
                    self.config.max_output_bytes,
                ) {
                    Ok(EmailReconciliation::Completed(execution)) => {
                        let verified = outcome_from_tool_execution(request, *execution);
                        if verified.result == cached.result {
                            verified
                        } else {
                            unknown(
                                request.budget_charge,
                                "receipt_integrity_error",
                                "receipt_integrity_mismatch",
                            )
                        }
                    }
                    Ok(EmailReconciliation::NotFound) => unknown(
                        request.budget_charge,
                        "receipt_integrity_error",
                        "receipt_missing_after_execution",
                    ),
                    Err(error) => outcome_from_tool_error(request.budget_charge, error),
                };
            }
            return ProviderExecutionOutcome {
                result: cached.result.clone(),
                cleanup: None,
            };
        }
        if registry.entries.len() >= MAX_OPERATION_REGISTRY_ENTRIES {
            return blocked("executor_state_unavailable", "operation_registry_full");
        }

        let outcome = match dispatch_tool(&self.config, request, now) {
            Ok(execution) => outcome_from_tool_execution(request, execution),
            Err(error) => outcome_from_tool_error(request.budget_charge, error),
        };
        if matches!(
            outcome.result.execution_status(),
            ProviderExecutionStatus::Completed
                | ProviderExecutionStatus::ExecutedWithError
                | ProviderExecutionStatus::OutcomeUnknown
                | ProviderExecutionStatus::Simulated
        ) {
            registry.entries.insert(
                key,
                CachedOperation {
                    binding,
                    result: outcome.result.clone(),
                },
            );
        }
        outcome
    }

    fn reconcile(&self, operation_id: OperationId) -> ReconciliationResult {
        if !self.config.roots_are_pinned() {
            return ReconciliationResult::Unknown;
        }
        let key = OperationKey { operation_id };
        let cached = match operation_registry().lock() {
            Ok(registry) => registry
                .entries
                .get(&key)
                .map(|cached| (cached.binding.provider.clone(), cached.result.clone())),
            Err(_) => return ReconciliationResult::Unknown,
        };

        if let Some((provider, cached_result)) = cached {
            if provider == "external.email.send" {
                return match reconcile_email(
                    &self.config.sandbox_root,
                    operation_id,
                    self.config.max_output_bytes,
                ) {
                    Ok(EmailReconciliation::Completed(execution)) => {
                        match reconciled_email_result(operation_id, *execution) {
                            Some(result)
                                if result.receipt() == cached_result.receipt()
                                    && result.output_hash() == cached_result.output_hash() =>
                            {
                                ReconciliationResult::Completed(Box::new(result))
                            }
                            _ => ReconciliationResult::Unknown,
                        }
                    }
                    Ok(EmailReconciliation::NotFound) | Err(_) => ReconciliationResult::Unknown,
                };
            }
            return match cached_result.execution_status() {
                ProviderExecutionStatus::Completed => {
                    ReconciliationResult::Completed(Box::new(cached_result))
                }
                ProviderExecutionStatus::NotExecuted
                | ProviderExecutionStatus::FailedBeforeSideEffect => {
                    ReconciliationResult::NotExecuted
                }
                ProviderExecutionStatus::Running
                | ProviderExecutionStatus::ExecutedWithError
                | ProviderExecutionStatus::OutcomeUnknown
                | ProviderExecutionStatus::Simulated => ReconciliationResult::Unknown,
            };
        }

        match reconcile_email(
            &self.config.sandbox_root,
            operation_id,
            self.config.max_output_bytes,
        ) {
            Ok(EmailReconciliation::Completed(execution)) => {
                reconciled_email_result(operation_id, *execution)
                    .map(|result| ReconciliationResult::Completed(Box::new(result)))
                    .unwrap_or(ReconciliationResult::Unknown)
            }
            Ok(EmailReconciliation::NotFound) => ReconciliationResult::NotExecuted,
            Err(_) => ReconciliationResult::Unknown,
        }
    }

    fn finalize_cleanup(
        &self,
        token: CleanupToken,
        disposition: CleanupDisposition,
    ) -> Result<(), CleanupError> {
        if !self.config.roots_are_pinned() {
            return Err(CleanupError::Failed {
                reason_code: "executor_root_identity_changed".to_owned(),
            });
        }
        if token.provider() != "external.email.send" {
            return Err(CleanupError::ProviderMismatch);
        }
        let expected = CleanupToken::bind(
            token.operation_id(),
            token.provider().to_owned(),
            token.relative_path().clone(),
            token.sha256().clone(),
        );
        if expected.id() != token.id() {
            return Err(CleanupError::UnknownToken);
        }
        if disposition == CleanupDisposition::JournalFailedRetainForReconcile {
            return Ok(());
        }
        finalize_email_cleanup(
            &self.config.sandbox_root,
            token.operation_id(),
            token.relative_path(),
            token.sha256(),
            self.config.max_output_bytes,
        )
        .map_err(|error| CleanupError::Failed {
            reason_code: error.reason_code().to_owned(),
        })
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

fn claim_matches_arguments(
    config: &ExecutorConfig,
    provider: &runwarden_kernel::KernelProvider,
    request: &ProviderExecutionRequest,
) -> bool {
    ResourceExtractorRegistry::contest_default()
        .extract(
            provider,
            &request.action,
            &request.arguments,
            &config.resource_context,
        )
        .is_ok_and(|claim| claim == request.resource_claim)
}

fn dispatch_tool(
    config: &ExecutorConfig,
    request: &ProviderExecutionRequest,
    now: OffsetDateTime,
) -> Result<ToolExecution, ToolError> {
    let max_output =
        u64::try_from(config.max_output_bytes).map_err(|_| ToolError::LimitExceeded)?;
    match request.provider.as_str() {
        "external.mcp.filesystem.read_file" => read_file(
            &config.sandbox_root,
            &request.arguments,
            &request.resource_claim,
            max_output.min(request.budget_charge.file_bytes),
        ),
        "external.mcp.filesystem.write_file" => write_file(
            &config.sandbox_root,
            &request.arguments,
            &request.resource_claim,
            max_output.min(request.budget_charge.file_bytes),
        ),
        "external.email.send" => send_email(
            &config.sandbox_root,
            request.operation_id,
            &request.argument_hash,
            &request.arguments,
            &request.resource_claim,
            now,
            config.max_output_bytes,
        ),
        "external.api.request" => simulate_api_request(&request.arguments, &request.resource_claim),
        "external.mcp.browser.open_page" => {
            simulate_browser_open(&request.arguments, &request.resource_claim)
        }
        "external.memory.read" => read_store(
            &config.sandbox_root,
            StoreClass::Memory,
            &request.arguments,
            &request.resource_claim,
            max_output.min(request.budget_charge.file_bytes),
        ),
        "external.memory.write" => write_store(
            &config.sandbox_root,
            StoreClass::Memory,
            &request.arguments,
            &request.resource_claim,
            max_output.min(request.budget_charge.file_bytes),
        ),
        "external.knowledge.read" => read_store(
            &config.sandbox_root,
            StoreClass::Knowledge,
            &request.arguments,
            &request.resource_claim,
            max_output.min(request.budget_charge.file_bytes),
        ),
        "external.knowledge.write" => write_store(
            &config.sandbox_root,
            StoreClass::Knowledge,
            &request.arguments,
            &request.resource_claim,
            max_output.min(request.budget_charge.file_bytes),
        ),
        _ => Err(ToolError::InvalidRequest),
    }
}

fn reconciled_email_result(
    operation_id: OperationId,
    execution: ToolExecution,
) -> Option<ProviderExecutionResult> {
    if execution.state != ToolExecutionState::Completed || execution.cleanup.is_some() {
        return None;
    }
    let receipt = execution.receipt?;
    if receipt.operation_id != operation_id || receipt.kind != "email_receipt" {
        return None;
    }
    ProviderExecutionResult::completed(
        execution.output,
        Some(ExecutionReceipt {
            operation_id: receipt.operation_id,
            kind: receipt.kind,
            relative_path: receipt.relative_path,
            sha256: receipt.sha256,
        }),
        execution.actual_budget_charge,
    )
    .ok()
}

fn outcome_from_tool_execution(
    request: &ProviderExecutionRequest,
    execution: ToolExecution,
) -> ProviderExecutionOutcome {
    let ToolExecution {
        state,
        output,
        actual_budget_charge,
        receipt,
        cleanup,
    } = execution;

    if state == ToolExecutionState::Simulated && (receipt.is_some() || cleanup.is_some()) {
        return blocked("provider_result_invalid", "simulated_result_has_material");
    }
    let receipt = match receipt {
        Some(receipt)
            if request.provider == "external.email.send"
                && receipt.operation_id == request.operation_id
                && receipt.kind == "email_receipt" =>
        {
            Some(ExecutionReceipt {
                operation_id: receipt.operation_id,
                kind: receipt.kind,
                relative_path: receipt.relative_path,
                sha256: receipt.sha256,
            })
        }
        Some(_) => {
            return unknown(
                request.budget_charge,
                "provider_result_invalid",
                "receipt_binding_invalid",
            );
        }
        None => None,
    };

    let result = match state {
        ToolExecutionState::Completed => {
            ProviderExecutionResult::completed(output, receipt, actual_budget_charge)
        }
        ToolExecutionState::Simulated => {
            ProviderExecutionResult::simulated(output, "provider_simulated")
        }
    };
    let result = match result {
        Ok(result) if result.validate_against(request.budget_charge).is_ok() => result,
        _ if state == ToolExecutionState::Completed => {
            return unknown(
                request.budget_charge,
                "provider_result_invalid",
                "result_budget_or_shape_invalid",
            );
        }
        _ => return blocked("provider_result_invalid", "simulated_result_invalid"),
    };
    let cleanup = cleanup.map(|cleanup| {
        CleanupToken::bind(
            request.operation_id,
            request.provider.clone(),
            cleanup.relative_path,
            cleanup.sha256,
        )
    });
    ProviderExecutionOutcome { result, cleanup }
}

fn outcome_from_tool_error(reserved: BudgetCharge, error: ToolError) -> ProviderExecutionOutcome {
    if error == ToolError::BindingConflict {
        return blocked(error.error_kind(), error.reason_code());
    }
    let result = match error.failure_stage() {
        ToolFailureStage::BeforeSideEffect => ProviderExecutionResult::failed_before_side_effect(
            error.error_kind(),
            error.reason_code(),
        ),
        ToolFailureStage::ExecutedWithError => ProviderExecutionResult::executed_with_error(
            error.error_kind(),
            error.reason_code(),
            reserved,
        )
        .unwrap_or_else(|_| {
            ProviderExecutionResult::outcome_unknown(
                "provider_result_invalid",
                "executed_error_result_invalid",
                reserved,
            )
            .expect("a permit-validated reservation forms a valid unknown result")
        }),
        ToolFailureStage::OutcomeUnknown => {
            return unknown(reserved, error.error_kind(), error.reason_code());
        }
    };
    ProviderExecutionOutcome {
        result,
        cleanup: None,
    }
}

fn unknown(
    reserved: BudgetCharge,
    error_kind: &str,
    reason_code: &str,
) -> ProviderExecutionOutcome {
    match ProviderExecutionResult::outcome_unknown(error_kind, reason_code, reserved) {
        Ok(result) => ProviderExecutionOutcome {
            result,
            cleanup: None,
        },
        Err(_) => blocked("provider_result_invalid", "unknown_result_invalid"),
    }
}

fn valid_context_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
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
