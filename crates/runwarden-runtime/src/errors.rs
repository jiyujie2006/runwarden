use runwarden_kernel::operation::OperationState;
use runwarden_kernel::story::OperationId;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("runtime context is unavailable: {0}")]
    ContextUnavailable(String),
    #[error("provider is not present in the canonical catalog: {0}")]
    ProviderUnknown(String),
    #[error("provider resource request is invalid: {0}")]
    ResourceInvalid(String),
    #[error("journal failed before provider execution: {0}")]
    JournalBeforeExecution(String),
    #[error("journal failed after provider execution for {operation_id}: {reason}")]
    JournalAfterExecution {
        operation_id: OperationId,
        reason: String,
    },
    #[error("provider result committed for {operation_id}, but cleanup failed: {reason}")]
    CleanupAfterCommit {
        operation_id: OperationId,
        reason: String,
    },
    #[error(
        "journal response and cleanup both failed after execution for {operation_id}: {journal_reason}; cleanup: {cleanup_reason}"
    )]
    JournalAndCleanupAfterExecution {
        operation_id: OperationId,
        journal_reason: String,
        cleanup_reason: String,
    },
    #[error("approval was denied for {operation_id}: {reason}")]
    ApprovalDenied {
        operation_id: OperationId,
        reason: String,
    },
    #[error("approval expired for {operation_id}")]
    ApprovalExpired { operation_id: OperationId },
    #[error("operation binding or ownership conflicts for {operation_id}")]
    OperationConflict { operation_id: OperationId },
    #[error("operation {operation_id} is not resumable from {state:?}")]
    OperationNotResumable {
        operation_id: OperationId,
        state: OperationState,
    },
}
