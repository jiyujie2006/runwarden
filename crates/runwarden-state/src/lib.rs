//! Durable, story-scoped state for Runwarden.
//!
//! The journal requires Unix owner-only filesystem permissions. The crate
//! still compiles on other targets, but [`StateStore::open`] fails closed with
//! [`JournalError::Permission`] there.

mod approvals;
mod events;
mod operations;
mod sessions;
pub mod snapshots;
mod store;
mod stories;

pub use approvals::{
    ApprovalDecisionInput, ApprovalRecordV1, DurableApprovalBinding, ExecutionLease,
    ExecutionResultInput, ExecutionStarted, ExpireApprovalInput, LeaseAuthorization, LeaseRequest,
    MarkOutcomeUnknownInput, NewApproval, OneShotConsumption, ReleaseLeaseInput, ReviewerDecision,
};
pub use events::{CommittedStoryEvent, NewStoryEvent};
pub use operations::{
    CreateOperationOutcome, NewOperation, PrivateOperationMaterial, RecordPolicyInput,
};
pub use sessions::SessionRecord;
pub use store::{StateStore, StoreDiagnostics};
pub use stories::{ActiveDemo, DemoActivation, StoryStatusUpdate};

use serde::{Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<String, JournalError> {
    let value = serde_json::to_value(value)?;
    String::from_utf8(runwarden_kernel::trace::canonical_json_v1(&value))
        .map_err(|error| JournalError::Integrity(format!("canonical JSON was not UTF-8: {error}")))
}

pub(crate) fn persisted_json<T: DeserializeOwned>(
    raw: &str,
    entity: &'static str,
) -> Result<T, JournalError> {
    serde_json::from_str(raw).map_err(|error| {
        JournalError::Integrity(format!(
            "stored {entity} JSON failed typed decoding: {error}"
        ))
    })
}

pub(crate) fn enum_text<T: Serialize>(value: &T) -> Result<String, JournalError> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(JournalError::Integrity(
            "serialized enum was not a string".to_owned(),
        )),
    }
}

pub(crate) fn persisted_string<T: DeserializeOwned>(
    raw: String,
    entity: &'static str,
) -> Result<T, JournalError> {
    serde_json::from_value(serde_json::Value::String(raw)).map_err(|error| {
        JournalError::Integrity(format!(
            "stored {entity} value failed typed decoding: {error}"
        ))
    })
}

pub(crate) fn persisted_enum<T: DeserializeOwned>(
    raw: String,
    entity: &'static str,
) -> Result<T, JournalError> {
    persisted_string(raw, entity)
}

pub(crate) fn format_time(value: OffsetDateTime) -> Result<String, JournalError> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|error| JournalError::Integrity(format!("timestamp formatting failed: {error}")))
}

pub(crate) fn persisted_time(
    raw: &str,
    entity: &'static str,
) -> Result<OffsetDateTime, JournalError> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|error| {
        JournalError::Integrity(format!("stored {entity} timestamp is invalid: {error}"))
    })
}

pub(crate) fn sqlite_u64(value: u64, entity: &'static str) -> Result<i64, JournalError> {
    i64::try_from(value).map_err(|_| {
        JournalError::Integrity(format!(
            "{entity} value {value} exceeds SQLite INTEGER range"
        ))
    })
}

pub(crate) fn rust_u64(value: i64, entity: &'static str) -> Result<u64, JournalError> {
    u64::try_from(value)
        .map_err(|_| JournalError::Integrity(format!("stored {entity} value {value} is negative")))
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal entity was not found: {entity} {id}")]
    NotFound { entity: &'static str, id: String },
    #[error("journal version conflict for {entity} {id}: expected {expected}, actual {actual}")]
    Conflict {
        entity: &'static str,
        id: String,
        expected: u64,
        actual: u64,
    },
    #[error("invalid {entity} transition from {from} to {to}")]
    InvalidTransition {
        entity: &'static str,
        from: String,
        to: String,
    },
    #[error("journal integrity failure: {0}")]
    Integrity(String),
    #[error("journal permission failure: {0}")]
    Permission(String),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
