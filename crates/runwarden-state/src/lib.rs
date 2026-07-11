//! Durable, story-scoped state for Runwarden.
//!
//! The journal requires Unix owner-only filesystem permissions. The crate
//! still compiles on other targets, but [`StateStore::open`] fails closed with
//! [`JournalError::Permission`] there.

mod store;

pub use store::{StateStore, StoreDiagnostics};

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
