use runwarden_kernel::story::StoryId;
use rusqlite::TransactionBehavior;

use crate::snapshots::load_story_evidence_tx;
use crate::{JournalError, StateStore, canonical_json};

impl StateStore {
    /// Export a verified compatibility stream without accepting a path or
    /// touching the filesystem. Each canonical `StoryEvent` is followed by a
    /// newline; a story with no events produces an empty byte vector.
    pub fn export_legacy_jsonl(&self, story_id: StoryId) -> Result<Vec<u8>, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let evidence = load_story_evidence_tx(&transaction, story_id)?;
        let mut output = Vec::new();
        for event in &evidence.events {
            let line = canonical_json(event)?;
            let additional = line.len().checked_add(1).ok_or_else(|| {
                JournalError::Integrity("legacy JSONL export size overflowed".to_owned())
            })?;
            output.try_reserve(additional).map_err(|error| {
                JournalError::Integrity(format!(
                    "legacy JSONL export capacity could not be reserved: {error}"
                ))
            })?;
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        }
        transaction.commit()?;
        Ok(output)
    }
}
