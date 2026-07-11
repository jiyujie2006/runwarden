use runwarden_kernel::session::{AuthoritySnapshot, BudgetUsageSnapshot};
use runwarden_kernel::story::{SessionId, StoryId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use time::OffsetDateTime;

use crate::approvals::verify_budget_reservation_aggregate_tx;
use crate::stories::{load_story_record, validate_digest, validate_nonempty};
use crate::{
    JournalError, StateStore, canonical_json, format_time, persisted_json, persisted_string,
    persisted_time, rust_u64,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub story_id: StoryId,
    pub authority: AuthoritySnapshot,
    pub policy_snapshot_hash: String,
    pub expires_at: OffsetDateTime,
}

pub(crate) struct StoredSession {
    pub record: SessionRecord,
    pub active: bool,
    #[allow(dead_code)]
    pub version: u64,
}

struct RawSessionRow {
    session_id: String,
    story_id: String,
    authority_json: String,
    policy_snapshot_hash: String,
    expires_at: String,
    active: i64,
    version: i64,
}

struct RawBudgetRow {
    story_id: String,
    version: i64,
    calls_reserved: i64,
    calls_committed: i64,
    file_bytes_reserved: i64,
    file_bytes_committed: i64,
    network_bytes_reserved: i64,
    network_bytes_committed: i64,
}

impl StateStore {
    pub fn create_session(&self, session: &SessionRecord) -> Result<(), JournalError> {
        validate_session_contract(session)?;
        let authority_json = canonical_json(&session.authority)?;
        let expires_at = format_time(session.expires_at)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let story = load_story_record(&transaction, session.story_id)?;
        if story.story.authority != session.authority
            || story.story.authority.session_id != session.session_id
            || story.story.identity.actor_id != session.authority.actor_id
        {
            return Err(JournalError::Integrity(
                "session authority does not exactly match its story authority".to_owned(),
            ));
        }

        let existing: Option<(String, String)> = transaction
            .query_row(
                r#"SELECT session_id, story_id FROM sessions
                   WHERE session_id = ?1 OR story_id = ?2 LIMIT 1"#,
                params![session.session_id.to_string(), session.story_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((session_id, story_id)) = existing {
            return Err(JournalError::Conflict {
                entity: "session",
                id: format!("{session_id}@{story_id}"),
                expected: 0,
                actual: 1,
            });
        }

        transaction.execute(
            r#"INSERT INTO sessions (
                session_id, story_id, authority_json, policy_snapshot_hash,
                expires_at, active, version
            ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 0)"#,
            params![
                session.session_id.to_string(),
                session.story_id.to_string(),
                authority_json,
                session.policy_snapshot_hash,
                expires_at,
            ],
        )?;
        transaction.execute(
            r#"INSERT INTO budget_usage (
                story_id, session_id, version, calls_reserved,
                calls_committed, file_bytes_reserved, file_bytes_committed,
                network_bytes_reserved, network_bytes_committed
            ) VALUES (?1, ?2, 0, 0, 0, 0, 0, 0, 0)"#,
            params![session.story_id.to_string(), session.session_id.to_string()],
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    pub fn session(&self, session_id: SessionId) -> Result<SessionRecord, JournalError> {
        let connection = self.connection()?;
        Ok(load_session_record(&connection, session_id)?.record)
    }

    pub fn budget_snapshot(
        &self,
        session_id: SessionId,
    ) -> Result<BudgetUsageSnapshot, JournalError> {
        let connection = self.connection()?;
        let session = load_session_record(&connection, session_id)?;
        verify_budget_reservation_aggregate_tx(&connection, session_id)?;
        let raw: Option<RawBudgetRow> = connection
            .query_row(
                r#"SELECT story_id, version, calls_reserved, calls_committed,
                          file_bytes_reserved, file_bytes_committed,
                          network_bytes_reserved, network_bytes_committed
                   FROM budget_usage WHERE session_id = ?1"#,
                params![session_id.to_string()],
                |row| {
                    Ok(RawBudgetRow {
                        story_id: row.get(0)?,
                        version: row.get(1)?,
                        calls_reserved: row.get(2)?,
                        calls_committed: row.get(3)?,
                        file_bytes_reserved: row.get(4)?,
                        file_bytes_committed: row.get(5)?,
                        network_bytes_reserved: row.get(6)?,
                        network_bytes_committed: row.get(7)?,
                    })
                },
            )
            .optional()?;
        let Some(raw) = raw else {
            return Err(JournalError::Integrity(format!(
                "session {session_id} has no budget usage row"
            )));
        };
        let stored_story_id: StoryId = persisted_string(raw.story_id, "budget story id")?;
        if stored_story_id != session.record.story_id {
            return Err(JournalError::Integrity(
                "budget usage story does not match session story".to_owned(),
            ));
        }
        Ok(BudgetUsageSnapshot {
            version: rust_u64(raw.version, "budget version")?,
            calls_reserved: rust_u64(raw.calls_reserved, "reserved calls")?,
            calls_committed: rust_u64(raw.calls_committed, "committed calls")?,
            file_bytes_reserved: rust_u64(raw.file_bytes_reserved, "reserved file bytes")?,
            file_bytes_committed: rust_u64(raw.file_bytes_committed, "committed file bytes")?,
            network_bytes_reserved: rust_u64(raw.network_bytes_reserved, "reserved network bytes")?,
            network_bytes_committed: rust_u64(
                raw.network_bytes_committed,
                "committed network bytes",
            )?,
        })
    }
}

pub(crate) fn load_session_record(
    connection: &Connection,
    session_id: SessionId,
) -> Result<StoredSession, JournalError> {
    let raw = connection
        .query_row(
            r#"SELECT session_id, story_id, authority_json,
                      policy_snapshot_hash, expires_at, active, version
               FROM sessions WHERE session_id = ?1"#,
            params![session_id.to_string()],
            |row| {
                Ok(RawSessionRow {
                    session_id: row.get(0)?,
                    story_id: row.get(1)?,
                    authority_json: row.get(2)?,
                    policy_snapshot_hash: row.get(3)?,
                    expires_at: row.get(4)?,
                    active: row.get(5)?,
                    version: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| JournalError::NotFound {
            entity: "session",
            id: session_id.to_string(),
        })?;

    let stored_session_id: SessionId = persisted_string(raw.session_id, "session id")?;
    let story_id: StoryId = persisted_string(raw.story_id, "session story id")?;
    let authority: AuthoritySnapshot = persisted_json(&raw.authority_json, "session authority")?;
    if canonical_json(&authority)? != raw.authority_json {
        return Err(JournalError::Integrity(
            "stored authority JSON is not canonical".to_owned(),
        ));
    }
    let expires_at = persisted_time(&raw.expires_at, "session expiry")?;
    if format_time(expires_at)? != raw.expires_at {
        return Err(JournalError::Integrity(
            "stored session expiry is not normalized UTC RFC3339".to_owned(),
        ));
    }
    let active = match raw.active {
        0 => false,
        1 => true,
        other => {
            return Err(JournalError::Integrity(format!(
                "stored session active flag is {other}"
            )));
        }
    };
    let record = SessionRecord {
        session_id: stored_session_id,
        story_id,
        authority,
        policy_snapshot_hash: raw.policy_snapshot_hash,
        expires_at,
    };
    validate_session_contract(&record)?;
    if record.session_id != session_id {
        return Err(JournalError::Integrity(
            "stored session id disagrees with lookup id".to_owned(),
        ));
    }
    let story = load_story_record(connection, story_id)?;
    if story.story.authority != record.authority
        || story.story.authority.session_id != record.session_id
        || story.story.identity.actor_id != record.authority.actor_id
    {
        return Err(JournalError::Integrity(
            "stored session authority disagrees with its story".to_owned(),
        ));
    }
    Ok(StoredSession {
        record,
        active,
        version: rust_u64(raw.version, "session version")?,
    })
}

fn validate_session_contract(session: &SessionRecord) -> Result<(), JournalError> {
    if session.session_id != session.authority.session_id {
        return Err(JournalError::Integrity(
            "session id does not match authority session id".to_owned(),
        ));
    }
    if session.policy_snapshot_hash != session.authority.policy_snapshot_hash {
        return Err(JournalError::Integrity(
            "session policy hash does not match authority policy hash".to_owned(),
        ));
    }
    if session.expires_at != session.authority.expires_at {
        return Err(JournalError::Integrity(
            "session expiry does not match authority expiry".to_owned(),
        ));
    }
    validate_digest(
        "session policy snapshot hash",
        &session.policy_snapshot_hash,
    )?;
    validate_nonempty("authority actor id", &session.authority.actor_id)?;
    validate_nonempty("authority id", &session.authority.authz_id)?;
    validate_nonempty("authority state", &session.authority.authz_state)
}
