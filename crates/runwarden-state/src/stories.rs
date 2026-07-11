use runwarden_kernel::story::{
    EnforcementMode, EvidenceStatus, RunMode, SchemaVersion, SecurityStory, StoryId,
    StoryProvenance, StoryStatus,
};
use runwarden_kernel::trace::Sha256Digest;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use time::OffsetDateTime;

use crate::sessions::load_session_record;
use crate::snapshots::load_story_evidence_tx;
use crate::{
    JournalError, StateStore, canonical_json, enum_text, format_time, persisted_enum,
    persisted_json, persisted_string, persisted_time, rust_u64, sqlite_u64,
};

#[derive(Debug, Clone)]
pub struct StoryStatusUpdate {
    pub story_id: StoryId,
    pub expected_version: u64,
    pub status: StoryStatus,
    pub evidence_status: EvidenceStatus,
    pub final_outcome_summary: String,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct DemoActivation {
    pub instance_id: String,
    pub story_id: StoryId,
    pub session_id: runwarden_kernel::story::SessionId,
    pub process_id: u32,
    pub host_id: String,
    pub instance_token_hash: String,
    pub now: OffsetDateTime,
}

/// Trusted local runtime metadata. It contains only the hash of the inherited
/// instance token, never the raw token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveDemo {
    pub instance_id: String,
    pub story_id: StoryId,
    pub session_id: runwarden_kernel::story::SessionId,
    pub process_id: u32,
    pub host_id: String,
    pub instance_token_hash: String,
    pub heartbeat_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ActiveContextSnapshot {
    pub active: ActiveDemo,
    pub story: SecurityStory,
    pub session: crate::SessionRecord,
}

pub(crate) struct StoredStory {
    pub story: SecurityStory,
    pub version: u64,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

struct RawStoryRow {
    story_id: String,
    schema_version: String,
    title: String,
    scenario_id: String,
    run_mode: String,
    enforcement_mode: String,
    status: String,
    evidence_status: String,
    safe_story_json: String,
    version: i64,
    created_at: String,
    updated_at: String,
}

struct RawActiveDemo {
    singleton: i64,
    instance_id: String,
    story_id: String,
    session_id: String,
    process_id: i64,
    host_id: String,
    instance_token_hash: String,
    heartbeat_at: String,
}

impl StateStore {
    pub fn create_story(&self, story: &SecurityStory) -> Result<(), JournalError> {
        validate_story_contract(story)?;
        validate_initial_story(story)?;

        let safe_story_json = canonical_json(story)?;
        let now = OffsetDateTime::now_utc();
        let now = format_time(now)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if story_exists(&transaction, story.story_id)? {
            return Err(JournalError::Conflict {
                entity: "story",
                id: story.story_id.to_string(),
                expected: 0,
                actual: 1,
            });
        }

        transaction.execute(
            r#"INSERT INTO stories (
                story_id, schema_version, title, scenario_id, run_mode,
                enforcement_mode, status, evidence_status, safe_story_json,
                version, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?10)"#,
            params![
                story.story_id.to_string(),
                story.schema_version.as_str(),
                story.title,
                story.scenario_id,
                enum_text(&story.run_mode)?,
                enum_text(&story.enforcement_mode)?,
                enum_text(&story.status)?,
                enum_text(&story.evidence_status)?,
                safe_story_json,
                now,
            ],
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    pub fn story(&self, story_id: StoryId) -> Result<SecurityStory, JournalError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let event_count: i64 = transaction.query_row(
            "SELECT count(*) FROM events WHERE story_id = ?1",
            params![story_id.to_string()],
            |row| row.get(0),
        )?;
        let story = if event_count == 0 {
            load_story_record(&transaction, story_id)?.story
        } else {
            load_story_evidence_tx(&transaction, story_id)?.story
        };
        transaction.commit()?;
        Ok(story)
    }

    pub fn update_story_status(
        &self,
        input: StoryStatusUpdate,
    ) -> Result<SecurityStory, JournalError> {
        let expected_version = sqlite_u64(input.expected_version, "story version")?;
        if input.final_outcome_summary.trim().is_empty() {
            return Err(JournalError::Integrity(
                "story final outcome summary must not be empty".to_owned(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = load_story_record(&transaction, input.story_id)?;
        let event_rows: i64 = transaction.query_row(
            "SELECT count(*) FROM events WHERE story_id = ?1",
            params![input.story_id.to_string()],
            |row| row.get(0),
        )?;
        let frame_rows: i64 = transaction.query_row(
            "SELECT count(*) FROM story_frames WHERE story_id = ?1",
            params![input.story_id.to_string()],
            |row| row.get(0),
        )?;
        if stored.story.event_count != 0 || event_rows != 0 || frame_rows != 0 {
            return Err(JournalError::InvalidTransition {
                entity: "story_after_event",
                from: format!(
                    "json={},events={event_rows},frames={frame_rows}",
                    stored.story.event_count
                ),
                to: "unframed_status_update".to_owned(),
            });
        }
        if stored.version != input.expected_version {
            return Err(JournalError::Conflict {
                entity: "story",
                id: input.story_id.to_string(),
                expected: input.expected_version,
                actual: stored.version,
            });
        }
        if input.now < stored.updated_at || input.now < stored.created_at {
            return Err(JournalError::InvalidTransition {
                entity: "story_time",
                from: format_time(stored.updated_at)?,
                to: format_time(input.now)?,
            });
        }
        validate_status_transition(stored.story.status, input.status)?;
        validate_evidence_transition(
            stored.story.evidence_status,
            input.evidence_status,
            stored.story.provenance,
        )?;
        validate_status_evidence_pair(input.status, input.evidence_status)?;

        let next_version = input
            .expected_version
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("story version overflowed u64".to_owned()))?;
        let next_version_sql = sqlite_u64(next_version, "story version")?;
        let mut story = stored.story;
        story.status = input.status;
        story.evidence_status = input.evidence_status;
        story.final_outcome_summary = input.final_outcome_summary;
        validate_story_contract(&story)?;
        let safe_story_json = canonical_json(&story)?;
        let updated_at = format_time(input.now)?;
        let affected = transaction.execute(
            r#"UPDATE stories
               SET status = ?1,
                   evidence_status = ?2,
                   safe_story_json = ?3,
                   version = ?4,
                   updated_at = ?5
               WHERE story_id = ?6 AND version = ?7"#,
            params![
                enum_text(&story.status)?,
                enum_text(&story.evidence_status)?,
                safe_story_json,
                next_version_sql,
                updated_at,
                story.story_id.to_string(),
                expected_version,
            ],
        )?;
        if affected != 1 {
            let actual: Option<i64> = transaction
                .query_row(
                    "SELECT version FROM stories WHERE story_id = ?1",
                    params![story.story_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            return match actual {
                Some(actual) => Err(JournalError::Conflict {
                    entity: "story",
                    id: story.story_id.to_string(),
                    expected: input.expected_version,
                    actual: rust_u64(actual, "story version")?,
                }),
                None => Err(JournalError::NotFound {
                    entity: "story",
                    id: story.story_id.to_string(),
                }),
            };
        }
        transaction.commit()?;
        self.harden_files()?;
        Ok(story)
    }

    pub fn activate_demo(&self, activation: &DemoActivation) -> Result<(), JournalError> {
        validate_activation(activation)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<String> = transaction
            .query_row(
                "SELECT instance_id FROM active_instances WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return Err(JournalError::Conflict {
                entity: "active_instance",
                id: existing,
                expected: 0,
                actual: 1,
            });
        }

        let story = load_story_record(&transaction, activation.story_id)?;
        let session = load_session_record(&transaction, activation.session_id)?;
        if session.record.story_id != activation.story_id
            || story.story.authority.session_id != activation.session_id
            || session.record.authority != story.story.authority
        {
            return Err(JournalError::Integrity(
                "active instance story, session, and authority do not identify one context"
                    .to_owned(),
            ));
        }
        if !session.active || session.record.authority.authz_state != "active" {
            return Err(JournalError::InvalidTransition {
                entity: "session",
                from: session.record.authority.authz_state,
                to: "active_demo".to_owned(),
            });
        }
        if activation.now >= session.record.expires_at {
            return Err(JournalError::InvalidTransition {
                entity: "session",
                from: "expired".to_owned(),
                to: "active_demo".to_owned(),
            });
        }

        transaction.execute(
            r#"INSERT INTO active_instances (
                singleton, instance_id, story_id, session_id, process_id,
                host_id, instance_token_hash, heartbeat_at
            ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                activation.instance_id,
                activation.story_id.to_string(),
                activation.session_id.to_string(),
                i64::from(activation.process_id),
                activation.host_id,
                activation.instance_token_hash,
                format_time(activation.now)?,
            ],
        )?;
        transaction.commit()?;
        self.harden_files()
    }

    pub fn active_demo(&self) -> Result<Option<ActiveDemo>, JournalError> {
        let connection = self.connection()?;
        let raw: Option<RawActiveDemo> = connection
            .query_row(
                r#"SELECT singleton, instance_id, story_id, session_id,
                          process_id, host_id, instance_token_hash, heartbeat_at
                   FROM active_instances"#,
                [],
                |row| {
                    Ok(RawActiveDemo {
                        singleton: row.get(0)?,
                        instance_id: row.get(1)?,
                        story_id: row.get(2)?,
                        session_id: row.get(3)?,
                        process_id: row.get(4)?,
                        host_id: row.get(5)?,
                        instance_token_hash: row.get(6)?,
                        heartbeat_at: row.get(7)?,
                    })
                },
            )
            .optional()?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        if raw.singleton != 1 {
            return Err(JournalError::Integrity(
                "active instance singleton key is not 1".to_owned(),
            ));
        }
        let story_id: StoryId = persisted_string(raw.story_id, "active instance story id")?;
        let session_id = persisted_string(raw.session_id, "active instance session id")?;
        let process_id = u32::try_from(raw.process_id).map_err(|_| {
            JournalError::Integrity("stored active instance process id is invalid".to_owned())
        })?;
        if process_id == 0 {
            return Err(JournalError::Integrity(
                "stored active instance process id is zero".to_owned(),
            ));
        }
        validate_nonempty("instance id", &raw.instance_id)?;
        validate_nonempty("host id", &raw.host_id)?;
        validate_digest("instance token hash", &raw.instance_token_hash)?;

        let story = load_story_record(&connection, story_id)?;
        let session = load_session_record(&connection, session_id)?;
        if session.record.story_id != story_id
            || story.story.authority.session_id != session_id
            || session.record.authority != story.story.authority
        {
            return Err(JournalError::Integrity(
                "stored active instance context is internally inconsistent".to_owned(),
            ));
        }
        if !session.active || session.record.authority.authz_state != "active" {
            return Err(JournalError::Integrity(
                "stored active instance references an inactive authority".to_owned(),
            ));
        }
        let heartbeat_at = persisted_time(&raw.heartbeat_at, "active instance heartbeat")?;
        if format_time(heartbeat_at)? != raw.heartbeat_at {
            return Err(JournalError::Integrity(
                "stored active instance heartbeat is not normalized UTC RFC3339".to_owned(),
            ));
        }
        if heartbeat_at >= session.record.expires_at {
            return Err(JournalError::Integrity(
                "stored active instance heartbeat is outside the session lifetime".to_owned(),
            ));
        }

        Ok(Some(ActiveDemo {
            instance_id: raw.instance_id,
            story_id,
            session_id,
            process_id,
            host_id: raw.host_id,
            instance_token_hash: raw.instance_token_hash,
            heartbeat_at,
        }))
    }

    /// Load and validate the active instance, verified story, and live session
    /// from one deferred SQLite snapshot. The caller supplies only the hash of
    /// its inherited process token and the current trusted time.
    pub fn active_context_snapshot(
        &self,
        expected_instance_token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<ActiveContextSnapshot, JournalError> {
        validate_digest("expected instance token hash", expected_instance_token_hash)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let raw: RawActiveDemo = transaction
            .query_row(
                r#"SELECT singleton, instance_id, story_id, session_id,
                          process_id, host_id, instance_token_hash, heartbeat_at
                   FROM active_instances"#,
                [],
                |row| {
                    Ok(RawActiveDemo {
                        singleton: row.get(0)?,
                        instance_id: row.get(1)?,
                        story_id: row.get(2)?,
                        session_id: row.get(3)?,
                        process_id: row.get(4)?,
                        host_id: row.get(5)?,
                        instance_token_hash: row.get(6)?,
                        heartbeat_at: row.get(7)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| JournalError::NotFound {
                entity: "active_instance",
                id: "singleton".to_owned(),
            })?;
        if raw.singleton != 1 {
            return Err(JournalError::Integrity(
                "active instance singleton key is not 1".to_owned(),
            ));
        }
        validate_nonempty("instance id", &raw.instance_id)?;
        validate_nonempty("host id", &raw.host_id)?;
        validate_digest("instance token hash", &raw.instance_token_hash)?;
        if raw.instance_token_hash != expected_instance_token_hash {
            return Err(JournalError::Integrity(
                "active instance token does not match trusted startup".to_owned(),
            ));
        }
        let story_id: StoryId = persisted_string(raw.story_id, "active instance story id")?;
        let session_id = persisted_string(raw.session_id, "active instance session id")?;
        let process_id = u32::try_from(raw.process_id).map_err(|_| {
            JournalError::Integrity("stored active instance process id is invalid".to_owned())
        })?;
        if process_id == 0 {
            return Err(JournalError::Integrity(
                "stored active instance process id is zero".to_owned(),
            ));
        }
        let heartbeat_at = persisted_time(&raw.heartbeat_at, "active instance heartbeat")?;
        if format_time(heartbeat_at)? != raw.heartbeat_at || heartbeat_at > now {
            return Err(JournalError::Integrity(
                "stored active instance heartbeat is noncanonical or in the future".to_owned(),
            ));
        }
        let evidence = load_story_evidence_tx(&transaction, story_id)?;
        evidence
            .verify_structure()
            .map_err(JournalError::Integrity)?;
        let session = load_session_record(&transaction, session_id)?;
        if session.record.story_id != story_id
            || evidence.story.authority.session_id != session_id
            || session.record.authority != evidence.story.authority
            || !session.active
            || session.record.authority.authz_state != "active"
            || heartbeat_at >= session.record.expires_at
            || now >= session.record.expires_at
        {
            return Err(JournalError::Integrity(
                "active instance story, session, authority, or lifetime is inconsistent".to_owned(),
            ));
        }
        let active = ActiveDemo {
            instance_id: raw.instance_id,
            story_id,
            session_id,
            process_id,
            host_id: raw.host_id,
            instance_token_hash: raw.instance_token_hash,
            heartbeat_at,
        };
        transaction.commit()?;
        Ok(ActiveContextSnapshot {
            active,
            story: evidence.story,
            session: session.record,
        })
    }
}

pub(crate) fn load_story_record(
    connection: &Connection,
    story_id: StoryId,
) -> Result<StoredStory, JournalError> {
    let raw = connection
        .query_row(
            r#"SELECT story_id, schema_version, title, scenario_id, run_mode,
                      enforcement_mode, status, evidence_status,
                      safe_story_json, version, created_at, updated_at
               FROM stories WHERE story_id = ?1"#,
            params![story_id.to_string()],
            |row| {
                Ok(RawStoryRow {
                    story_id: row.get(0)?,
                    schema_version: row.get(1)?,
                    title: row.get(2)?,
                    scenario_id: row.get(3)?,
                    run_mode: row.get(4)?,
                    enforcement_mode: row.get(5)?,
                    status: row.get(6)?,
                    evidence_status: row.get(7)?,
                    safe_story_json: row.get(8)?,
                    version: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| JournalError::NotFound {
            entity: "story",
            id: story_id.to_string(),
        })?;

    let story: SecurityStory = persisted_json(&raw.safe_story_json, "story")?;
    validate_story_contract(&story)?;
    if canonical_json(&story)? != raw.safe_story_json {
        return Err(JournalError::Integrity(
            "stored story JSON is not canonical".to_owned(),
        ));
    }
    let stored_story_id: StoryId = persisted_string(raw.story_id, "story id")?;
    let stored_schema: SchemaVersion =
        persisted_string(raw.schema_version, "story schema version")?;
    let stored_run_mode: RunMode = persisted_enum(raw.run_mode, "story run mode")?;
    let stored_enforcement: EnforcementMode =
        persisted_enum(raw.enforcement_mode, "story enforcement mode")?;
    let stored_status: StoryStatus = persisted_enum(raw.status, "story status")?;
    let stored_evidence: EvidenceStatus =
        persisted_enum(raw.evidence_status, "story evidence status")?;
    if stored_story_id != story_id
        || story.story_id != story_id
        || stored_schema != story.schema_version
        || raw.title != story.title
        || raw.scenario_id != story.scenario_id
        || stored_run_mode != story.run_mode
        || stored_enforcement != story.enforcement_mode
        || stored_status != story.status
        || stored_evidence != story.evidence_status
    {
        return Err(JournalError::Integrity(
            "stored story columns disagree with the typed safe story".to_owned(),
        ));
    }

    let created_at = persisted_time(&raw.created_at, "story created_at")?;
    let updated_at = persisted_time(&raw.updated_at, "story updated_at")?;
    if format_time(created_at)? != raw.created_at || format_time(updated_at)? != raw.updated_at {
        return Err(JournalError::Integrity(
            "stored story timestamps are not normalized UTC RFC3339".to_owned(),
        ));
    }
    if updated_at < created_at {
        return Err(JournalError::Integrity(
            "stored story updated_at precedes created_at".to_owned(),
        ));
    }
    Ok(StoredStory {
        story,
        version: rust_u64(raw.version, "story version")?,
        created_at,
        updated_at,
    })
}

fn story_exists(connection: &Connection, story_id: StoryId) -> Result<bool, JournalError> {
    connection
        .query_row(
            "SELECT 1 FROM stories WHERE story_id = ?1",
            params![story_id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(Into::into)
}

pub(crate) fn validate_story_contract(story: &SecurityStory) -> Result<(), JournalError> {
    if story.schema_version != runwarden_kernel::story::SchemaVersion::current() {
        return Err(JournalError::Integrity(
            "story schema version is not the current frozen version".to_owned(),
        ));
    }
    validate_nonempty("story title", &story.title)?;
    validate_nonempty("story scenario id", &story.scenario_id)?;
    validate_nonempty("story attack category", &story.attack_category)?;
    validate_nonempty("story identity actor", &story.identity.actor_id)?;
    if story.identity.actor_id != story.authority.actor_id {
        return Err(JournalError::Integrity(
            "story identity actor does not match authority actor".to_owned(),
        ));
    }
    validate_digest(
        "story policy snapshot hash",
        &story.authority.policy_snapshot_hash,
    )?;
    validate_digest("story attack content hash", &story.attack_content_hash)?;
    if let Some(final_event_hash) = story.final_event_hash.as_deref() {
        validate_digest("story final event hash", final_event_hash)?;
    }
    if story.provenance == StoryProvenance::LegacyDerived
        && story.evidence_status != EvidenceStatus::Incomplete
    {
        return Err(JournalError::Integrity(
            "legacy-derived stories must retain incomplete evidence".to_owned(),
        ));
    }
    validate_status_evidence_pair(story.status, story.evidence_status)
}

fn validate_initial_story(story: &SecurityStory) -> Result<(), JournalError> {
    if !story.operations.is_empty()
        || story.event_count != 0
        || !story.report_claims.is_empty()
        || story.final_event_hash.is_some()
    {
        return Err(JournalError::Integrity(
            "Task 2 cannot create a story with unpersisted operations, events, claims, or hashes"
                .to_owned(),
        ));
    }
    if story.evidence_status == EvidenceStatus::Verified {
        return Err(JournalError::Integrity(
            "verified evidence requires the later evidence verifier".to_owned(),
        ));
    }
    Ok(())
}

fn validate_status_transition(from: StoryStatus, to: StoryStatus) -> Result<(), JournalError> {
    let valid = from == to
        || matches!(
            (from, to),
            (
                StoryStatus::Running,
                StoryStatus::AwaitingApproval
                    | StoryStatus::BlockedBeforeSideEffect
                    | StoryStatus::CompletedWithControlledSideEffect
                    | StoryStatus::Failed
                    | StoryStatus::OutcomeUnknown
                    | StoryStatus::EvidenceInvalid
            ) | (
                StoryStatus::AwaitingApproval,
                StoryStatus::BlockedBeforeSideEffect
                    | StoryStatus::CompletedWithControlledSideEffect
                    | StoryStatus::Failed
                    | StoryStatus::OutcomeUnknown
                    | StoryStatus::EvidenceInvalid
            ) | (
                StoryStatus::BlockedBeforeSideEffect
                    | StoryStatus::CompletedWithControlledSideEffect
                    | StoryStatus::Failed
                    | StoryStatus::OutcomeUnknown,
                StoryStatus::EvidenceInvalid
            )
        );
    if valid {
        Ok(())
    } else {
        Err(JournalError::InvalidTransition {
            entity: "story",
            from: enum_text(&from)?,
            to: enum_text(&to)?,
        })
    }
}

fn validate_evidence_transition(
    from: EvidenceStatus,
    to: EvidenceStatus,
    provenance: StoryProvenance,
) -> Result<(), JournalError> {
    if to == EvidenceStatus::Verified {
        return Err(JournalError::InvalidTransition {
            entity: "story_evidence",
            from: enum_text(&from)?,
            to: enum_text(&to)?,
        });
    }
    if provenance == StoryProvenance::LegacyDerived && to != EvidenceStatus::Incomplete {
        return Err(JournalError::InvalidTransition {
            entity: "story_evidence",
            from: enum_text(&from)?,
            to: enum_text(&to)?,
        });
    }
    let valid = from == to
        || matches!(
            (from, to),
            (
                EvidenceStatus::Pending,
                EvidenceStatus::Incomplete | EvidenceStatus::Invalid
            ) | (EvidenceStatus::Incomplete, EvidenceStatus::Invalid)
                | (EvidenceStatus::Verified, EvidenceStatus::Invalid)
        );
    if valid {
        Ok(())
    } else {
        Err(JournalError::InvalidTransition {
            entity: "story_evidence",
            from: enum_text(&from)?,
            to: enum_text(&to)?,
        })
    }
}

fn validate_status_evidence_pair(
    status: StoryStatus,
    evidence: EvidenceStatus,
) -> Result<(), JournalError> {
    if (status == StoryStatus::EvidenceInvalid) != (evidence == EvidenceStatus::Invalid) {
        return Err(JournalError::Integrity(
            "story evidence-invalid status and invalid evidence must occur together".to_owned(),
        ));
    }
    Ok(())
}

fn validate_activation(activation: &DemoActivation) -> Result<(), JournalError> {
    validate_nonempty("instance id", &activation.instance_id)?;
    validate_nonempty("host id", &activation.host_id)?;
    validate_digest("instance token hash", &activation.instance_token_hash)?;
    if activation.process_id == 0 {
        return Err(JournalError::Integrity(
            "active instance process id must be positive".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_digest(label: &'static str, raw: &str) -> Result<(), JournalError> {
    Sha256Digest::try_from(raw.to_owned())
        .map(|_| ())
        .map_err(|error| JournalError::Integrity(format!("{label} is invalid: {error}")))
}

pub(crate) fn validate_nonempty(label: &'static str, raw: &str) -> Result<(), JournalError> {
    if raw.trim().is_empty() {
        Err(JournalError::Integrity(format!(
            "{label} must not be empty"
        )))
    } else {
        Ok(())
    }
}
