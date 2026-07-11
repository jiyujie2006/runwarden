use runwarden_kernel::story::{
    EventId, ObservationId, OperationId, SessionId, StoryId, StoryReplayFrame,
};
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEvent, StoryEventPayload};
use rusqlite::{OptionalExtension, Transaction, params};
use time::{OffsetDateTime, UtcOffset};

use crate::snapshots::{load_story_snapshot_tx, verify_event_frame_chains_tx};
use crate::stories::load_story_record;
use crate::{
    JournalError, canonical_json, enum_text, format_time, persisted_string, rust_u64, sqlite_u64,
};

pub struct NewStoryEvent {
    pub obs_id: ObservationId,
    pub event_id: EventId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub operation_id: Option<OperationId>,
    pub provider: Option<EventCode>,
    pub payload: StoryEventPayload,
    pub recorded_at: OffsetDateTime,
}

pub struct CommittedStoryEvent {
    pub event: StoryEvent,
    pub frame: StoryReplayFrame,
    pub story_version: u64,
}

pub(crate) fn append_event_and_frame_tx(
    transaction: &Transaction<'_>,
    input: NewStoryEvent,
) -> Result<CommittedStoryEvent, JournalError> {
    verify_event_frame_chains_tx(transaction, input.story_id)?;
    let stored = load_story_record(transaction, input.story_id)?;
    if stored.story.authority.session_id != input.session_id {
        return Err(JournalError::Integrity(
            "event session does not match story authority".to_owned(),
        ));
    }
    if let Some(operation_id) = input.operation_id {
        let operation_tuple: Option<(String, String)> = transaction
            .query_row(
                r#"SELECT story_id, session_id FROM operations
                   WHERE operation_id = ?1"#,
                params![operation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if operation_tuple != Some((input.story_id.to_string(), input.session_id.to_string())) {
            return Err(JournalError::Integrity(
                "event operation does not match story and session".to_owned(),
            ));
        }
    }

    let event_tail: Option<(i64, String)> = transaction
        .query_row(
            r#"SELECT sequence, event_hash FROM events
               WHERE story_id = ?1 ORDER BY sequence DESC LIMIT 1"#,
            params![input.story_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let frame_tail: Option<(i64, String)> = transaction
        .query_row(
            r#"SELECT sequence, frame_hash FROM story_frames
               WHERE story_id = ?1 ORDER BY sequence DESC LIMIT 1"#,
            params![input.story_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match (&event_tail, &frame_tail) {
        (None, None) => {
            if stored.story.event_count != 0 || stored.story.final_event_hash.is_some() {
                return Err(JournalError::Integrity(
                    "story claims an event tail but journal rows are empty".to_owned(),
                ));
            }
        }
        (Some((event_sequence, event_hash)), Some((frame_sequence, _))) => {
            let event_sequence = rust_u64(*event_sequence, "event sequence")?;
            let frame_sequence = rust_u64(*frame_sequence, "frame sequence")?;
            if event_sequence != frame_sequence
                || stored.story.event_count != event_sequence
                || stored.story.final_event_hash.as_deref() != Some(event_hash.as_str())
            {
                return Err(JournalError::Integrity(
                    "story, event, and frame tails disagree".to_owned(),
                ));
            }
        }
        _ => {
            return Err(JournalError::Integrity(
                "event and frame tails are not paired".to_owned(),
            ));
        }
    }

    let previous_event_hash = event_tail
        .as_ref()
        .map(|(_, hash)| persisted_string::<Sha256Digest>(hash.clone(), "previous event hash"))
        .transpose()?;
    let previous_frame_hash = frame_tail
        .as_ref()
        .map(|(_, hash)| persisted_string::<Sha256Digest>(hash.clone(), "previous frame hash"))
        .transpose()?
        .map(|hash| hash.as_str().to_owned());
    let previous_sequence = event_tail
        .as_ref()
        .map_or(Ok(0), |(sequence, _)| rust_u64(*sequence, "event sequence"))?;
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("event sequence overflowed u64".to_owned()))?;
    let sequence_sql = sqlite_u64(sequence, "event sequence")?;
    let story_version = stored
        .version
        .checked_add(1)
        .ok_or_else(|| JournalError::Integrity("story version overflowed u64".to_owned()))?;
    let story_version_sql = sqlite_u64(story_version, "story version")?;
    let recorded_at = input.recorded_at.to_offset(UtcOffset::UTC);
    let recorded_at_text = format_time(recorded_at)?;

    let event = StoryEvent::seal(
        input.obs_id,
        input.event_id,
        input.story_id,
        input.session_id,
        sequence,
        input.operation_id,
        input.provider,
        input.payload,
        previous_event_hash,
        recorded_at,
    );
    let payload_json = canonical_json(event.payload())?;
    transaction.execute(
        r#"INSERT INTO events (
            story_id, sequence, obs_id, event_id, session_id, operation_id,
            event_type, provider, redacted_payload_json, previous_hash,
            event_hash, recorded_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
        params![
            event.story_id.to_string(),
            sequence_sql,
            event.obs_id.to_string(),
            event.event_id.to_string(),
            event.session_id.to_string(),
            event.operation_id.map(|id| id.to_string()),
            enum_text(&event.event_type)?,
            event.provider.as_ref().map(EventCode::as_str),
            payload_json,
            event.previous_hash.as_ref().map(Sha256Digest::as_str),
            event.event_hash(),
            recorded_at_text,
        ],
    )?;

    let snapshot = load_story_snapshot_tx(transaction, input.story_id)?;
    if snapshot.event_count != sequence
        || snapshot.final_event_hash.as_deref() != Some(event.event_hash())
    {
        return Err(JournalError::Integrity(
            "post-event snapshot does not anchor the new event".to_owned(),
        ));
    }
    let safe_story_json = canonical_json(&snapshot)?;
    let affected = transaction.execute(
        r#"UPDATE stories
           SET status = ?1, evidence_status = ?2, safe_story_json = ?3,
               version = ?4, updated_at = ?5
           WHERE story_id = ?6 AND version = ?7"#,
        params![
            enum_text(&snapshot.status)?,
            enum_text(&snapshot.evidence_status)?,
            safe_story_json,
            story_version_sql,
            recorded_at_text,
            input.story_id.to_string(),
            sqlite_u64(stored.version, "story version")?,
        ],
    )?;
    if affected != 1 {
        let actual: Option<i64> = transaction
            .query_row(
                "SELECT version FROM stories WHERE story_id = ?1",
                params![input.story_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        return match actual {
            Some(actual) => Err(JournalError::Conflict {
                entity: "story",
                id: input.story_id.to_string(),
                expected: stored.version,
                actual: rust_u64(actual, "story version")?,
            }),
            None => Err(JournalError::NotFound {
                entity: "story",
                id: input.story_id.to_string(),
            }),
        };
    }

    let frame = StoryReplayFrame::seal(
        sequence,
        story_version,
        event.event_hash().to_owned(),
        previous_frame_hash,
        recorded_at,
        snapshot,
    )?;
    transaction.execute(
        r#"INSERT INTO story_frames (
            story_id, sequence, story_version, event_hash, snapshot_hash,
            previous_frame_hash, frame_hash, safe_story_json, recorded_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
        params![
            input.story_id.to_string(),
            sequence_sql,
            story_version_sql,
            frame.event_hash,
            frame.snapshot_hash,
            frame.previous_frame_hash,
            frame.frame_hash,
            canonical_json(&frame.story)?,
            recorded_at_text,
        ],
    )?;

    Ok(CommittedStoryEvent {
        event,
        frame,
        story_version,
    })
}
