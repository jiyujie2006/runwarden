use std::{convert::Infallible, time::Duration};

use axum::{
    Router,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderName},
    response::{
        IntoResponse, Sse,
        sse::{Event, KeepAlive},
    },
    routing::get,
};
use runwarden_kernel::{
    story::{SessionId, StoryId},
    trace::StoryEvent,
};
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::{
    ReviewerApiState,
    api::{self, ApiError},
};

const EVENT_PAGE_LIMIT: u64 = 256;
const EVENT_CHANNEL_CAPACITY: usize = 1;
const MAX_SERIALIZED_EVENT_BYTES: usize = 256 * 1_024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");

type SseItem = Result<Event, Infallible>;

pub(super) fn routes() -> Router<ReviewerApiState> {
    Router::new().route("/events", get(story_events))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoryEventsQuery {
    story_id: String,
    #[serde(default)]
    after_seq: u64,
}

async fn story_events(
    State(state): State<ReviewerApiState>,
    headers: HeaderMap,
    query: Result<Query<StoryEventsQuery>, QueryRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::unprocessable("invalid_query"))?;
    let story_id: StoryId = api::parse_path_id(&query.story_id, "story")?;
    let story = api::active_story_snapshot(&state.store, story_id)?;
    let after_sequence = resume_sequence(&headers, query.after_seq)?;

    let (sender, receiver) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    tokio::spawn(poll_committed_events(
        state,
        story_id,
        story.authority.session_id,
        story.authority.expires_at,
        after_sequence,
        sender,
    ));

    Ok(Sse::new(ReceiverStream::new(receiver)).keep_alive(
        KeepAlive::new()
            .interval(KEEP_ALIVE_INTERVAL)
            .text("keep-alive"),
    ))
}

fn resume_sequence(headers: &HeaderMap, after_sequence: u64) -> Result<u64, ApiError> {
    let Some(raw) = api::exactly_one_header(headers, LAST_EVENT_ID) else {
        if headers.contains_key(LAST_EVENT_ID) {
            return Err(ApiError::unprocessable("invalid_last_event_id"));
        }
        return Ok(after_sequence);
    };
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::unprocessable("invalid_last_event_id"));
    }
    raw.parse()
        .map_err(|_| ApiError::unprocessable("invalid_last_event_id"))
}

async fn poll_committed_events(
    state: ReviewerApiState,
    story_id: StoryId,
    session_id: SessionId,
    authority_expires_at: OffsetDateTime,
    mut after_sequence: u64,
    sender: mpsc::Sender<SseItem>,
) {
    loop {
        if !wait_for_capacity(&sender).await {
            return;
        }
        let events = match read_committed_page(
            &state,
            story_id,
            session_id,
            authority_expires_at,
            after_sequence,
        )
        .await
        {
            Ok(events) => events,
            Err(PollReadError::Inactive) => {
                log_stream_termination(story_id, None, "story context is no longer active");
                return;
            }
            Err(PollReadError::Storage) => {
                log_stream_termination(story_id, None, "verified event read failed");
                return;
            }
        };

        if events.is_empty() {
            tokio::select! {
                () = sender.closed() => return,
                () = tokio::time::sleep(POLL_INTERVAL) => {}
            }
            continue;
        }

        for event in events {
            let sequence = event.sequence;
            let sse_event = match encode_event(&event) {
                Ok(sse_event) => sse_event,
                Err(EncodeError::Serialization) => {
                    log_stream_termination(story_id, Some(sequence), "event serialization failed");
                    return;
                }
                Err(EncodeError::Oversized { bytes }) => {
                    eprintln!(
                        "reviewer SSE stream closed: story_id={story_id} sequence={sequence} \
                         serialized_bytes={bytes} limit_bytes={MAX_SERIALIZED_EVENT_BYTES} \
                         reason=event exceeded the SSE safety bound"
                    );
                    return;
                }
            };
            if sender.send(Ok(sse_event)).await.is_err() {
                return;
            }
            after_sequence = sequence;
        }
    }
}

async fn wait_for_capacity(sender: &mpsc::Sender<SseItem>) -> bool {
    if sender.capacity() > 0 {
        return true;
    }
    match sender.reserve().await {
        Ok(permit) => {
            drop(permit);
            true
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollReadError {
    Inactive,
    Storage,
}

async fn read_committed_page(
    state: &ReviewerApiState,
    story_id: StoryId,
    session_id: SessionId,
    authority_expires_at: OffsetDateTime,
    after_sequence: u64,
) -> Result<Vec<StoryEvent>, PollReadError> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        if OffsetDateTime::now_utc() >= authority_expires_at {
            return Err(PollReadError::Inactive);
        }
        let active = store
            .active_demo()
            .map_err(|_| PollReadError::Storage)?
            .ok_or(PollReadError::Inactive)?;
        if active.story_id != story_id || active.session_id != session_id {
            return Err(PollReadError::Inactive);
        }
        let events = store
            .events_after(story_id, after_sequence, EVENT_PAGE_LIMIT)
            .map_err(|_| PollReadError::Storage)?;
        let active = store
            .active_demo()
            .map_err(|_| PollReadError::Storage)?
            .ok_or(PollReadError::Inactive)?;
        if active.story_id != story_id
            || active.session_id != session_id
            || OffsetDateTime::now_utc() >= authority_expires_at
        {
            return Err(PollReadError::Inactive);
        }
        Ok(events)
    })
    .await
    .map_err(|_| PollReadError::Storage)?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodeError {
    Serialization,
    Oversized { bytes: usize },
}

fn encode_event(event: &StoryEvent) -> Result<Event, EncodeError> {
    let data = serde_json::to_string(event).map_err(|_| EncodeError::Serialization)?;
    if data.len() > MAX_SERIALIZED_EVENT_BYTES {
        return Err(EncodeError::Oversized { bytes: data.len() });
    }
    Ok(Event::default()
        .id(event.sequence.to_string())
        .event("story_event")
        .data(data))
}

fn log_stream_termination(story_id: StoryId, sequence: Option<u64>, reason: &'static str) {
    if let Some(sequence) = sequence {
        eprintln!(
            "reviewer SSE stream closed: story_id={story_id} sequence={sequence} reason={reason}"
        );
    } else {
        eprintln!("reviewer SSE stream closed: story_id={story_id} reason={reason}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_cursor_rejects_noncanonical_or_duplicate_headers() {
        let mut headers = HeaderMap::new();
        assert!(matches!(resume_sequence(&headers, 7), Ok(7)));

        headers.insert(LAST_EVENT_ID, "12".parse().unwrap());
        assert!(matches!(resume_sequence(&headers, 7), Ok(12)));

        headers.append(LAST_EVENT_ID, "13".parse().unwrap());
        assert!(resume_sequence(&headers, 7).is_err());
    }
}
