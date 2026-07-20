mod common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use common::{ApiFixture, ExpiredReaderFixture, REVIEWER_ADDR, SseFixture, json_body, send};
use runwarden_cli::web_server::{ReviewerApiState, reviewer_router};
use runwarden_kernel::{
    story::StoryId,
    trace::{EventCode, StoryEvent},
};
use runwarden_state::StateStore;
use serde_json::Value;
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tower::ServiceExt;

#[derive(Debug)]
struct ReceivedEvent {
    id: u64,
    event: String,
    data: Value,
}

fn sse_request(story_id: impl std::fmt::Display, after_seq: u64) -> Request<Body> {
    Request::builder()
        .uri(format!("/events?story_id={story_id}&after_seq={after_seq}"))
        .header(header::ACCEPT, "text/event-stream")
        .body(Body::empty())
        .unwrap()
}

async fn open_sse(fixture: &SseFixture, request: Request<Body>) -> Response<Body> {
    fixture.app.clone().oneshot(request).await.unwrap()
}

async fn take_events(response: Response<Body>, count: usize) -> Vec<ReceivedEvent> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );

    let mut stream = response.into_body().into_data_stream();
    let mut pending = Vec::new();
    let mut events = Vec::new();
    while events.len() < count {
        let bytes = timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("timed out waiting for SSE data")
            .expect("SSE response ended before the expected events")
            .expect("SSE body error");
        pending.extend_from_slice(&bytes);

        while let Some(boundary) = pending.windows(2).position(|window| window == b"\n\n") {
            let frame = pending.drain(..boundary + 2).collect::<Vec<_>>();
            let frame = std::str::from_utf8(&frame[..frame.len() - 2]).unwrap();
            if frame.lines().all(|line| line.starts_with(':')) {
                continue;
            }

            let mut id = None;
            let mut event = None;
            let mut data = None;
            for line in frame.lines() {
                let (field, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "id" => id = Some(value.parse::<u64>().unwrap()),
                    "event" => event = Some(value.to_owned()),
                    "data" => data = Some(serde_json::from_str(value).unwrap()),
                    _ => {}
                }
            }
            events.push(ReceivedEvent {
                id: id.expect("SSE event id"),
                event: event.expect("SSE event type"),
                data: data.expect("SSE JSON data"),
            });
            if events.len() == count {
                break;
            }
        }
    }
    events
}

fn assert_story_events(events: &[ReceivedEvent], expected_ids: &[u64]) {
    assert_eq!(
        events.iter().map(|event| event.id).collect::<Vec<_>>(),
        expected_ids
    );
    for event in events {
        assert_eq!(event.event, "story_event");
        assert_eq!(event.data["sequence"], event.id);
    }
}

fn assert_event_data(events: &[ReceivedEvent], expected: &[StoryEvent]) {
    assert_story_events(
        events,
        &expected
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.data.clone())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn reconnect_resumes_committed_events_from_last_event_id_or_query_cursor() {
    let fixture = SseFixture::new();
    let story_id = fixture.story.story_id;

    let initial = open_sse(&fixture, sse_request(story_id, 0)).await;
    let initial_events = take_events(initial, 2).await;
    let initial_expected = fixture.store.events_after(story_id, 0, 2).unwrap();
    assert_event_data(&initial_events, &initial_expected);

    let appended = vec![
        fixture.append_numbered_event(3),
        fixture.append_numbered_event(4),
    ];

    let mut header_resume = sse_request(story_id, 0);
    header_resume
        .headers_mut()
        .insert("last-event-id", "2".parse().unwrap());
    let header_events = take_events(open_sse(&fixture, header_resume).await, 2).await;
    assert_event_data(&header_events, &appended);

    let query_events = take_events(open_sse(&fixture, sse_request(story_id, 2)).await, 2).await;
    assert_event_data(&query_events, &appended);
}

#[tokio::test]
async fn caught_up_connection_polls_sqlite_for_new_committed_events() {
    let fixture = SseFixture::new();
    let response = open_sse(&fixture, sse_request(fixture.story.story_id, 2)).await;

    tokio::time::sleep(Duration::from_millis(250)).await;
    let appended = fixture.append_numbered_event(3);

    let events = take_events(response, 1).await;
    assert_event_data(&events, &[appended]);
}

#[tokio::test]
async fn last_event_id_takes_precedence_and_invalid_cursors_fail_closed() {
    let fixture = SseFixture::new();
    let story_id = fixture.story.story_id;

    let mut precedence = sse_request(story_id, 4);
    precedence
        .headers_mut()
        .insert("last-event-id", "1".parse().unwrap());
    let events = take_events(open_sse(&fixture, precedence).await, 1).await;
    assert_story_events(&events, &[2]);

    for invalid in ["", "-1", "+1", " 1", "1 ", "18446744073709551616"] {
        let mut request = sse_request(story_id, 0);
        request
            .headers_mut()
            .insert("last-event-id", invalid.parse().unwrap());
        assert_eq!(
            open_sse(&fixture, request).await.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    let mut duplicate = sse_request(story_id, 0);
    duplicate
        .headers_mut()
        .append("last-event-id", "1".parse().unwrap());
    duplicate
        .headers_mut()
        .append("last-event-id", "2".parse().unwrap());
    assert_eq!(
        open_sse(&fixture, duplicate).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn stream_rejects_missing_foreign_or_inactive_story_contexts() {
    let fixture = SseFixture::new();

    let missing_query = Request::builder()
        .uri("/events?after_seq=0")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        open_sse(&fixture, missing_query).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    assert_eq!(
        open_sse(&fixture, sse_request("not-a-story-id", 0))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let api_fixture = ApiFixture::new();
    let same_database_foreign_story = api_fixture.seeded.other_story.story_id;
    assert_eq!(
        api_fixture
            .app
            .clone()
            .oneshot(sse_request(same_database_foreign_story, 0))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api_fixture
            .app
            .clone()
            .oneshot(sse_request(StoryId::new(), 0))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );

    let expired = ExpiredReaderFixture::new();
    assert_eq!(
        expired
            .app
            .clone()
            .oneshot(sse_request(expired.story_id, 0))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("state")).unwrap();
    let inactive_app = reviewer_router(ReviewerApiState::new(store, REVIEWER_ADDR).unwrap());
    let inactive = inactive_app
        .oneshot(sse_request(fixture.story.story_id, 0))
        .await
        .unwrap();
    assert_eq!(inactive.status(), StatusCode::NOT_FOUND);

    for uri in [
        format!(
            "/events?story_id={}&after_seq=invalid",
            fixture.story.story_id
        ),
        format!(
            "/events?story_id={}&after_seq=0&unexpected=true",
            fixture.story.story_id
        ),
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[tokio::test]
async fn oversized_event_closes_sse_but_remains_available_from_json_api() {
    let fixture = SseFixture::new();
    let story_id = fixture.story.story_id;
    let risk_codes = (0..3_000)
        .map(|index| EventCode::try_from(format!("risk-{index:04}-{}", "x".repeat(110))).unwrap())
        .collect();
    let oversized = fixture.append_oversized_model_filter(risk_codes);
    assert_eq!(oversized.sequence, 4);
    assert!(serde_json::to_vec(&oversized).unwrap().len() > 256 * 1_024);

    let response = open_sse(&fixture, sse_request(story_id, 3)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let next = timeout(Duration::from_secs(3), stream.next())
        .await
        .expect("oversized SSE event should close the stream promptly");
    assert!(next.is_none(), "oversized SSE event must not be emitted");

    let response = send(
        &fixture.app,
        Request::builder()
            .uri(format!("/api/stories/{story_id}/events?after_seq=3"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let events = json_body(response).await;
    assert_eq!(events.as_array().unwrap().len(), 1);
    assert_eq!(events[0]["sequence"], 4);
    assert_eq!(
        events[0]["payload"]["risk_codes"].as_array().unwrap().len(),
        3_000
    );
}
