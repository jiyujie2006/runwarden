mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use common::{
    ApiFixture, ExpiredReaderFixture, MinorReaderFixture, PRIVATE_MARKER, REVIEWER_ORIGIN,
    get_request, json_body, send,
};
use runwarden_kernel::story::{OperationId, StoryId};

#[tokio::test]
async fn bootstrap_and_story_list_preserve_the_actual_schema_and_expose_no_secrets() {
    let fixture = ApiFixture::new();

    let bootstrap_response = send(&fixture.app, get_request("/api/bootstrap")).await;
    assert_eq!(bootstrap_response.status(), StatusCode::OK);
    let bootstrap = json_body(bootstrap_response).await;
    let keys: BTreeSet<_> = bootstrap.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "accepted_origin".to_owned(),
            "active_story_id".to_owned(),
            "evidence".to_owned(),
            "mode".to_owned(),
            "reviewer_nonce".to_owned(),
            "schema_version".to_owned(),
        ])
    );
    assert_eq!(bootstrap["schema_version"], "1.0.0");
    assert_eq!(bootstrap["mode"], "live");
    assert_eq!(
        bootstrap["active_story_id"],
        fixture.seeded.active_story.story_id.to_string()
    );
    assert_eq!(bootstrap["accepted_origin"], REVIEWER_ORIGIN);
    assert_eq!(bootstrap["evidence"]["story"]["schema_version"], "1.0.0");
    assert_eq!(bootstrap["evidence"]["events"].as_array().unwrap().len(), 3);
    assert_eq!(
        bootstrap["evidence"]["replay_frames"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(!bootstrap.to_string().contains(PRIVATE_MARKER));

    let stories_response = send(&fixture.app, get_request("/api/stories")).await;
    assert_eq!(stories_response.status(), StatusCode::OK);
    let stories = json_body(stories_response).await;
    let stories = stories.as_array().unwrap();
    assert_eq!(stories.len(), 1);
    assert_eq!(
        stories[0]["story_id"],
        fixture.seeded.active_story.story_id.to_string()
    );
    assert_eq!(stories[0]["schema_version"], "1.0.0");
    assert!(
        !serde_json::to_string(stories)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );
}

#[tokio::test]
async fn bootstrap_preserves_a_supported_minor_written_by_a_compatible_future_writer() {
    let fixture = MinorReaderFixture::new();

    let bootstrap_response = send(&fixture.app, get_request("/api/bootstrap")).await;
    assert_eq!(bootstrap_response.status(), StatusCode::OK);
    let bootstrap = json_body(bootstrap_response).await;
    assert_eq!(bootstrap["schema_version"], "1.7.9");
    assert_eq!(bootstrap["active_story_id"], fixture.story_id.to_string());
    assert_eq!(bootstrap["evidence"]["story"]["schema_version"], "1.7.9");
    assert!(
        bootstrap["evidence"]["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .store
            .story_snapshot(fixture.story_id)
            .unwrap()
            .schema_version
            .as_str(),
        "1.7.9"
    );
}

#[tokio::test]
async fn story_event_operation_report_and_structural_verification_routes_are_safe() {
    let fixture = ApiFixture::new();
    let story_id = fixture.seeded.active_story.story_id;
    let operation_id = fixture.seeded.active_operation_id;

    let story_response = send(
        &fixture.app,
        get_request(&format!("/api/stories/{story_id}")),
    )
    .await;
    assert_eq!(story_response.status(), StatusCode::OK);
    let story = json_body(story_response).await;
    assert_eq!(story["story_id"], story_id.to_string());
    assert_eq!(story["event_count"], 3);
    assert_eq!(story["operations"].as_array().unwrap().len(), 1);
    assert!(!story.to_string().contains(PRIVATE_MARKER));

    let all_events_response = send(
        &fixture.app,
        get_request(&format!("/api/stories/{story_id}/events?after_seq=0")),
    )
    .await;
    assert_eq!(all_events_response.status(), StatusCode::OK);
    let all_events = json_body(all_events_response).await;
    let all_events = all_events.as_array().unwrap();
    assert_eq!(all_events.len(), 3);
    assert_eq!(all_events[0]["sequence"], 1);
    assert_eq!(all_events[1]["sequence"], 2);
    assert_eq!(all_events[2]["sequence"], 3);
    assert!(
        !serde_json::to_string(all_events)
            .unwrap()
            .contains(PRIVATE_MARKER)
    );

    let later_events_response = send(
        &fixture.app,
        get_request(&format!("/api/stories/{story_id}/events?after_seq=2")),
    )
    .await;
    assert_eq!(later_events_response.status(), StatusCode::OK);
    let later_events = json_body(later_events_response).await;
    let later_events = later_events.as_array().unwrap();
    assert_eq!(later_events.len(), 1);
    assert_eq!(later_events[0]["sequence"], 3);

    let operation_response = send(
        &fixture.app,
        get_request(&format!(
            "/api/stories/{story_id}/operations/{operation_id}"
        )),
    )
    .await;
    assert_eq!(operation_response.status(), StatusCode::OK);
    let operation = json_body(operation_response).await;
    assert_eq!(
        operation["operation"]["operation_id"],
        operation_id.to_string()
    );
    assert_eq!(operation["operation"]["story_id"], story_id.to_string());
    assert_eq!(operation["operation"]["approval"]["state"], "pending");
    assert_eq!(operation["approval_version"], 0);
    assert!(!operation.to_string().contains(PRIVATE_MARKER));

    let report_response = send(
        &fixture.app,
        get_request(&format!("/api/stories/{story_id}/report")),
    )
    .await;
    assert_eq!(report_response.status(), StatusCode::OK);
    let report = json_body(report_response).await;
    assert!(report.as_array().unwrap().is_empty());

    let verification_response = send(
        &fixture.app,
        get_request(&format!("/api/stories/{story_id}/evidence/verify")),
    )
    .await;
    assert_eq!(verification_response.status(), StatusCode::OK);
    let verification = json_body(verification_response).await;
    assert_eq!(verification["verification_scope"], "structural");
    assert_eq!(verification["structural_valid"], true);
    assert_eq!(verification["evidence_status"], "pending");
    assert_ne!(verification.get("verified"), Some(&serde_json::json!(true)));
    assert!(!verification.to_string().contains(PRIVATE_MARKER));

    assert_eq!(
        fixture
            .seeded
            .store
            .story_snapshot(story_id)
            .unwrap()
            .evidence_status,
        runwarden_kernel::story::EvidenceStatus::Pending
    );
}

#[tokio::test]
async fn every_story_scoped_reader_hides_unknown_and_cross_story_ids() {
    let fixture = ApiFixture::new();
    let active_story_id = fixture.seeded.active_story.story_id;
    let other_story_id = fixture.seeded.other_story.story_id;
    let other_operation_id = fixture.seeded.other_operation_id;
    let unknown_story_id = StoryId::new();
    let unknown_operation_id = OperationId::new();

    for uri in [
        format!("/api/stories/{other_story_id}"),
        format!("/api/stories/{other_story_id}/events?after_seq=0"),
        format!("/api/stories/{active_story_id}/operations/{other_operation_id}"),
        format!("/api/stories/{active_story_id}/operations/{unknown_operation_id}"),
        format!("/api/stories/{other_story_id}/report"),
        format!("/api/stories/{other_story_id}/evidence/verify"),
        format!("/api/stories/{unknown_story_id}"),
    ] {
        let response = send(&fixture.app, get_request(&uri)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn expired_active_authority_cannot_read_story_scoped_state() {
    let fixture = ExpiredReaderFixture::new();
    let story_id = fixture.story_id;

    let stories = send(&fixture.app, get_request("/api/stories")).await;
    assert_eq!(stories.status(), StatusCode::OK);
    assert!(json_body(stories).await.as_array().unwrap().is_empty());

    for uri in [
        "/api/bootstrap".to_owned(),
        format!("/api/stories/{story_id}"),
        format!("/api/stories/{story_id}/events?after_seq=0"),
        format!("/api/stories/{story_id}/operations/{}", OperationId::new()),
        format!("/api/stories/{story_id}/report"),
        format!("/api/stories/{story_id}/evidence/verify"),
    ] {
        let response = send(&fixture.app, get_request(&uri)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{uri}");
    }
}
