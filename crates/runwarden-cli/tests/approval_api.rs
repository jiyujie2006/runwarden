mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{
    ApiFixture, PRIVATE_MARKER, REVIEWER_ADDR, REVIEWER_ORIGIN, SeededStore, decision_request,
    json_body, reviewer_nonce, send,
};
use runwarden_cli::web_server::{ReviewerApiState, reviewer_router};
use runwarden_kernel::{
    authority::ApprovalState,
    operation::{OperationState, SideEffectState},
    story::ApprovalId,
    trace::{Sha256Digest, StoryEventPayload},
};
use serde_json::{Value, json};
use time::Duration;

fn decision_body(decision: &str, reviewer: &str, reason: &str) -> Value {
    json!({
        "decision": decision,
        "reviewer": reviewer,
        "reason": reason,
        "expected_approval_version": 0,
        "expected_operation_version": 1,
    })
}

#[tokio::test]
async fn approving_updates_both_versions_and_commits_one_safe_event() {
    let fixture = ApiFixture::new();
    let nonce = reviewer_nonce(&fixture.app).await;
    let approval_id = fixture.seeded.active_approval.approval_id;
    let operation_id = fixture.seeded.active_operation_id;
    let reviewer = "reviewer-primary";
    let reason = "approved for this one bounded execution";

    let before = fixture
        .seeded
        .store
        .story_evidence(fixture.seeded.active_story.story_id)
        .unwrap();
    assert_eq!(before.events.len(), 3);

    let response = send(
        &fixture.app,
        decision_request(
            approval_id,
            decision_body("approve", reviewer, reason),
            Some(REVIEWER_ORIGIN),
            Some(&nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = json_body(response).await;
    assert_eq!(response_body["approval_id"], approval_id.to_string());
    assert_eq!(response_body["operation_id"], operation_id.to_string());
    assert_eq!(response_body["approval_state"], "approved");
    assert_eq!(response_body["approval_version"], 1);
    assert_eq!(response_body["operation_state"], "approved");
    assert_eq!(response_body["operation_version"], 2);
    assert_eq!(response_body["side_effect_state"], "not_attempted");
    assert!(!response_body.to_string().contains(PRIVATE_MARKER));

    let approval = fixture.seeded.store.approval(approval_id).unwrap();
    assert_eq!(approval.state, ApprovalState::Approved);
    assert_eq!(approval.version, 1);
    assert_eq!(approval.reviewer.as_deref(), Some(reviewer));
    assert_eq!(approval.reason.as_deref(), Some(reason));
    let operation = fixture.seeded.store.operation(operation_id).unwrap();
    assert_eq!(operation.state, OperationState::Approved);
    assert_eq!(operation.version, 2);
    assert_eq!(operation.side_effect_state, SideEffectState::NotAttempted);
    assert!(operation.provider_result.is_none());

    let evidence = fixture
        .seeded
        .store
        .story_evidence(fixture.seeded.active_story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 4);
    let expected_reviewer_hash = Sha256Digest::from_bytes(reviewer.as_bytes());
    assert!(matches!(
        evidence.events.last().unwrap().payload(),
        StoryEventPayload::ApprovalLifecycle {
            approval_id: event_approval_id,
            state: ApprovalState::Approved,
            reviewer_id_hash: Some(actual),
        } if *event_approval_id == approval_id && actual == &expected_reviewer_hash
    ));
    let events_json = serde_json::to_string(&evidence.events).unwrap();
    assert!(!events_json.contains(reason));
    assert!(!events_json.contains(PRIVATE_MARKER));
}

#[tokio::test]
async fn denying_blocks_before_execution_and_commits_the_denial() {
    let fixture = ApiFixture::new();
    let nonce = reviewer_nonce(&fixture.app).await;
    let approval_id = fixture.seeded.active_approval.approval_id;
    let operation_id = fixture.seeded.active_operation_id;

    let response = send(
        &fixture.app,
        decision_request(
            approval_id,
            decision_body(
                "deny",
                "reviewer-deny",
                "the recipient is outside the approved scope",
            ),
            Some(REVIEWER_ORIGIN),
            Some(&nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let approval = fixture.seeded.store.approval(approval_id).unwrap();
    assert_eq!(approval.state, ApprovalState::Denied);
    assert_eq!(approval.version, 1);
    let operation = fixture.seeded.store.operation(operation_id).unwrap();
    assert_eq!(operation.state, OperationState::DeniedByReviewer);
    assert_eq!(operation.version, 2);
    assert_eq!(
        operation.side_effect_state,
        SideEffectState::BlockedBeforeExecution
    );
    assert!(operation.provider_result.is_none());

    let evidence = fixture
        .seeded
        .store
        .story_evidence(fixture.seeded.active_story.story_id)
        .unwrap();
    assert_eq!(evidence.events.len(), 4);
    assert!(matches!(
        evidence.events.last().unwrap().payload(),
        StoryEventPayload::ApprovalLifecycle {
            approval_id: event_approval_id,
            state: ApprovalState::Denied,
            reviewer_id_hash: Some(_),
        } if *event_approval_id == approval_id
    ));
}

#[tokio::test]
async fn invalid_decision_bodies_are_422_and_do_not_mutate_authority() {
    let fixture = ApiFixture::new();
    let nonce = reviewer_nonce(&fixture.app).await;
    let approval_id = fixture.seeded.active_approval.approval_id;

    let mut unknown_field = decision_body("approve", "reviewer", "bounded approval");
    unknown_field["unexpected"] = json!(true);
    let mut approval_id_in_body = decision_body("approve", "reviewer", "bounded approval");
    approval_id_in_body["approval_id"] = json!(approval_id.to_string());

    for body in [
        unknown_field,
        approval_id_in_body,
        decision_body("approve", "   ", "bounded approval"),
        decision_body("deny", "reviewer", "\t\n"),
        decision_body("approve", &"r".repeat(257), "bounded approval"),
        decision_body("deny", "reviewer", &"x".repeat(4_097)),
        decision_body("allow", "reviewer", "bounded approval"),
        json!({
            "decision": "approve",
            "reviewer": "reviewer",
            "reason": null,
            "expected_approval_version": 0,
            "expected_operation_version": 1,
        }),
        json!({
            "decision": "approve",
            "reviewer": "reviewer",
            "reason": "bounded approval",
            "expected_operation_version": 1,
        }),
        json!({
            "decision": "approve",
            "reviewer": "reviewer",
            "reason": "bounded approval",
            "expected_approval_version": -1,
            "expected_operation_version": 1,
        }),
    ] {
        let response = send(
            &fixture.app,
            decision_request(approval_id, body, Some(REVIEWER_ORIGIN), Some(&nonce)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    assert_eq!(
        fixture.seeded.store.approval(approval_id).unwrap().state,
        ApprovalState::Pending
    );
    assert_eq!(
        fixture.seeded.store.approval(approval_id).unwrap().version,
        0
    );
    assert_eq!(
        fixture
            .seeded
            .store
            .operation(fixture.seeded.active_operation_id)
            .unwrap()
            .version,
        1
    );
    assert_eq!(
        fixture
            .seeded
            .store
            .story_evidence(fixture.seeded.active_story.story_id)
            .unwrap()
            .events
            .len(),
        3
    );

    let malformed = Request::builder()
        .method("POST")
        .uri(format!("/api/approvals/{approval_id}/decision"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, REVIEWER_ORIGIN)
        .header(runwarden_cli::web_server::REVIEWER_NONCE_HEADER, &nonce)
        .body(Body::from("{"))
        .unwrap();
    assert_eq!(
        send(&fixture.app, malformed).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn stale_repeat_unknown_and_cross_story_decisions_fail_closed() {
    let fixture = ApiFixture::new();
    let nonce = reviewer_nonce(&fixture.app).await;
    let approval_id = fixture.seeded.active_approval.approval_id;

    let mut stale_approval = decision_body("approve", "reviewer", "stale approval version");
    stale_approval["expected_approval_version"] = json!(9);
    let response = send(
        &fixture.app,
        decision_request(
            approval_id,
            stale_approval,
            Some(REVIEWER_ORIGIN),
            Some(&nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let mut stale_operation = decision_body("approve", "reviewer", "stale operation version");
    stale_operation["expected_operation_version"] = json!(0);
    let response = send(
        &fixture.app,
        decision_request(
            approval_id,
            stale_operation,
            Some(REVIEWER_ORIGIN),
            Some(&nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let mut hidden_error_codes = Vec::new();
    for hidden_id in [ApprovalId::new(), fixture.seeded.other_approval.approval_id] {
        let response = send(
            &fixture.app,
            decision_request(
                hidden_id,
                decision_body("approve", "reviewer", "hidden approval"),
                Some(REVIEWER_ORIGIN),
                Some(&nonce),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        hidden_error_codes.push(json_body(response).await["error"]["code"].clone());
    }
    assert_eq!(hidden_error_codes[0], hidden_error_codes[1]);

    let valid_body = decision_body("approve", "reviewer", "single decision");
    let response = send(
        &fixture.app,
        decision_request(
            approval_id,
            valid_body.clone(),
            Some(REVIEWER_ORIGIN),
            Some(&nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let repeat = send(
        &fixture.app,
        decision_request(approval_id, valid_body, Some(REVIEWER_ORIGIN), Some(&nonce)),
    )
    .await;
    assert_eq!(repeat.status(), StatusCode::CONFLICT);
    assert_eq!(
        fixture.seeded.store.approval(approval_id).unwrap().version,
        1
    );
    assert_eq!(
        fixture
            .seeded
            .store
            .story_evidence(fixture.seeded.active_story.story_id)
            .unwrap()
            .events
            .len(),
        4
    );
}

#[tokio::test]
async fn reviewer_decision_requires_one_server_owned_active_story() {
    let seeded = SeededStore::new(false);
    let state = ReviewerApiState::new(seeded.store.clone(), REVIEWER_ADDR).unwrap();
    let nonce = state.encoded_nonce();
    let app = reviewer_router(state);
    let response = send(
        &app,
        decision_request(
            seeded.active_approval.approval_id,
            decision_body("approve", "reviewer", "inactive reviewer context"),
            Some(REVIEWER_ORIGIN),
            Some(&nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        seeded
            .store
            .approval(seeded.active_approval.approval_id)
            .unwrap()
            .state,
        ApprovalState::Pending
    );
}

#[tokio::test]
async fn expired_and_changed_binding_records_are_conflicts_without_a_decision() {
    let expired = ApiFixture::with_approval_ttl(Duration::milliseconds(100));
    let expired_nonce = reviewer_nonce(&expired.app).await;
    let expired_id = expired.seeded.active_approval.approval_id;
    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(
        expired.seeded.store.approval(expired_id).unwrap().state,
        ApprovalState::Pending
    );
    let event_count_before = expired
        .seeded
        .store
        .story_evidence(expired.seeded.active_story.story_id)
        .unwrap()
        .events
        .len();
    let response = send(
        &expired.app,
        decision_request(
            expired_id,
            decision_body("approve", "reviewer", "expired approval"),
            Some(REVIEWER_ORIGIN),
            Some(&expired_nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        expired.seeded.store.approval(expired_id).unwrap().state,
        ApprovalState::Pending
    );
    assert_eq!(
        expired
            .seeded
            .store
            .story_evidence(expired.seeded.active_story.story_id)
            .unwrap()
            .events
            .len(),
        event_count_before
    );

    let changed = ApiFixture::new();
    let changed_nonce = reviewer_nonce(&changed.app).await;
    let changed_id = changed.seeded.active_approval.approval_id;
    let changed_hash = Sha256Digest::from_bytes(b"changed reviewer binding")
        .as_str()
        .to_owned();
    let connection = rusqlite::Connection::open(changed.seeded.database_path()).unwrap();
    connection
        .execute(
            "UPDATE approvals SET binding_hash = ?1 WHERE approval_id = ?2",
            rusqlite::params![changed_hash, changed_id.to_string()],
        )
        .unwrap();
    let response = send(
        &changed.app,
        decision_request(
            changed_id,
            decision_body("deny", "reviewer", "changed binding"),
            Some(REVIEWER_ORIGIN),
            Some(&changed_nonce),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let (state, version): (String, i64) = connection
        .query_row(
            "SELECT state, version FROM approvals WHERE approval_id = ?1",
            rusqlite::params![changed_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "pending");
    assert_eq!(version, 0);
}
