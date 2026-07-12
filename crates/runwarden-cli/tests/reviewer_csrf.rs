mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use common::{
    ApiFixture, REVIEWER_ORIGIN, decision_request, get_request, json_body, reviewer_nonce, send,
};
use runwarden_cli::web_server::REVIEWER_NONCE_HEADER;
use runwarden_kernel::authority::ApprovalState;
use serde_json::json;

fn assert_no_cors_headers(headers: &axum::http::HeaderMap) {
    for name in [
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::ACCESS_CONTROL_ALLOW_METHODS,
    ] {
        assert!(
            headers.get(&name).is_none(),
            "unexpected CORS header {name}"
        );
    }
}

fn valid_decision_body() -> serde_json::Value {
    json!({
        "decision": "approve",
        "reviewer": "reviewer-csrf",
        "reason": "approved after exact-origin nonce validation",
        "expected_approval_version": 0,
        "expected_operation_version": 1,
    })
}

#[tokio::test]
async fn bootstrap_nonce_is_32_url_safe_bytes_and_never_cacheable() {
    let fixture = ApiFixture::new();
    let response = send(&fixture.app, get_request("/api/bootstrap")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, no-cache, must-revalidate, private"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(response.headers().get(header::EXPIRES).unwrap(), "0");
    assert_no_cors_headers(response.headers());

    let body = json_body(response).await;
    let nonce = body["reviewer_nonce"].as_str().unwrap();
    assert!(!nonce.is_empty());
    assert!(
        nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
    );
    let decoded = URL_SAFE_NO_PAD
        .decode(nonce)
        .or_else(|_| URL_SAFE.decode(nonce))
        .unwrap();
    assert_eq!(decoded.len(), 32);
}

#[tokio::test]
async fn missing_foreign_null_and_malformed_csrf_inputs_are_forbidden() {
    let fixture = ApiFixture::new();
    let nonce = reviewer_nonce(&fixture.app).await;
    let approval_id = fixture.seeded.active_approval.approval_id;
    let wrong_nonce = URL_SAFE_NO_PAD.encode([0xA5; 32]);

    let cases = [
        (Some(REVIEWER_ORIGIN), None),
        (Some(REVIEWER_ORIGIN), Some("not-base64***")),
        (Some(REVIEWER_ORIGIN), Some("c2hvcnQ")),
        (Some(REVIEWER_ORIGIN), Some(wrong_nonce.as_str())),
        (None, Some(nonce.as_str())),
        (Some("https://attacker.example"), Some(nonce.as_str())),
        (Some("null"), Some(nonce.as_str())),
        (Some("http://localhost:18088"), Some(nonce.as_str())),
    ];
    for (origin, candidate_nonce) in cases {
        let response = send(
            &fixture.app,
            decision_request(approval_id, valid_decision_body(), origin, candidate_nonce),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_no_cors_headers(response.headers());
    }

    let approval = fixture.seeded.store.approval(approval_id).unwrap();
    assert_eq!(approval.state, ApprovalState::Pending);
    assert_eq!(approval.version, 0);
}

#[tokio::test]
async fn duplicate_headers_and_credentialed_cross_origin_requests_are_forbidden() {
    let fixture = ApiFixture::new();
    let nonce = reviewer_nonce(&fixture.app).await;
    let approval_id = fixture.seeded.active_approval.approval_id;

    let mut duplicate_origin = decision_request(
        approval_id,
        valid_decision_body(),
        Some(REVIEWER_ORIGIN),
        Some(&nonce),
    );
    duplicate_origin
        .headers_mut()
        .append(header::ORIGIN, REVIEWER_ORIGIN.parse().unwrap());
    let mut duplicate_nonce = decision_request(
        approval_id,
        valid_decision_body(),
        Some(REVIEWER_ORIGIN),
        Some(&nonce),
    );
    duplicate_nonce
        .headers_mut()
        .append(REVIEWER_NONCE_HEADER, nonce.parse().unwrap());
    let mut credentialed_cross_origin = decision_request(
        approval_id,
        valid_decision_body(),
        Some("https://attacker.example"),
        Some(&nonce),
    );
    credentialed_cross_origin
        .headers_mut()
        .insert(header::COOKIE, "session=foreign".parse().unwrap());

    for request in [duplicate_origin, duplicate_nonce, credentialed_cross_origin] {
        let response = send(&fixture.app, request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_no_cors_headers(response.headers());
    }
    assert_eq!(
        fixture.seeded.store.approval(approval_id).unwrap().state,
        ApprovalState::Pending
    );
}

#[tokio::test]
async fn cors_preflight_is_rejected_without_permissive_headers() {
    let fixture = ApiFixture::new();
    let approval_id = fixture.seeded.active_approval.approval_id;
    let request = Request::builder()
        .method("OPTIONS")
        .uri(format!("/api/approvals/{approval_id}/decision"))
        .header(header::ORIGIN, REVIEWER_ORIGIN)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            REVIEWER_NONCE_HEADER,
        )
        .body(Body::empty())
        .unwrap();

    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_no_cors_headers(response.headers());
    assert_eq!(
        fixture.seeded.store.approval(approval_id).unwrap().state,
        ApprovalState::Pending
    );
}

#[tokio::test]
async fn process_restart_invalidates_the_old_nonce_and_accepts_only_the_new_one() {
    let fixture = ApiFixture::new();
    let old_nonce = reviewer_nonce(&fixture.app).await;
    let restarted = fixture.restarted_router();
    let new_nonce = reviewer_nonce(&restarted).await;
    assert_ne!(old_nonce, new_nonce);

    let approval_id = fixture.seeded.active_approval.approval_id;
    let old_response = send(
        &restarted,
        decision_request(
            approval_id,
            valid_decision_body(),
            Some(REVIEWER_ORIGIN),
            Some(&old_nonce),
        ),
    )
    .await;
    assert_eq!(old_response.status(), StatusCode::FORBIDDEN);
    assert_no_cors_headers(old_response.headers());

    let accepted_response = send(
        &restarted,
        decision_request(
            approval_id,
            valid_decision_body(),
            Some(REVIEWER_ORIGIN),
            Some(&new_nonce),
        ),
    )
    .await;
    assert_eq!(accepted_response.status(), StatusCode::OK);
    assert_no_cors_headers(accepted_response.headers());
    assert_eq!(
        fixture.seeded.store.approval(approval_id).unwrap().state,
        ApprovalState::Approved
    );
}
