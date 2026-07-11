mod common;

use common::{
    FixedClock, INSTANCE_TOKEN, RecordingExecutor, RuntimeFixture, email_request,
    persist_story_with_session, token_hash,
};
use runwarden_kernel::story::EnforcementMode;
use runwarden_providers::executor::PermitAuthority;
use runwarden_runtime::{
    ApprovalWaitPolicy, OperationRuntime, RuntimeApi, RuntimeContextLoader, RuntimeDisposition,
    RuntimeError,
};
use runwarden_state::{DemoActivation, JournalError, StateStore};
use serde_json::json;
use time::{Duration, OffsetDateTime};

#[test]
fn active_context_requires_the_exact_token_and_an_unexpired_session() {
    let fixture = RuntimeFixture::new();

    RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now)
        .expect("the trusted token must load the active context");

    let wrong_token = RuntimeContextLoader::load(
        &fixture.store,
        "agent-controlled-replacement-token",
        fixture.now,
    )
    .expect_err("a different raw token must not select the active instance");
    assert!(matches!(wrong_token, RuntimeError::ContextUnavailable(_)));

    let expired = RuntimeContextLoader::load(
        &fixture.store,
        INSTANCE_TOKEN,
        fixture.story.authority.expires_at,
    )
    .expect_err("context must expire at the authority deadline");
    assert!(matches!(expired, RuntimeError::ContextUnavailable(_)));
}

#[test]
fn story_session_authority_mismatch_never_becomes_an_active_context() {
    let temp = tempfile::tempdir().expect("create context mismatch test directory");
    let store = StateStore::open(temp.path().join("state")).expect("open state journal");
    let now = OffsetDateTime::now_utc() + Duration::seconds(10);
    let story_a = persist_story_with_session(&store, "story-a", now + Duration::hours(1));
    let story_b = persist_story_with_session(&store, "story-b", now + Duration::hours(1));

    let mismatch = store
        .activate_demo(&DemoActivation {
            instance_id: "mismatched-runtime".to_owned(),
            story_id: story_a.story_id,
            session_id: story_b.authority.session_id,
            process_id: std::process::id(),
            host_id: "runtime-test-host".to_owned(),
            instance_token_hash: token_hash(INSTANCE_TOKEN),
            now,
        })
        .expect_err("an instance cannot mix one story with another session/authority");
    assert!(matches!(mismatch, JournalError::Integrity(_)));

    let load = RuntimeContextLoader::load(&store, INSTANCE_TOKEN, now)
        .expect_err("the rejected mismatch must not leave an active context");
    assert!(matches!(load, RuntimeError::ContextUnavailable(_)));
}

#[test]
fn provider_arguments_cannot_replace_server_owned_context() {
    let fixture = RuntimeFixture::new();
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now)
        .expect("load trusted active context");
    let (permit_issuer, permit_verifier) =
        PermitAuthority::generate().expect("create one process-local permit authority");
    let executor = RecordingExecutor::new(permit_verifier);
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        fixture.store.clone(),
        executor,
        FixedClock::new(fixture.now),
        context,
        permit_issuer,
        "runtime-test-lease-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .expect("construct runtime from trusted dependencies");

    let replacement_fields = [
        ("story_id", json!(runwarden_kernel::story::StoryId::new())),
        (
            "session_id",
            json!(runwarden_kernel::story::SessionId::new()),
        ),
        ("authority", json!({"authz_state": "agent-approved"})),
        ("authz_id", json!("agent-authz")),
        ("instance_token", json!("agent-token")),
        ("policy_snapshot_hash", json!(token_hash("agent-policy"))),
    ];

    for (index, (field, value)) in replacement_fields.into_iter().enumerate() {
        let mut request = email_request(index as u8 + 10);
        request
            .arguments
            .as_object_mut()
            .expect("email arguments are an object")
            .insert(field.to_owned(), value);

        let error = RuntimeApi::invoke(&runtime, request)
            .expect_err("reserved context fields must be rejected as provider arguments");
        assert!(
            matches!(error, RuntimeError::ResourceInvalid(_)),
            "field {field} returned {error:?}"
        );
        assert_eq!(
            executor_probe.call_count(),
            0,
            "field {field} reached the executor"
        );
    }

    let clean_request = email_request(99);
    let expected_private_arguments = clean_request.arguments.clone();
    let response = RuntimeApi::invoke(&runtime, clean_request)
        .expect("a clean request should create one durable review operation");
    assert!(matches!(
        response.disposition,
        RuntimeDisposition::AwaitingApproval
    ));
    assert_eq!(executor_probe.call_count(), 0);

    let stored = fixture
        .store
        .operation(response.operation_id)
        .expect("load the durable operation");
    assert_eq!(stored.story_id, fixture.story.story_id);
    assert_eq!(stored.session_id, fixture.story.authority.session_id);
    assert_eq!(
        stored.policy_snapshot_hash.as_str(),
        fixture.story.authority.policy_snapshot_hash
    );
    let private_material = fixture
        .store
        .load_private_operation_material(response.operation_id)
        .expect("load frozen private provider arguments");
    assert_eq!(private_material.arguments, expected_private_arguments);
}

#[test]
fn monitor_only_policy_results_never_masquerade_as_approved() {
    let fixture = RuntimeFixture::new_with_mode(EnforcementMode::MonitorOnly);
    let context = RuntimeContextLoader::load(&fixture.store, INSTANCE_TOKEN, fixture.now)
        .expect("load monitor-only context");
    let (permit_issuer, permit_verifier) = PermitAuthority::generate().unwrap();
    let executor = RecordingExecutor::new(permit_verifier);
    let executor_probe = executor.clone();
    let runtime = OperationRuntime::new(
        fixture.store.clone(),
        executor,
        FixedClock::new(fixture.now),
        context,
        permit_issuer,
        "runtime-monitor-only-owner".to_owned(),
        ApprovalWaitPolicy::immediate(),
    )
    .unwrap();

    let review = RuntimeApi::invoke(&runtime, email_request(110)).unwrap();
    assert_eq!(
        review.operation_state,
        runwarden_kernel::operation::OperationState::PolicyEvaluated
    );
    assert_eq!(
        review.policy_decision,
        Some(runwarden_kernel::contracts::PolicyDecision::RequiresReview)
    );
    assert!(matches!(review.disposition, RuntimeDisposition::Proposed));
    assert!(
        fixture
            .store
            .approval_for_operation(review.operation_id)
            .unwrap()
            .is_none()
    );

    let mut denied_request = email_request(111);
    denied_request.arguments["to"] = json!(["outside-authority@example.test"]);
    let denied = RuntimeApi::invoke(&runtime, denied_request).unwrap();
    assert_eq!(
        denied.operation_state,
        runwarden_kernel::operation::OperationState::PolicyEvaluated
    );
    assert_eq!(
        denied.policy_decision,
        Some(runwarden_kernel::contracts::PolicyDecision::Denied)
    );
    assert!(matches!(denied.disposition, RuntimeDisposition::Denied));
    assert_eq!(executor_probe.call_count(), 0);
}
