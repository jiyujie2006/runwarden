mod common;

use common::{McpFixture, call, payload};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::operation::OperationState;
use runwarden_providers::demo_tools::mailbox_view_for_test;
use serde_json::json;

#[test]
fn approval_resume_and_status_complete_one_email_operation() {
    let fixture = McpFixture::new();
    let pending = call(
        &fixture.server,
        50,
        "runwarden.provider.call",
        json!({
            "provider": "external.email.send",
            "to": ["judge@example.test"],
            "subject": "reviewed",
            "body": "bounded body"
        }),
    );
    let operation_id = serde_json::from_value(payload(&pending)["operation_id"].clone()).unwrap();
    fixture.approve(operation_id);

    let resumed = call(
        &fixture.server,
        51,
        "runwarden.operation.resume",
        json!({"operation_id": operation_id}),
    );
    assert_eq!(resumed["result"]["isError"], false);
    assert_eq!(payload(&resumed)["disposition"], "completed");
    assert_eq!(payload(&resumed)["operation_id"], operation_id.to_string());

    let status = call(
        &fixture.server,
        52,
        "runwarden.operation.status",
        json!({"operation_id": operation_id}),
    );
    assert_eq!(payload(&status)["disposition"], "completed");
    let terminal_resume = call(
        &fixture.server,
        53,
        "runwarden.operation.resume",
        json!({"operation_id": operation_id}),
    );
    assert_eq!(payload(&terminal_resume)["disposition"], "completed");

    let approval = fixture
        .store
        .approval_for_operation(operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(approval.state, ApprovalState::Consumed);
    assert_eq!(
        fixture.store.operation(operation_id).unwrap().state,
        OperationState::Completed
    );
    assert_eq!(
        mailbox_view_for_test(&fixture.sandbox_root)
            .unwrap()
            .lines()
            .count(),
        1
    );
}
