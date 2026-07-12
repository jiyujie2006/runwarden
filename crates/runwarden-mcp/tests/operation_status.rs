mod common;

use common::{McpFixture, call, payload};
use serde_json::json;

#[test]
fn status_returns_only_the_same_display_safe_operation() {
    let fixture = McpFixture::new();
    let pending = call(
        &fixture.server,
        30,
        "runwarden.provider.call",
        json!({
            "provider": "external.email.send",
            "to": ["judge@example.test"],
            "subject": "private subject",
            "body": "private body marker"
        }),
    );
    let operation_id = payload(&pending)["operation_id"].clone();
    let status = call(
        &fixture.server,
        31,
        "runwarden.operation.status",
        json!({"operation_id": operation_id}),
    );
    assert_eq!(status["result"]["isError"], true);
    assert_eq!(payload(&status)["disposition"], "awaiting_approval");
    assert_eq!(
        payload(&status)["operation_id"],
        payload(&pending)["operation_id"]
    );
    let serialized = serde_json::to_string(&status).unwrap();
    assert!(!serialized.contains("private body marker"));
    assert!(!serialized.contains("private subject"));
    assert!(payload(&status).get("operation_version").is_some());
    assert!(payload(&status).get("side_effect_state").is_some());
    assert!(payload(&status).get("observation_refs").is_some());
}

#[test]
fn status_and_resume_reject_every_replacement_field() {
    let fixture = McpFixture::new();
    for tool in ["runwarden.operation.status", "runwarden.operation.resume"] {
        for forbidden in [
            "provider",
            "arguments",
            "approval_id",
            "session_id",
            "root",
            "env",
            "cwd",
            "url",
            "transport",
        ] {
            let mut arguments = json!({"operation_id": "op_invalid"});
            arguments
                .as_object_mut()
                .unwrap()
                .insert(forbidden.to_owned(), json!("replacement"));
            let response = call(&fixture.server, 40, tool, arguments);
            assert_eq!(
                response["error"]["code"], -32602,
                "{tool} accepted {forbidden}"
            );
        }
    }
}
