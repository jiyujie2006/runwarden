use runwarden_runtime::{RuntimeDisposition, RuntimeResponse};
use serde_json::Value;

pub(crate) fn response_payload(response: RuntimeResponse) -> Value {
    serde_json::to_value(response).expect("display-safe runtime response serializes")
}

pub(crate) fn response_is_error(payload: &Value) -> bool {
    matches!(
        payload.get("disposition").and_then(Value::as_str),
        Some(
            "proposed" | "denied" | "awaiting_approval" | "failed" | "expired" | "outcome_unknown"
        )
    )
}

#[allow(dead_code)]
fn _assert_disposition_is_exhaustive(disposition: RuntimeDisposition) -> bool {
    matches!(
        disposition,
        RuntimeDisposition::Proposed
            | RuntimeDisposition::Denied
            | RuntimeDisposition::AwaitingApproval
            | RuntimeDisposition::Approved
            | RuntimeDisposition::Executing
            | RuntimeDisposition::Completed
            | RuntimeDisposition::Failed
            | RuntimeDisposition::Expired
            | RuntimeDisposition::OutcomeUnknown
    )
}
