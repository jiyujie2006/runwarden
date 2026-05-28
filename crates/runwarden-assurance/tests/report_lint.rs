use runwarden_assurance::report::{
    ReportClaim, ReportDraft, ReportLintErrorKind, lint_report_against_trace,
};
use runwarden_kernel::evidence::TraceEvent;
use serde_json::json;

fn trace(obs_id: &str) -> TraceEvent {
    TraceEvent::sealed(
        obs_id.to_string(),
        "provider_completed".to_string(),
        Some("runwarden.evidence.inspect".to_string()),
        json!({"ok": true}),
        None,
    )
}

#[test]
fn report_lint_accepts_claims_with_known_obs_refs() {
    let trace_events = vec![trace("obs_1"), trace("obs_2")];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Shell was denied", ["obs_1"]),
        ReportClaim::new("finding-2", "Trace verified", ["obs_2"]),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok);
    assert!(result.errors.is_empty());
}

#[test]
fn report_lint_rejects_uncited_claim() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Shell was denied",
        [] as [&str; 0],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(result.errors[0].kind, ReportLintErrorKind::UncitedClaim);
    assert_eq!(result.errors[0].claim_id, "finding-1");
}

#[test]
fn report_lint_rejects_unknown_obs_ref() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Shell was denied",
        ["obs_missing"],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnknownObservation
    );
    assert_eq!(result.errors[0].obs_ref.as_deref(), Some("obs_missing"));
}
