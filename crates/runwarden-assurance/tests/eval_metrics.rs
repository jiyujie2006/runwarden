use runwarden_assurance::eval::{EvalThresholds, evaluate_report_assurance};
use runwarden_assurance::report::{ReportClaim, ReportDraft};
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
fn eval_passes_when_report_cites_all_expected_trace_events() {
    let trace_events = vec![trace("obs_1"), trace("obs_2")];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Policy denied raw shell", ["obs_1"]),
        ReportClaim::new("finding-2", "Trace verified", ["obs_2"]),
    ]);

    let eval = evaluate_report_assurance(
        &report,
        &trace_events,
        ["obs_1", "obs_2"],
        EvalThresholds::strict(),
    );

    assert!(eval.passed);
    assert_eq!(eval.metrics.trace_completeness, 1.0);
    assert_eq!(eval.metrics.report_citation_accuracy, 1.0);
}

#[test]
fn eval_fails_when_expected_obs_ref_is_missing_from_report() {
    let trace_events = vec![trace("obs_1"), trace("obs_2")];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Policy denied raw shell",
        ["obs_1"],
    )]);

    let eval = evaluate_report_assurance(
        &report,
        &trace_events,
        ["obs_1", "obs_2"],
        EvalThresholds::strict(),
    );

    assert!(!eval.passed);
    assert_eq!(eval.metrics.trace_completeness, 0.5);
    assert!(
        eval.failures
            .iter()
            .any(|failure| failure == "trace_completeness")
    );
}
