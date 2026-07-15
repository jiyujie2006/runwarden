use runwarden_assurance::eval::{EvalThresholds, evaluate_report_assurance};
use runwarden_assurance::report::{ReportClaim, ReportClaimSupport, ReportDraft};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent};
use serde_json::json;

fn trace_events(obs_ids: &[&str]) -> Vec<TraceEvent> {
    let mut store = InMemoryTraceStore::default();
    for obs_id in obs_ids {
        store.append_signed(
            (*obs_id).to_string(),
            "provider_completed",
            Some("runwarden.input.inspect"),
            json!({
                "ok": true,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false
            }),
        );
    }
    store.events_mut_for_test().to_vec()
}

fn completed_claim(id: &str, text: &str, obs_ref: &str) -> ReportClaim {
    ReportClaim::new(id, text, [obs_ref]).with_support(ReportClaimSupport {
        provider: Some("runwarden.input.inspect".to_string()),
        event_type: Some("provider_completed".to_string()),
        decision: Some("allowed".to_string()),
        execution_status: Some("completed".to_string()),
        side_effect_executed: Some(false),
        simulated: None,
    })
}

#[test]
fn eval_passes_when_report_cites_all_expected_trace_events() {
    let trace_events = trace_events(&["obs_1", "obs_2"]);
    let report = ReportDraft::new(vec![
        completed_claim("finding-1", "Evidence inspection completed", "obs_1"),
        completed_claim("finding-2", "Trace verification completed", "obs_2"),
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
    let trace_events = trace_events(&["obs_1", "obs_2"]);
    let report = ReportDraft::new(vec![completed_claim(
        "finding-1",
        "Evidence inspection completed",
        "obs_1",
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

#[test]
fn eval_rejects_empty_evidence_instead_of_awarding_perfect_ratios() {
    let report = ReportDraft::new(Vec::new());
    let eval = evaluate_report_assurance(
        &report,
        Vec::<TraceEvent>::new().as_slice(),
        Vec::<String>::new(),
        EvalThresholds::strict(),
    );

    assert!(!eval.passed);
    assert_eq!(eval.metrics.trace_completeness, 0.0);
    assert_eq!(eval.metrics.report_citation_accuracy, 0.0);
    assert!(
        eval.failures
            .contains(&"expected_obs_refs_empty".to_string())
    );
    assert!(eval.failures.contains(&"trace_events_empty".to_string()));
    assert!(eval.failures.contains(&"report_claims_empty".to_string()));
}
