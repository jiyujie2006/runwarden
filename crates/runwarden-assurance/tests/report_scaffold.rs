use runwarden_assurance::report::scaffold_report_from_trace;
use runwarden_kernel::evidence::TraceEvent;
use serde_json::json;

fn trace(obs_id: &str, event_type: &str) -> TraceEvent {
    TraceEvent::sealed(
        obs_id.to_string(),
        event_type.to_string(),
        Some("runwarden.input.inspect".to_string()),
        json!({
            "ok": true,
            "decision": "allowed",
            "execution_status": if event_type == "provider_completed" { "completed" } else { "not_executed" },
            "side_effect_executed": false
        }),
        None,
    )
}

#[test]
fn report_scaffold_cites_every_generated_claim_to_trace_observation() {
    let report = scaffold_report_from_trace(&[
        trace("obs_1", "provider_policy_evaluated"),
        trace("obs_2", "provider_completed"),
    ]);

    assert_eq!(report.claims.len(), 2);
    assert_eq!(report.claims[0].obs_refs, vec!["obs_1"]);
    assert_eq!(report.claims[1].obs_refs, vec!["obs_2"]);
    assert!(report.claims[0].text.contains("provider_policy_evaluated"));
    assert!(report.claims.iter().all(|claim| claim.support.is_some()));
}

#[test]
fn report_scaffold_does_not_invent_findings_for_empty_trace() {
    let report = scaffold_report_from_trace(&[]);

    assert!(report.claims.is_empty());
}
