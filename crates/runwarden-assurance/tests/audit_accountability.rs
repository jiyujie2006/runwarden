use runwarden_assurance::accountability::accountability_summary;
use runwarden_assurance::audit::audit_summary;
use runwarden_kernel::evidence::TraceEvent;
use serde_json::json;

fn trace_events() -> Vec<TraceEvent> {
    vec![
        TraceEvent::sealed(
            "obs_1".to_string(),
            "provider_denied".to_string(),
            Some("external.shell.command".to_string()),
            json!({
                "decision": "denied",
                "actor_id": "agent-1",
                "authz_id": "authz-1",
                "approval_id": "approval-1",
                "reviewer": "reviewer-alice",
                "report_claim_id": "finding-1"
            }),
            None,
        ),
        TraceEvent::sealed(
            "obs_2".to_string(),
            "provider_completed".to_string(),
            Some("runwarden.report.render".to_string()),
            json!({
                "decision": "allowed",
                "actor_id": "agent-1",
                "authz_id": "authz-1",
                "report_claim_id": "finding-1"
            }),
            Some("obs_1_hash".to_string()),
        ),
    ]
}

#[test]
fn audit_summary_counts_decisions_and_provider_events() {
    let summary = audit_summary(&trace_events());

    assert_eq!(summary.total_events, 2);
    assert_eq!(summary.denied_count, 1);
    assert_eq!(summary.completed_count, 1);
    assert!(!summary.side_effect_executed);
    assert_eq!(
        summary
            .providers
            .get("external.shell.command")
            .expect("shell provider")
            .denied,
        1
    );
}

#[test]
fn accountability_summary_links_reviewer_authz_provider_obs_and_claim() {
    let summary = accountability_summary(&trace_events());

    assert_eq!(summary.chains.len(), 2);
    let first = &summary.chains[0];
    assert_eq!(first.obs_id, "obs_1");
    assert_eq!(first.provider.as_deref(), Some("external.shell.command"));
    assert_eq!(first.actor_id.as_deref(), Some("agent-1"));
    assert_eq!(first.authz_id.as_deref(), Some("authz-1"));
    assert_eq!(first.approval_id.as_deref(), Some("approval-1"));
    assert_eq!(first.reviewer.as_deref(), Some("reviewer-alice"));
    assert_eq!(first.report_claim_id.as_deref(), Some("finding-1"));
    assert!(!summary.side_effect_executed);
}
