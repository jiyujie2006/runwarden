use runwarden_assurance::report::{
    RenderFormat, ReportClaim, ReportDraft, ReportRenderErrorKind, render_report,
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
fn report_render_outputs_markdown_json_html_and_sarif_for_cited_claims() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Shell access was denied",
        ["obs_1"],
    )]);

    let markdown =
        render_report(&report, &trace_events, RenderFormat::Markdown).expect("markdown render");
    let json = render_report(&report, &trace_events, RenderFormat::Json).expect("json render");
    let html = render_report(&report, &trace_events, RenderFormat::Html).expect("html render");
    let sarif = render_report(&report, &trace_events, RenderFormat::Sarif).expect("sarif render");

    assert_eq!(markdown.extension, "md");
    assert!(markdown.contents.contains("Shell access was denied"));
    assert!(markdown.contents.contains("obs_1"));
    assert_eq!(json.extension, "json");
    assert!(json.contents.contains("\"finding-1\""));
    assert_eq!(html.extension, "html");
    assert!(html.contents.contains("&lt;") || html.contents.contains("<article"));
    assert_eq!(sarif.extension, "sarif.json");
    assert!(sarif.contents.contains("\"version\":\"2.1.0\""));
}

#[test]
fn report_render_rejects_uncited_claims_before_artifact_write() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Shell access was denied",
        [] as [&str; 0],
    )]);

    let error = render_report(&report, &trace_events, RenderFormat::Markdown)
        .expect_err("uncited claims fail render");

    assert_eq!(error.kind, ReportRenderErrorKind::CitationInvalid);
    assert!(!error.side_effect_executed);
}
