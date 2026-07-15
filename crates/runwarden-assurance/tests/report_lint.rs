use runwarden_assurance::report::{
    ReportClaim, ReportClaimSupport, ReportDraft, ReportLintErrorKind, lint_report_against_trace,
};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent};
use serde_json::json;

fn trace(obs_id: &str) -> TraceEvent {
    TraceEvent::sealed(
        obs_id.to_string(),
        "provider_completed".to_string(),
        Some("runwarden.input.inspect".to_string()),
        json!({
            "ok": true,
            "decision": "allowed",
            "execution_status": "completed",
            "side_effect_executed": false
        }),
        None,
    )
}

fn trace_with_payload(
    obs_id: &str,
    event_type: &str,
    provider: &str,
    payload: serde_json::Value,
) -> TraceEvent {
    TraceEvent::sealed(
        obs_id.to_string(),
        event_type.to_string(),
        Some(provider.to_string()),
        payload,
        None,
    )
}

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

fn support(
    provider: &str,
    event_type: &str,
    decision: &str,
    execution_status: &str,
    side_effect_executed: bool,
) -> ReportClaimSupport {
    ReportClaimSupport {
        provider: Some(provider.to_string()),
        event_type: Some(event_type.to_string()),
        decision: Some(decision.to_string()),
        execution_status: Some(execution_status.to_string()),
        side_effect_executed: Some(side_effect_executed),
        simulated: None,
    }
}

fn completed_support() -> ReportClaimSupport {
    support(
        "runwarden.input.inspect",
        "provider_completed",
        "allowed",
        "completed",
        false,
    )
}

#[test]
fn report_lint_accepts_claims_with_known_obs_refs() {
    let trace_events = trace_events(&["obs_1", "obs_2"]);
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Evidence inspection completed", ["obs_1"])
            .with_support(completed_support()),
        ReportClaim::new("finding-2", "Trace verification completed", ["obs_2"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok);
    assert!(result.errors.is_empty());
}

#[test]
fn report_lint_rejects_claims_citing_unrelated_observations() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "Shell command was denied before execution",
            ["obs_1"],
        )
        .with_support(support(
            "external.raw.shell",
            "provider_denied",
            "denied",
            "not_executed",
            false,
        )),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnsupportedObservation
    );
    assert_eq!(result.errors[0].claim_id, "finding-1");
    assert_eq!(result.errors[0].obs_ref.as_deref(), Some("obs_1"));
}

#[test]
fn report_lint_rejects_neutral_claim_without_structured_support() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Provider behavior was reviewed",
        ["obs_1"],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
    assert_eq!(result.errors[0].claim_id, "finding-1");
    assert_eq!(result.errors[0].obs_ref, None);
}

#[test]
fn report_lint_ignores_negated_denial_words_and_uses_typed_predicate() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "Provider call completed and was not denied",
            ["obs_1"],
        )
        .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok, "{result:#?}");
    assert!(result.errors.is_empty());
}

#[test]
fn report_lint_accepts_allowed_claim_with_allowed_decision() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_completed",
        "runwarden.input.inspect",
        json!({
            "decision": "allowed",
            "execution_status": "completed",
            "side_effect_executed": false
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Provider call was allowed", ["obs_1"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok, "{result:#?}");
    assert!(result.errors.is_empty());
}

#[test]
fn report_lint_rejects_completed_claim_when_event_only_says_policy_allowed() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_policy_evaluated",
        "runwarden.input.inspect",
        json!({"decision": "allowed", "execution_status": "not_executed"}),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Provider call completed", ["obs_1"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnsupportedObservation
    );
}

#[test]
fn report_lint_rejects_completed_claim_when_completed_event_payload_failed() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_completed",
        "runwarden.input.inspect",
        json!({"decision": "allowed", "execution_status": "failed"}),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Provider call completed", ["obs_1"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnsupportedObservation
    );
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
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Shell was denied", ["obs_missing"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnknownObservation
    );
    assert_eq!(result.errors[0].obs_ref.as_deref(), Some("obs_missing"));
}

#[test]
fn report_lint_rejects_known_refs_without_obs_prefix() {
    let trace_events = vec![trace("trace_1")];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Provider call completed", ["trace_1"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok, "{result:#?}");
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnknownObservation
    );
    assert_eq!(result.errors[0].obs_ref.as_deref(), Some("trace_1"));
}

#[test]
fn report_lint_rejects_tampered_trace_before_trusting_citations() {
    let mut trace_events = trace_events(&["obs_1"]);
    trace_events[0].payload = json!({"ok": false});
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Shell was denied",
        ["obs_1"],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(result.errors[0].kind, ReportLintErrorKind::TraceTampered);
    assert_eq!(result.errors[0].obs_ref.as_deref(), Some("obs_1"));
}

#[test]
fn report_lint_accepts_structured_support_matching_trace_event_fields() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_requires_review",
        "external.mcp.browser.open_page",
        json!({
            "decision": "requires_review",
            "execution_status": "not_executed",
            "side_effect_executed": false
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "Browser navigation requires review before execution",
            ["obs_1"],
        )
        .with_support(ReportClaimSupport {
            provider: Some("external.mcp.browser.open_page".to_string()),
            event_type: Some("provider_requires_review".to_string()),
            decision: Some("requires_review".to_string()),
            execution_status: Some("not_executed".to_string()),
            side_effect_executed: Some(false),
            simulated: None,
        }),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok, "{result:#?}");
    assert!(result.errors.is_empty());
}

#[test]
fn report_lint_rejects_structured_support_citing_wrong_decision() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_completed",
        "external.mcp.browser.open_page",
        json!({
            "decision": "allowed",
            "execution_status": "completed",
            "side_effect_executed": true
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "Browser navigation requires review before execution",
            ["obs_1"],
        )
        .with_support(ReportClaimSupport {
            provider: Some("external.mcp.browser.open_page".to_string()),
            event_type: Some("provider_requires_review".to_string()),
            decision: Some("requires_review".to_string()),
            execution_status: Some("not_executed".to_string()),
            side_effect_executed: Some(false),
            simulated: None,
        }),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnsupportedObservation
    );
}

#[test]
fn report_lint_rejects_structured_support_when_side_effect_state_differs() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_denied",
        "external.api.request",
        json!({
            "decision": "denied",
            "execution_status": "not_executed",
            "side_effect_executed": true
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "API request was denied before side effects",
            ["obs_1"],
        )
        .with_support(ReportClaimSupport {
            provider: Some("external.api.request".to_string()),
            event_type: Some("provider_denied".to_string()),
            decision: Some("denied".to_string()),
            execution_status: Some("not_executed".to_string()),
            side_effect_executed: Some(false),
            simulated: None,
        }),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::UnsupportedObservation
    );
}

#[test]
fn report_lint_rejects_unstructured_denied_claim_without_reading_prose() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_denied",
        "external.api.request",
        json!({
            "decision": "denied",
            "execution_status": "not_executed",
            "side_effect_executed": true
        }),
    )];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "API request was denied before side effects",
        ["obs_1"],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok, "{result:#?}");
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
    assert_eq!(result.errors[0].obs_ref, None);
}

#[test]
fn report_lint_rejects_false_security_claim_with_provider_only_support() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_denied",
        "external.api.request",
        json!({
            "decision": "denied",
            "execution_status": "not_executed",
            "side_effect_executed": true
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "All secrets are safe", ["obs_1"]).with_support(
            ReportClaimSupport {
                provider: Some("external.api.request".to_string()),
                event_type: None,
                decision: None,
                execution_status: None,
                side_effect_executed: None,
                simulated: None,
            },
        ),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok, "{result:#?}");
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
    assert_eq!(result.errors[0].obs_ref, None);
}

#[test]
fn report_parser_rejects_unknown_or_markup_bearing_predicate_fields() {
    let unknown = serde_json::from_value::<ReportDraft>(json!({
        "claims": [{
            "id": "finding-1",
            "text": "All secrets are safe",
            "obs_refs": ["obs_1"],
            "support": {
                "provider": "runwarden.input.inspect",
                "event_type": "provider_completed",
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "all_secrets_safe": true
            }
        }]
    }));
    assert!(
        unknown.is_err(),
        "unknown predicate fields must fail closed"
    );

    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Evidence inspection completed", ["obs_1"]).with_support(
            support(
                "runwarden.input.inspect`spoof",
                "provider_completed",
                "allowed",
                "completed",
                false,
            ),
        ),
    ]);
    let result = lint_report_against_trace(&report, &trace_events);
    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
}

#[test]
fn report_lint_rejects_invalid_typed_decision_value() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_completed",
        "external.api.request",
        json!({
            "decision": "completed",
            "execution_status": "completed",
            "side_effect_executed": true
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "API request completed and was blocked before side effects",
            ["obs_1"],
        )
        .with_support(support(
            "external.api.request",
            "provider_completed",
            "completed",
            "completed",
            true,
        )),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok, "{result:#?}");
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
    assert_eq!(result.errors[0].obs_ref, None);
}

#[test]
fn report_lint_rejects_inconsistent_event_type_and_decision_predicate() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_completed",
        "external.api.request",
        json!({
            "decision": "denied",
            "execution_status": "not_executed",
            "side_effect_executed": false
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "API request was denied", ["obs_1"]).with_support(support(
            "external.api.request",
            "provider_completed",
            "denied",
            "not_executed",
            false,
        )),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
}

#[test]
fn report_lint_rejects_unstructured_review_claim_even_when_words_match_event() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_requires_review",
        "external.mcp.browser.open_page",
        json!({
            "decision": "requires_review",
            "execution_status": "not_executed",
            "side_effect_executed": false
        }),
    )];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "Browser navigation was review-blocked before side effects",
        ["obs_1"],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok, "{result:#?}");
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
}

#[test]
fn report_lint_accepts_held_for_review_claim_with_structured_support() {
    let trace_events = vec![trace_with_payload(
        "obs_review",
        "provider_approval_pending",
        "external.api.request",
        json!({
            "decision": "requires_review",
            "execution_status": "not_executed",
            "side_effect_executed": false
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "The memory-to-API sequence was held for review with no side effect",
            ["obs_review"],
        )
        .with_support(ReportClaimSupport {
            provider: Some("external.api.request".to_string()),
            event_type: Some("provider_approval_pending".to_string()),
            decision: Some("requires_review".to_string()),
            execution_status: Some("not_executed".to_string()),
            side_effect_executed: Some(false),
            simulated: None,
        }),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok, "{result:#?}");
}

#[test]
fn report_lint_rejects_simulated_completed_claim_without_simulated_support() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_simulated_replay",
        "external.api.request",
        json!({
            "decision": "allowed",
            "execution_status": "simulated",
            "side_effect_executed": false,
            "simulated": true
        }),
    )];
    let report = ReportDraft::new(vec![ReportClaim::new(
        "finding-1",
        "External API request completed",
        ["obs_1"],
    )]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
}

#[test]
fn report_lint_rejects_structured_support_missing_simulated_expectation_for_simulated_event() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_simulated_replay",
        "external.api.request",
        json!({
            "decision": "allowed",
            "execution_status": "simulated",
            "side_effect_executed": false,
            "simulated": true
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "External API request was replayed without trusted side effects",
            ["obs_1"],
        )
        .with_support(ReportClaimSupport {
            provider: Some("external.api.request".to_string()),
            event_type: Some("provider_simulated_replay".to_string()),
            decision: Some("allowed".to_string()),
            execution_status: Some("simulated".to_string()),
            side_effect_executed: Some(false),
            simulated: None,
        }),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
}

#[test]
fn report_lint_accepts_simulated_replay_with_explicit_support() {
    let trace_events = vec![trace_with_payload(
        "obs_1",
        "provider_simulated_replay",
        "external.api.request",
        json!({
            "decision": "allowed",
            "execution_status": "simulated",
            "side_effect_executed": false,
            "simulated": true
        }),
    )];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "External API request was simulated without trusted side effects",
            ["obs_1"],
        )
        .with_support(ReportClaimSupport {
            provider: Some("external.api.request".to_string()),
            event_type: Some("provider_simulated_replay".to_string()),
            decision: Some("allowed".to_string()),
            execution_status: Some("simulated".to_string()),
            side_effect_executed: Some(false),
            simulated: Some(true),
        }),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(result.ok, "{result:#?}");
    assert!(result.errors.is_empty());
}

#[test]
fn report_lint_empty_structured_support_never_falls_back_to_text_semantics() {
    let trace_events = vec![trace("obs_1")];
    let report = ReportDraft::new(vec![
        ReportClaim::new(
            "finding-1",
            "Shell command was denied before execution",
            ["obs_1"],
        )
        .with_support(ReportClaimSupport::default()),
    ]);

    let result = lint_report_against_trace(&report, &trace_events);

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::IncompleteSupport
    );
}

#[test]
fn report_lint_rejects_empty_trace_and_empty_report() {
    let empty_report = ReportDraft::new(Vec::new());
    let result = lint_report_against_trace(&empty_report, &[]);

    assert!(!result.ok);
    assert!(
        result
            .errors
            .iter()
            .any(|error| error.kind == ReportLintErrorKind::EmptyTrace)
    );
    assert!(
        result
            .errors
            .iter()
            .any(|error| error.kind == ReportLintErrorKind::EmptyReport)
    );
}

#[test]
fn report_lint_rejects_duplicate_observation_ids_before_citation_lookup() {
    let mut store = InMemoryTraceStore::default();
    for _ in 0..2 {
        store.append_signed(
            "obs_duplicate",
            "provider_completed",
            Some("runwarden.input.inspect"),
            json!({
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false
            }),
        );
    }
    let report = ReportDraft::new(vec![
        ReportClaim::new("finding-1", "Evidence inspected", ["obs_duplicate"])
            .with_support(completed_support()),
    ]);

    let result = lint_report_against_trace(&report, store.events_mut_for_test());

    assert!(!result.ok);
    assert_eq!(
        result.errors[0].kind,
        ReportLintErrorKind::DuplicateObservation
    );
    assert_eq!(result.errors[0].obs_ref.as_deref(), Some("obs_duplicate"));
}
