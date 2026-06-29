use std::collections::BTreeSet;

use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent};
use serde::{Deserialize, Serialize};

pub const FAST_GATE_NAME: &str = "runwarden-fast-gate";

pub mod report {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReportDraft {
        pub claims: Vec<ReportClaim>,
    }

    impl ReportDraft {
        pub fn new(claims: Vec<ReportClaim>) -> Self {
            Self { claims }
        }

        pub fn cited_obs_refs(&self) -> BTreeSet<String> {
            self.claims
                .iter()
                .flat_map(|claim| claim.obs_refs.iter().cloned())
                .collect()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReportClaim {
        pub id: String,
        pub text: String,
        pub obs_refs: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub support: Option<ReportClaimSupport>,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReportClaimSupport {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub event_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decision: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub execution_status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub side_effect_executed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub simulated: Option<bool>,
    }

    impl ReportClaimSupport {
        fn has_expectations(&self) -> bool {
            self.provider.is_some()
                || self.event_type.is_some()
                || self.decision.is_some()
                || self.execution_status.is_some()
                || self.side_effect_executed.is_some()
                || self.simulated.is_some()
        }
    }

    impl ReportClaim {
        pub fn new<I, S>(id: impl Into<String>, text: impl Into<String>, obs_refs: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            Self {
                id: id.into(),
                text: text.into(),
                obs_refs: obs_refs.into_iter().map(Into::into).collect(),
                support: None,
            }
        }

        pub fn with_support(mut self, support: ReportClaimSupport) -> Self {
            self.support = Some(support);
            self
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ReportLintResult {
        pub ok: bool,
        pub errors: Vec<ReportLintError>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ReportLintError {
        pub kind: ReportLintErrorKind,
        pub claim_id: String,
        pub obs_ref: Option<String>,
        pub message: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub enum ReportLintErrorKind {
        UncitedClaim,
        UnknownObservation,
        UnsupportedObservation,
        TraceTampered,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RenderFormat {
        Markdown,
        Json,
        Html,
        Sarif,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct RenderedReport {
        pub extension: String,
        pub contents: String,
        pub side_effect_executed: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ReportRenderError {
        pub kind: ReportRenderErrorKind,
        pub message: String,
        pub side_effect_executed: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub enum ReportRenderErrorKind {
        CitationInvalid,
        SerializationFailed,
    }

    pub fn lint_report_against_trace(
        report: &ReportDraft,
        trace_events: &[TraceEvent],
    ) -> ReportLintResult {
        let mut errors = Vec::new();
        if let Err(err) = verify_trace_hash_chain(trace_events) {
            errors.push(ReportLintError {
                kind: ReportLintErrorKind::TraceTampered,
                claim_id: String::new(),
                obs_ref: Some(err.obs_id),
                message: format!("trace hash chain is invalid: {}", err.reason),
            });
            return ReportLintResult { ok: false, errors };
        }

        let known_obs_refs: BTreeSet<_> = trace_events
            .iter()
            .map(|event| event.obs_id.clone())
            .collect();
        let trace_by_obs: std::collections::BTreeMap<_, _> = trace_events
            .iter()
            .map(|event| (event.obs_id.as_str(), event))
            .collect();

        for claim in &report.claims {
            if claim.obs_refs.is_empty() {
                errors.push(ReportLintError {
                    kind: ReportLintErrorKind::UncitedClaim,
                    claim_id: claim.id.clone(),
                    obs_ref: None,
                    message: "report claim must cite at least one obs_* reference".to_string(),
                });
                continue;
            }

            for obs_ref in &claim.obs_refs {
                if !known_obs_refs.contains(obs_ref) {
                    errors.push(ReportLintError {
                        kind: ReportLintErrorKind::UnknownObservation,
                        claim_id: claim.id.clone(),
                        obs_ref: Some(obs_ref.clone()),
                        message: "report claim cites an unknown obs_* reference".to_string(),
                    });
                    continue;
                }
                if let Some(event) = trace_by_obs.get(obs_ref.as_str())
                    && !observation_supports_claim(claim, event)
                {
                    errors.push(ReportLintError {
                        kind: ReportLintErrorKind::UnsupportedObservation,
                        claim_id: claim.id.clone(),
                        obs_ref: Some(obs_ref.clone()),
                        message: "report claim cites an observation that does not support the claim semantics".to_string(),
                    });
                }
            }
        }

        ReportLintResult {
            ok: errors.is_empty(),
            errors,
        }
    }

    fn observation_supports_claim(claim: &ReportClaim, event: &TraceEvent) -> bool {
        if event_is_simulated(event)
            && claim.support.as_ref().and_then(|support| support.simulated) != Some(true)
        {
            return false;
        }

        if let Some(support) = &claim.support
            && support.has_expectations()
        {
            return observation_matches_structured_support(support, event);
        }

        let text = claim.text.to_ascii_lowercase();
        if text.contains("completed") || text.contains("allowed") {
            return event.event_type.contains("completed")
                || event
                    .payload
                    .get("decision")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|decision| matches!(decision, "allowed" | "completed"));
        }
        if text.contains("denied") || text.contains("blocked") || text.contains("rejected") {
            return event.event_type.contains("denied")
                || event.event_type.contains("blocked")
                || event.event_type.contains("rejected")
                || event
                    .payload
                    .get("decision")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|decision| matches!(decision, "denied" | "blocked" | "rejected"));
        }
        false
    }

    fn observation_matches_structured_support(
        support: &ReportClaimSupport,
        event: &TraceEvent,
    ) -> bool {
        if event_is_simulated(event) && support.simulated != Some(true) {
            return false;
        }

        string_field_matches(support.provider.as_deref(), event.provider.as_deref())
            && string_field_matches(
                support.event_type.as_deref(),
                Some(event.event_type.as_str()),
            )
            && string_field_matches(
                support.decision.as_deref(),
                payload_string(&event.payload, "decision"),
            )
            && string_field_matches(
                support.execution_status.as_deref(),
                payload_string(&event.payload, "execution_status"),
            )
            && bool_field_matches(
                support.side_effect_executed,
                payload_bool(&event.payload, "side_effect_executed"),
            )
            && bool_field_matches(support.simulated, Some(event_is_simulated(event)))
    }

    fn string_field_matches(expected: Option<&str>, actual: Option<&str>) -> bool {
        expected.is_none_or(|expected| actual == Some(expected))
    }

    fn bool_field_matches(expected: Option<bool>, actual: Option<bool>) -> bool {
        expected.is_none_or(|expected| actual == Some(expected))
    }

    fn payload_string<'a>(payload: &'a serde_json::Value, key: &str) -> Option<&'a str> {
        payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                payload
                    .get("envelope")
                    .and_then(|envelope| envelope.get(key))
                    .and_then(serde_json::Value::as_str)
            })
    }

    fn payload_bool(payload: &serde_json::Value, key: &str) -> Option<bool> {
        payload
            .get(key)
            .and_then(serde_json::Value::as_bool)
            .or_else(|| {
                payload
                    .get("envelope")
                    .and_then(|envelope| envelope.get(key))
                    .and_then(serde_json::Value::as_bool)
            })
    }

    fn event_is_simulated(event: &TraceEvent) -> bool {
        payload_bool(&event.payload, "simulated").unwrap_or(false)
    }

    fn verify_trace_hash_chain(
        trace_events: &[TraceEvent],
    ) -> Result<(), runwarden_kernel::evidence::TraceVerificationError> {
        let mut store = InMemoryTraceStore::default();
        for event in trace_events {
            store.append(event.clone());
        }
        store.verify_hash_chain()
    }

    pub fn scaffold_report_from_trace(trace_events: &[TraceEvent]) -> ReportDraft {
        let claims = trace_events
            .iter()
            .enumerate()
            .map(|(idx, event)| {
                ReportClaim::new(
                    format!("trace-observation-{}", idx + 1),
                    format!(
                        "{} observed for {}",
                        event.event_type,
                        event.provider.as_deref().unwrap_or("unknown provider")
                    ),
                    [event.obs_id.clone()],
                )
            })
            .collect();
        ReportDraft::new(claims)
    }

    pub fn render_report(
        report: &ReportDraft,
        trace_events: &[TraceEvent],
        format: RenderFormat,
    ) -> Result<RenderedReport, ReportRenderError> {
        let lint = lint_report_against_trace(report, trace_events);
        if !lint.ok {
            return Err(ReportRenderError {
                kind: ReportRenderErrorKind::CitationInvalid,
                message: "report render blocked by citation lint failure".to_string(),
                side_effect_executed: false,
            });
        }

        let (extension, contents) = match format {
            RenderFormat::Markdown => ("md", render_markdown(report)),
            RenderFormat::Json => (
                "json",
                serde_json::to_string_pretty(report).map_err(serialization_error)?,
            ),
            RenderFormat::Html => ("html", render_html(report)),
            RenderFormat::Sarif => (
                "sarif.json",
                render_sarif(report).map_err(serialization_error)?,
            ),
        };

        Ok(RenderedReport {
            extension: extension.to_string(),
            contents,
            side_effect_executed: false,
        })
    }

    fn render_markdown(report: &ReportDraft) -> String {
        let mut output = String::from("# Runwarden Report\n\n");
        for claim in &report.claims {
            output.push_str(&format!(
                "## {}\n\n{}\n\nObs refs: {}\n\n",
                claim.id,
                claim.text,
                claim.obs_refs.join(", ")
            ));
        }
        output
    }

    fn render_html(report: &ReportDraft) -> String {
        let mut output = String::from("<article><h1>Runwarden Report</h1>");
        for claim in &report.claims {
            output.push_str(&format!(
                "<section><h2>{}</h2><p>{}</p><p><code>{}</code></p></section>",
                html_escape(&claim.id),
                html_escape(&claim.text),
                html_escape(&claim.obs_refs.join(", "))
            ));
        }
        output.push_str("</article>");
        output
    }

    fn render_sarif(report: &ReportDraft) -> Result<String, serde_json::Error> {
        let results: Vec<_> = report
            .claims
            .iter()
            .map(|claim| {
                serde_json::json!({
                    "ruleId": claim.id,
                    "message": {
                        "text": claim.text
                    },
                    "properties": {
                        "obs_refs": claim.obs_refs
                    }
                })
            })
            .collect();

        serde_json::to_string(&serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Runwarden"
                        }
                    },
                    "results": results
                }
            ]
        }))
    }

    fn serialization_error(error: serde_json::Error) -> ReportRenderError {
        ReportRenderError {
            kind: ReportRenderErrorKind::SerializationFailed,
            message: error.to_string(),
            side_effect_executed: false,
        }
    }

    fn html_escape(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

pub mod eval {
    use super::report::{ReportDraft, lint_report_against_trace};
    use super::*;
    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct EvalThresholds {
        pub min_trace_completeness: f64,
        pub min_report_citation_accuracy: f64,
    }

    impl EvalThresholds {
        pub fn strict() -> Self {
            Self {
                min_trace_completeness: 1.0,
                min_report_citation_accuracy: 1.0,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct EvalMetrics {
        pub trace_completeness: f64,
        pub report_citation_accuracy: f64,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct EvalReport {
        pub passed: bool,
        pub metrics: EvalMetrics,
        pub failures: Vec<String>,
        pub side_effect_executed: bool,
    }
    pub fn evaluate_report_assurance<I, S>(
        report: &ReportDraft,
        trace_events: &[TraceEvent],
        expected_obs_refs: I,
        thresholds: EvalThresholds,
    ) -> EvalReport
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let expected_obs_refs: BTreeSet<String> =
            expected_obs_refs.into_iter().map(Into::into).collect();
        let cited_obs_refs = report.cited_obs_refs();
        let known_obs_refs: BTreeSet<_> = trace_events
            .iter()
            .map(|event| event.obs_id.clone())
            .collect();

        let trace_completeness = ratio(
            expected_obs_refs
                .iter()
                .filter(|obs_ref| cited_obs_refs.contains(*obs_ref))
                .count(),
            expected_obs_refs.len(),
        );

        let valid_claims = report
            .claims
            .iter()
            .filter(|claim| {
                !claim.obs_refs.is_empty()
                    && claim
                        .obs_refs
                        .iter()
                        .all(|obs_ref| known_obs_refs.contains(obs_ref))
            })
            .count();
        let report_citation_accuracy = ratio(valid_claims, report.claims.len());

        let lint = lint_report_against_trace(report, trace_events);
        let mut failures = Vec::new();
        if !lint.ok {
            failures.push("report_lint".to_string());
        }
        if trace_completeness < thresholds.min_trace_completeness {
            failures.push("trace_completeness".to_string());
        }
        if report_citation_accuracy < thresholds.min_report_citation_accuracy {
            failures.push("report_citation_accuracy".to_string());
        }

        EvalReport {
            passed: failures.is_empty(),
            metrics: EvalMetrics {
                trace_completeness,
                report_citation_accuracy,
            },
            failures,
            side_effect_executed: false,
        }
    }
    fn ratio(numerator: usize, denominator: usize) -> f64 {
        if denominator == 0 {
            1.0
        } else {
            numerator as f64 / denominator as f64
        }
    }
}
