//! Explainable behavior-risk fusion for Runwarden-supervised tool calls.
//!
//! The anomaly monitor complements the rule-based kernel policy. It never
//! executes a tool or overrides an allow/deny/review decision; instead it
//! scores behavioral deviations and recommends a response to the caller.
//! Five independently explainable signals are fused into a bounded 0-100
//! score:
//!
//! - an unexpected provider sequence;
//! - egress to a host absent from the benign baseline;
//! - arguments larger than the provider baseline;
//! - movement from a sensitive source to an external sink; and
//! - a repeated burst of the same provider.
//!
//! The monitor is stateful per session. Its retained observations and the
//! history returned in each report are both bounded by the profile's history
//! window.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

/// Weight assigned to an unexpected provider transition.
pub const UNEXPECTED_SEQUENCE_WEIGHT: usize = 20;
/// Weight assigned to a previously unseen egress host.
pub const NOVEL_EGRESS_WEIGHT: usize = 25;
/// Weight assigned to arguments that exceed the provider baseline.
pub const OVERSIZED_ARGUMENTS_WEIGHT: usize = 20;
/// Weight assigned to a sensitive-source-to-external-sink flow.
pub const SENSITIVE_SOURCE_TO_SINK_WEIGHT: usize = 55;
/// Weight assigned to a repeated burst of one provider.
pub const REPEATED_BURST_WEIGHT: usize = 20;

/// Coarse risk band derived from the fused 0-100 score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Suggested handling for the anomaly report. Enforcement remains with the
/// Runwarden kernel and its server-owned policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    Allow,
    Monitor,
    RequireReview,
    Deny,
}

impl RecommendedAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Monitor => "monitor",
            Self::RequireReview => "require_review",
            Self::Deny => "deny",
        }
    }
}

/// Stable machine-readable identifier for an explainable anomaly signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySignalKind {
    UnexpectedSequence,
    NovelEgress,
    OversizedArguments,
    SensitiveSourceToSink,
    RepeatedBurst,
}

impl AnomalySignalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedSequence => "unexpected_sequence",
            Self::NovelEgress => "novel_egress",
            Self::OversizedArguments => "oversized_arguments",
            Self::SensitiveSourceToSink => "sensitive_source_to_sink",
            Self::RepeatedBurst => "repeated_burst",
        }
    }
}

/// One weighted and human-explainable contributor to the fused score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnomalySignal {
    pub kind: AnomalySignalKind,
    pub weight: usize,
    pub evidence: String,
}

/// A privacy-conscious history item retained by the behavior monitor. It
/// stores argument size rather than argument contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BehaviorObservation {
    pub provider: String,
    pub arg_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_host: Option<String>,
}

/// The result of analyzing one tool call against the benign baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnomalyReport {
    /// Fused and saturated risk score in the inclusive range `0..=100`.
    pub score: usize,
    /// True when at least one weighted signal was emitted.
    pub is_anomalous: bool,
    /// Backward-compatible human-readable explanations, one per signal.
    pub reasons: Vec<String>,
    pub risk_level: RiskLevel,
    pub recommended_action: RecommendedAction,
    pub signals: Vec<AnomalySignal>,
    /// Bounded recent history including the call described by this report.
    pub history: Vec<BehaviorObservation>,
}

impl Default for AnomalyReport {
    fn default() -> Self {
        Self {
            score: 0,
            is_anomalous: false,
            reasons: Vec::new(),
            risk_level: RiskLevel::None,
            recommended_action: RecommendedAction::Allow,
            signals: Vec::new(),
            history: Vec::new(),
        }
    }
}

/// Configurable thresholds for converting a non-zero score into a risk band.
/// Scores below `medium` are low risk. Invalid or out-of-order direct field
/// mutations are normalized when a report is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskThresholds {
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            medium: 25,
            high: 50,
            critical: 80,
        }
    }
}

impl RiskThresholds {
    fn normalized(self) -> Self {
        let medium = self.medium.clamp(1, 100);
        let high = self.high.clamp(medium, 100);
        let critical = self.critical.clamp(high, 100);
        Self {
            medium,
            high,
            critical,
        }
    }
}

/// A benign behavior baseline plus risk-fusion configuration.
#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    pub allowed_bigrams: BTreeSet<(String, String)>,
    pub max_arg_bytes: BTreeMap<String, usize>,
    pub allowed_egress_hosts: BTreeSet<String>,
    pub sensitive_sources: BTreeSet<String>,
    pub sensitive_sinks: BTreeSet<String>,
    /// Maximum observations retained by a monitor and returned in a report.
    pub history_window: usize,
    /// How many prior observations may connect a source to a sink. Zero
    /// disables the source-to-sink signal.
    pub source_to_sink_window: usize,
    /// Consecutive calls, including the current call, required for a burst.
    /// Zero disables burst detection; non-zero values are treated as at least
    /// two because a single call cannot be a repeated burst.
    pub repeated_burst_threshold: usize,
    pub risk_thresholds: RiskThresholds,
}

impl Default for BehaviorProfile {
    fn default() -> Self {
        Self {
            allowed_bigrams: BTreeSet::new(),
            max_arg_bytes: BTreeMap::new(),
            allowed_egress_hosts: BTreeSet::new(),
            sensitive_sources: BTreeSet::new(),
            sensitive_sinks: BTreeSet::new(),
            history_window: 16,
            source_to_sink_window: 4,
            repeated_burst_threshold: 4,
            risk_thresholds: RiskThresholds::default(),
        }
    }
}

impl BehaviorProfile {
    /// A benign baseline derived from the contest scenario flows
    /// (`inspect -> read/email/api/memory/browser`, `email -> api`).
    pub fn default_benign() -> Self {
        let after_inspect = [
            "external.mcp.filesystem.read_file",
            "external.mcp.filesystem.write_file",
            "external.email.send",
            "external.api.request",
            "external.memory.read",
            "external.memory.write",
            "external.knowledge.read",
            "external.knowledge.write",
            "external.mcp.browser.open_page",
        ];
        let mut profile = Self::default();
        for next in after_inspect {
            profile
                .allowed_bigrams
                .insert(("runwarden.input.inspect".to_string(), next.to_string()));
            profile.max_arg_bytes.insert(next.to_string(), 4096);
        }
        profile.allowed_bigrams.insert((
            "external.email.send".to_string(),
            "external.api.request".to_string(),
        ));
        profile
            .max_arg_bytes
            .insert("runwarden.input.inspect".to_string(), 4096);
        profile.allowed_egress_hosts = ["api.example.com", "mail.example.com"]
            .into_iter()
            .map(str::to_string)
            .collect();
        profile.sensitive_sources = [
            "external.mcp.filesystem.read_file",
            "external.memory.read",
            "external.knowledge.read",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        profile.sensitive_sinks = [
            "external.email.send",
            "external.api.request",
            "external.mcp.browser.open_page",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        profile
    }

    pub fn with_sensitive_source(mut self, provider: impl Into<String>) -> Self {
        self.sensitive_sources.insert(provider.into());
        self
    }

    pub fn with_sensitive_sink(mut self, provider: impl Into<String>) -> Self {
        self.sensitive_sinks.insert(provider.into());
        self
    }

    pub fn with_history_window(mut self, history_window: usize) -> Self {
        self.history_window = history_window.max(1);
        self
    }

    pub fn with_source_to_sink_window(mut self, source_to_sink_window: usize) -> Self {
        self.source_to_sink_window = source_to_sink_window;
        self
    }

    pub fn with_repeated_burst_threshold(mut self, threshold: usize) -> Self {
        self.repeated_burst_threshold = threshold;
        self
    }

    pub fn with_risk_thresholds(mut self, thresholds: RiskThresholds) -> Self {
        self.risk_thresholds = thresholds;
        self
    }
}

/// Per-session anomaly monitor. Tracks a bounded provider history and scores
/// each call against the [`BehaviorProfile`].
#[derive(Clone)]
pub struct AnomalyMonitor {
    history: VecDeque<BehaviorObservation>,
    profile: BehaviorProfile,
}

impl AnomalyMonitor {
    pub fn new(mut profile: BehaviorProfile) -> Self {
        profile.history_window = profile.history_window.max(1);
        Self {
            history: VecDeque::with_capacity(profile.history_window),
            profile,
        }
    }

    /// Number of observations retained internally. This never exceeds the
    /// configured history window.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Score a candidate without committing it to the retained behavior
    /// history. Callers should use this before policy enforcement and only
    /// commit successfully completed operations with [`Self::analyze`].
    pub fn preview(
        &self,
        provider: &str,
        arg_bytes: usize,
        egress_host: Option<&str>,
    ) -> AnomalyReport {
        let mut candidate = self.clone();
        candidate.analyze(provider, arg_bytes, egress_host)
    }

    /// Analyze one call. `egress_host` is the normalized host of an outbound
    /// request, if any. The signature is retained for existing callers.
    pub fn analyze(
        &mut self,
        provider: &str,
        arg_bytes: usize,
        egress_host: Option<&str>,
    ) -> AnomalyReport {
        let mut signals = Vec::new();

        if let Some(previous) = self.history.back()
            && !self
                .profile
                .allowed_bigrams
                .contains(&(previous.provider.clone(), provider.to_string()))
        {
            push_signal(
                &mut signals,
                AnomalySignalKind::UnexpectedSequence,
                UNEXPECTED_SEQUENCE_WEIGHT,
                format!(
                    "unexpected provider sequence {} -> {provider}",
                    previous.provider
                ),
            );
        }

        if let Some(max) = self.profile.max_arg_bytes.get(provider)
            && arg_bytes > *max
        {
            push_signal(
                &mut signals,
                AnomalySignalKind::OversizedArguments,
                OVERSIZED_ARGUMENTS_WEIGHT,
                format!("argument size {arg_bytes} bytes exceeds baseline {max} for {provider}"),
            );
        }

        if let Some(host) = egress_host
            && !self.profile.allowed_egress_hosts.contains(host)
        {
            push_signal(
                &mut signals,
                AnomalySignalKind::NovelEgress,
                NOVEL_EGRESS_WEIGHT,
                format!("novel egress host {host}"),
            );
        }

        if self.profile.sensitive_sinks.contains(provider)
            && self.profile.source_to_sink_window > 0
            && let Some((distance, source)) = self
                .history
                .iter()
                .rev()
                .take(self.profile.source_to_sink_window)
                .enumerate()
                .find_map(|(distance, observation)| {
                    self.profile
                        .sensitive_sources
                        .contains(&observation.provider)
                        .then_some((distance + 1, observation.provider.as_str()))
                })
        {
            push_signal(
                &mut signals,
                AnomalySignalKind::SensitiveSourceToSink,
                SENSITIVE_SOURCE_TO_SINK_WEIGHT,
                format!(
                    "sensitive source {source} reached sink {provider} within {distance} call(s)"
                ),
            );
        }

        let burst_threshold = match self.profile.repeated_burst_threshold {
            0 => None,
            threshold => Some(threshold.max(2)),
        };
        if let Some(threshold) = burst_threshold {
            let repeated = self
                .history
                .iter()
                .rev()
                .take_while(|observation| observation.provider == provider)
                .count()
                + 1;
            if repeated >= threshold {
                push_signal(
                    &mut signals,
                    AnomalySignalKind::RepeatedBurst,
                    REPEATED_BURST_WEIGHT,
                    format!(
                        "repeated provider burst: {provider} called {repeated} consecutive times"
                    ),
                );
            }
        }

        self.history.push_back(BehaviorObservation {
            provider: provider.to_string(),
            arg_bytes,
            egress_host: egress_host.map(str::to_string),
        });
        while self.history.len() > self.profile.history_window {
            self.history.pop_front();
        }

        let score = signals
            .iter()
            .map(|signal| signal.weight)
            .sum::<usize>()
            .min(100);
        let risk_level = classify_risk(score, self.profile.risk_thresholds);
        let recommended_action = action_for(risk_level);
        let reasons = signals
            .iter()
            .map(|signal| signal.evidence.clone())
            .collect();

        AnomalyReport {
            score,
            is_anomalous: !signals.is_empty(),
            reasons,
            risk_level,
            recommended_action,
            signals,
            history: self.history.iter().cloned().collect(),
        }
    }
}

fn push_signal(
    signals: &mut Vec<AnomalySignal>,
    kind: AnomalySignalKind,
    weight: usize,
    evidence: String,
) {
    signals.push(AnomalySignal {
        kind,
        weight,
        evidence,
    });
}

fn classify_risk(score: usize, thresholds: RiskThresholds) -> RiskLevel {
    let thresholds = thresholds.normalized();
    if score == 0 {
        RiskLevel::None
    } else if score >= thresholds.critical {
        RiskLevel::Critical
    } else if score >= thresholds.high {
        RiskLevel::High
    } else if score >= thresholds.medium {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn action_for(risk_level: RiskLevel) -> RecommendedAction {
    match risk_level {
        RiskLevel::None => RecommendedAction::Allow,
        RiskLevel::Low => RecommendedAction::Monitor,
        RiskLevel::Medium | RiskLevel::High => RecommendedAction::RequireReview,
        RiskLevel::Critical => RecommendedAction::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_signal(report: &AnomalyReport, kind: AnomalySignalKind) -> bool {
        report.signals.iter().any(|signal| signal.kind == kind)
    }

    #[test]
    fn benign_flow_is_not_anomalous() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        let inspect = monitor.analyze("runwarden.input.inspect", 100, None);
        let email = monitor.analyze("external.email.send", 200, Some("mail.example.com"));

        assert_eq!(inspect.score, 0);
        assert_eq!(inspect.risk_level, RiskLevel::None);
        assert_eq!(inspect.recommended_action, RecommendedAction::Allow);
        assert!(
            !inspect.is_anomalous,
            "inspect should be benign: {inspect:?}"
        );
        assert!(
            !email.is_anomalous,
            "inspect->email should be benign: {email:?}"
        );
        assert!(email.signals.is_empty());
        assert_eq!(email.history.len(), 2);
    }

    #[test]
    fn unexpected_sequence_is_weighted_and_explained() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        let memory_write = monitor.analyze("external.memory.write", 100, None);
        let api = monitor.analyze("external.api.request", 100, Some("api.example.com"));

        assert!(!memory_write.is_anomalous);
        assert!(has_signal(&api, AnomalySignalKind::UnexpectedSequence));
        assert_eq!(api.score, UNEXPECTED_SEQUENCE_WEIGHT);
        assert_eq!(api.risk_level, RiskLevel::Low);
        assert_eq!(api.recommended_action, RecommendedAction::Monitor);
        assert!(
            api.reasons
                .iter()
                .any(|reason| reason.contains("unexpected provider sequence"))
        );
    }

    #[test]
    fn novel_egress_host_is_flagged() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        let report = monitor.analyze("external.api.request", 100, Some("attacker.example.com"));

        assert!(has_signal(&report, AnomalySignalKind::NovelEgress));
        assert_eq!(report.score, NOVEL_EGRESS_WEIGHT);
        assert_eq!(report.risk_level, RiskLevel::Medium);
        assert_eq!(report.recommended_action, RecommendedAction::RequireReview);
    }

    #[test]
    fn large_argument_is_flagged() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        let report = monitor.analyze("external.mcp.filesystem.write_file", 100_000, None);

        assert!(has_signal(&report, AnomalySignalKind::OversizedArguments));
        assert_eq!(report.score, OVERSIZED_ARGUMENTS_WEIGHT);
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.contains("argument size"))
        );
    }

    #[test]
    fn first_call_skips_sequence_check() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        let report = monitor.analyze("external.email.send", 100, Some("mail.example.com"));

        assert!(!report.is_anomalous);
        assert!(!has_signal(&report, AnomalySignalKind::UnexpectedSequence));
    }

    #[test]
    fn preview_scores_candidate_without_committing_history() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);

        let report = monitor.preview("external.api.request", 100, Some("attacker.example.com"));

        assert_eq!(monitor.history_len(), 1);
        assert_eq!(report.history.len(), 2);
        assert!(has_signal(&report, AnomalySignalKind::NovelEgress));
    }

    #[test]
    fn sensitive_source_to_sink_is_high_risk_even_on_an_allowed_path() {
        let mut profile = BehaviorProfile::default_benign();
        profile.allowed_bigrams.insert((
            "external.mcp.filesystem.read_file".to_string(),
            "external.email.send".to_string(),
        ));
        let mut monitor = AnomalyMonitor::new(profile);

        monitor.analyze("runwarden.input.inspect", 100, None);
        monitor.analyze("external.mcp.filesystem.read_file", 200, None);
        let report = monitor.analyze("external.email.send", 300, Some("mail.example.com"));

        assert_eq!(report.score, SENSITIVE_SOURCE_TO_SINK_WEIGHT);
        assert_eq!(report.risk_level, RiskLevel::High);
        assert_eq!(report.recommended_action, RecommendedAction::RequireReview);
        assert!(has_signal(
            &report,
            AnomalySignalKind::SensitiveSourceToSink
        ));
    }

    #[test]
    fn combined_signals_saturate_at_critical() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        monitor.analyze("external.mcp.filesystem.read_file", 200, None);
        let report = monitor.analyze(
            "external.api.request",
            100_000,
            Some("attacker.example.com"),
        );

        assert_eq!(report.score, 100);
        assert_eq!(report.risk_level, RiskLevel::Critical);
        assert_eq!(report.recommended_action, RecommendedAction::Deny);
        for kind in [
            AnomalySignalKind::UnexpectedSequence,
            AnomalySignalKind::NovelEgress,
            AnomalySignalKind::OversizedArguments,
            AnomalySignalKind::SensitiveSourceToSink,
        ] {
            assert!(has_signal(&report, kind), "missing signal {kind:?}");
        }
    }

    #[test]
    fn repeated_provider_burst_is_detected() {
        let mut profile = BehaviorProfile::default_benign()
            .with_repeated_burst_threshold(3)
            .with_history_window(8);
        profile.allowed_bigrams.insert((
            "external.email.send".to_string(),
            "external.email.send".to_string(),
        ));
        let mut monitor = AnomalyMonitor::new(profile);

        monitor.analyze("runwarden.input.inspect", 10, None);
        monitor.analyze("external.email.send", 10, Some("mail.example.com"));
        monitor.analyze("external.email.send", 10, Some("mail.example.com"));
        let report = monitor.analyze("external.email.send", 10, Some("mail.example.com"));

        assert_eq!(report.score, REPEATED_BURST_WEIGHT);
        assert!(has_signal(&report, AnomalySignalKind::RepeatedBurst));
        assert!(report.reasons[0].contains("3 consecutive times"));
    }

    #[test]
    fn report_and_monitor_history_are_bounded() {
        let profile = BehaviorProfile::default()
            .with_history_window(3)
            .with_repeated_burst_threshold(0);
        let mut monitor = AnomalyMonitor::new(profile);
        let mut report = AnomalyReport::default();

        for provider in ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"] {
            report = monitor.analyze(provider, 1, None);
        }

        assert_eq!(monitor.history_len(), 3);
        assert_eq!(report.history.len(), 3);
        assert_eq!(
            report
                .history
                .iter()
                .map(|observation| observation.provider.as_str())
                .collect::<Vec<_>>(),
            vec!["p5", "p6", "p7"]
        );
    }

    #[test]
    fn risk_and_action_names_are_stable_snake_case() {
        assert_eq!(RiskLevel::Critical.as_str(), "critical");
        assert_eq!(RecommendedAction::RequireReview.as_str(), "require_review");
        assert_eq!(
            AnomalySignalKind::SensitiveSourceToSink.as_str(),
            "sensitive_source_to_sink"
        );
    }

    #[test]
    fn custom_risk_thresholds_are_normalized_and_applied() {
        let profile = BehaviorProfile::default_benign().with_risk_thresholds(RiskThresholds {
            medium: 10,
            high: 15,
            critical: 20,
        });
        let mut monitor = AnomalyMonitor::new(profile);
        monitor.analyze("runwarden.input.inspect", 100, None);
        let report = monitor.analyze("external.memory.write", 100_000, None);

        assert_eq!(report.score, OVERSIZED_ARGUMENTS_WEIGHT);
        assert_eq!(report.risk_level, RiskLevel::Critical);
        assert_eq!(report.recommended_action, RecommendedAction::Deny);
    }
}
