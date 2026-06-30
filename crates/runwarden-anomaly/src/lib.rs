//! Lightweight behavior-based anomaly detection for Runwarden-supervised tool
//! calls.
//!
//! This is the contest's "anomaly detection model": a monitoring layer that
//! complements the rule-based policy (which enforces allow/deny/ask). It flags
//! tool calls that deviate from a benign baseline in three dimensions:
//!
//! - **unexpected provider sequence** — the (prev, curr) provider bigram was
//!   not seen in benign flows (e.g. `memory.write -> api.request`).
//! - **novel egress host** — the request targets a host absent from the benign
//!   host set (e.g. a shadow callback).
//! - **unusual argument size** — the argument payload exceeds the per-provider
//!   benign maximum (e.g. a bulk exfiltration).
//!
//! The monitor is stateful per session (it tracks the provider sequence) and
//! stateless across processes (callers maintain the `AnomalyMonitor`).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

/// The result of analyzing one tool call against the benign baseline.
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyReport {
    /// Number of baseline violations found (0 = benign-shaped).
    pub score: usize,
    /// True when `score > 0` (the call deviates from the baseline).
    pub is_anomalous: bool,
    /// Human-readable violation reasons.
    pub reasons: Vec<String>,
}

/// A benign behavior baseline: allowed provider bigrams, per-provider max
/// argument sizes, and the set of egress hosts seen in benign flows.
#[derive(Debug, Clone, Default)]
pub struct BehaviorProfile {
    pub allowed_bigrams: BTreeSet<(String, String)>,
    pub max_arg_bytes: BTreeMap<String, usize>,
    pub allowed_egress_hosts: BTreeSet<String>,
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
            "external.mcp.browser.open_page",
        ];
        let mut bigrams = BTreeSet::new();
        for next in after_inspect {
            bigrams.insert(("runwarden.input.inspect".to_string(), next.to_string()));
        }
        bigrams.insert((
            "external.email.send".to_string(),
            "external.api.request".to_string(),
        ));
        let mut max_arg_bytes = BTreeMap::new();
        for provider in after_inspect {
            max_arg_bytes.insert(provider.to_string(), 4096);
        }
        max_arg_bytes.insert("runwarden.input.inspect".to_string(), 4096);
        let allowed_egress_hosts = ["api.example.com", "mail.example.com"]
            .iter()
            .map(|host| host.to_string())
            .collect();
        Self {
            allowed_bigrams: bigrams,
            max_arg_bytes,
            allowed_egress_hosts,
        }
    }
}

/// Per-session anomaly monitor. Tracks the provider sequence + scores each
/// call against the [`BehaviorProfile`].
pub struct AnomalyMonitor {
    history: Vec<String>,
    profile: BehaviorProfile,
}

impl AnomalyMonitor {
    pub fn new(profile: BehaviorProfile) -> Self {
        Self {
            history: Vec::new(),
            profile,
        }
    }

    /// Analyze one call. `egress_host` is the host of any outbound request the
    /// call targets (None for non-network calls). Updates the internal
    /// sequence history.
    pub fn analyze(
        &mut self,
        provider: &str,
        arg_bytes: usize,
        egress_host: Option<&str>,
    ) -> AnomalyReport {
        let mut reasons = Vec::new();
        if let Some(prev) = self.history.last()
            && !self
                .profile
                .allowed_bigrams
                .contains(&(prev.clone(), provider.to_string()))
        {
            reasons.push(format!("unexpected provider sequence {prev} -> {provider}"));
        }
        if let Some(max) = self.profile.max_arg_bytes.get(provider)
            && arg_bytes > *max
        {
            reasons.push(format!(
                "argument size {arg_bytes} bytes exceeds baseline {max} for {provider}"
            ));
        }
        if let Some(host) = egress_host
            && !self.profile.allowed_egress_hosts.contains(host)
        {
            reasons.push(format!("novel egress host {host}"));
        }
        let score = reasons.len();
        self.history.push(provider.to_string());
        AnomalyReport {
            score,
            is_anomalous: score > 0,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_flow_is_not_anomalous() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        let inspect = monitor.analyze("runwarden.input.inspect", 100, None);
        let email = monitor.analyze("external.email.send", 200, Some("mail.example.com"));
        assert!(
            !inspect.is_anomalous,
            "inspect should be benign: {inspect:?}"
        );
        assert!(
            !email.is_anomalous,
            "inspect->email.send should be benign: {email:?}"
        );
    }

    #[test]
    fn unexpected_sequence_is_flagged() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        let memory_write = monitor.analyze("external.memory.write", 100, None);
        // inspect -> memory.write is benign; memory.write -> api.request is not.
        let api = monitor.analyze("external.api.request", 100, Some("api.example.com"));
        assert!(!memory_write.is_anomalous);
        assert!(
            api.is_anomalous,
            "memory.write -> api.request should be flagged"
        );
        assert!(
            api.reasons
                .iter()
                .any(|r| r.contains("unexpected provider sequence"))
        );
    }

    #[test]
    fn novel_egress_host_is_flagged() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        let report = monitor.analyze("external.api.request", 100, Some("attacker.example.com"));
        assert!(report.is_anomalous);
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.contains("novel egress host attacker.example.com"))
        );
    }

    #[test]
    fn large_argument_is_flagged() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        monitor.analyze("runwarden.input.inspect", 100, None);
        let report = monitor.analyze("external.mcp.filesystem.write_file", 100_000, None);
        assert!(report.is_anomalous);
        assert!(report.reasons.iter().any(|r| r.contains("argument size")));
    }

    #[test]
    fn first_call_skips_sequence_check() {
        let mut monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
        // No prior call -> no bigram to violate; only arg/host can flag.
        let report = monitor.analyze("external.email.send", 100, Some("mail.example.com"));
        assert!(!report.is_anomalous);
    }
}
