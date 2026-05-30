use std::collections::BTreeSet;

use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent};
use serde::{Deserialize, Serialize};

pub const FAST_GATE_NAME: &str = "runwarden-fast-gate";

pub mod artifact {
    use std::fs;
    use std::path::{Component, Path, PathBuf};

    use runwarden_kernel::artifact::{
        ArtifactManifest, ArtifactManifestEntry,
        ArtifactVerificationStatus as KernelArtifactVerificationStatus, RedactionSidecar,
    };
    use runwarden_kernel::evidence::hex_sha256;
    use serde::Serialize;

    pub use runwarden_kernel::artifact::ArtifactVerificationStatus;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ArtifactError {
        pub kind: ArtifactErrorKind,
        pub path: String,
        pub message: String,
        pub side_effect_executed: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub enum ArtifactErrorKind {
        RedactionFailed,
        PathEscape,
        SymlinkEscape,
        ArtifactHashMismatch,
        RedactionSidecarMissing,
        RedactionSidecarMismatch,
        ManifestIncomplete,
        ReadFailed,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ArtifactVerification {
        pub status: KernelArtifactVerificationStatus,
        pub findings: Vec<ArtifactError>,
    }

    pub fn seal_artifact(
        artifact_root: &Path,
        artifact_id: impl Into<String>,
        relative_path: impl AsRef<Path>,
        contents: &str,
    ) -> Result<ArtifactManifest, ArtifactError> {
        let artifact_id = artifact_id.into();
        let relative_path = relative_path.as_ref();
        reject_unsafe_relative_path(relative_path)?;

        let original_sha = hex_sha256(contents.as_bytes());
        let redacted = redact(contents);
        if redacted.contains_secret {
            return Err(artifact_error(
                ArtifactErrorKind::RedactionFailed,
                format_path(relative_path),
                "artifact contains unredacted secret-like material",
                false,
            ));
        }

        let artifact_path = contained_path(artifact_root, relative_path)?;
        let sidecar_relative_path =
            PathBuf::from(format!("{}.redaction.json", format_path(relative_path)));
        let sidecar_path = contained_path(artifact_root, &sidecar_relative_path)?;
        reject_symlink_components(artifact_root, relative_path)?;
        reject_symlink_components(artifact_root, &sidecar_relative_path)?;
        if let Some(parent) = artifact_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                artifact_error(
                    ArtifactErrorKind::ReadFailed,
                    format_path(relative_path),
                    format!("failed to create artifact directory: {err}"),
                    false,
                )
            })?;
        }
        reject_symlink_components(artifact_root, relative_path)?;
        reject_symlink_components(artifact_root, &sidecar_relative_path)?;

        let sidecar = RedactionSidecar {
            artifact_id: artifact_id.clone(),
            redaction_applied: redacted.redaction_applied,
            redacted_patterns: redacted.redacted_patterns,
            original_sha256: original_sha,
            redacted_sha256: hex_sha256(redacted.contents.as_bytes()),
        };
        let sidecar_body = serde_json::to_string_pretty(&sidecar).map_err(|err| {
            artifact_error(
                ArtifactErrorKind::ReadFailed,
                format_path(&sidecar_relative_path),
                format!("failed to serialize redaction sidecar: {err}"),
                false,
            )
        })?;

        fs::write(&artifact_path, redacted.contents.as_bytes()).map_err(|err| {
            artifact_error(
                ArtifactErrorKind::ReadFailed,
                format_path(relative_path),
                format!("failed to write artifact: {err}"),
                false,
            )
        })?;
        fs::write(&sidecar_path, format!("{sidecar_body}\n")).map_err(|err| {
            artifact_error(
                ArtifactErrorKind::ReadFailed,
                format_path(&sidecar_relative_path),
                format!("failed to write redaction sidecar: {err}"),
                true,
            )
        })?;

        Ok(ArtifactManifest::single(ArtifactManifestEntry {
            artifact_id,
            relative_path: format_path(relative_path),
            sha256: Some(hex_sha256(redacted.contents.as_bytes())),
            redaction_sidecar_path: Some(format_path(&sidecar_relative_path)),
            redaction_sidecar_sha256: Some(hex_sha256(format!("{sidecar_body}\n").as_bytes())),
            obs_refs: extract_obs_refs(&redacted.contents),
        }))
    }

    pub fn verify_artifact_manifest(
        artifact_root: &Path,
        manifest: &ArtifactManifest,
    ) -> ArtifactVerification {
        let mut findings = Vec::new();
        if manifest.artifacts.is_empty() {
            findings.push(artifact_error(
                ArtifactErrorKind::ManifestIncomplete,
                String::new(),
                "artifact manifest contains no artifacts",
                false,
            ));
        }

        for entry in &manifest.artifacts {
            verify_entry(artifact_root, entry, &mut findings);
        }

        ArtifactVerification {
            status: if findings.is_empty() {
                KernelArtifactVerificationStatus::Verified
            } else {
                KernelArtifactVerificationStatus::Failed
            },
            findings,
        }
    }

    fn verify_entry(
        artifact_root: &Path,
        entry: &ArtifactManifestEntry,
        findings: &mut Vec<ArtifactError>,
    ) {
        let relative_path = PathBuf::from(&entry.relative_path);
        if let Err(err) = reject_unsafe_relative_path(&relative_path) {
            findings.push(err);
            return;
        }

        let artifact_path = match contained_path(artifact_root, &relative_path) {
            Ok(path) => path,
            Err(err) => {
                findings.push(err);
                return;
            }
        };

        if symlink_escapes(artifact_root, &artifact_path) {
            findings.push(artifact_error(
                ArtifactErrorKind::SymlinkEscape,
                entry.relative_path.clone(),
                "artifact path resolves outside the artifact root",
                false,
            ));
            return;
        }

        match fs::read(&artifact_path) {
            Ok(bytes) => {
                let artifact_sha = hex_sha256(&bytes);
                if entry.sha256.as_deref() != Some(artifact_sha.as_str()) {
                    findings.push(artifact_error(
                        ArtifactErrorKind::ArtifactHashMismatch,
                        entry.relative_path.clone(),
                        "artifact sha256 does not match manifest",
                        false,
                    ));
                }
                verify_redaction_sidecar(artifact_root, entry, artifact_sha.as_str(), findings);
            }
            Err(err) => findings.push(artifact_error(
                ArtifactErrorKind::ReadFailed,
                entry.relative_path.clone(),
                format!("failed to read artifact: {err}"),
                false,
            )),
        }
    }

    fn verify_redaction_sidecar(
        artifact_root: &Path,
        entry: &ArtifactManifestEntry,
        artifact_sha: &str,
        findings: &mut Vec<ArtifactError>,
    ) {
        let Some(sidecar_relative_path) = &entry.redaction_sidecar_path else {
            findings.push(artifact_error(
                ArtifactErrorKind::RedactionSidecarMissing,
                entry.relative_path.clone(),
                "artifact is missing a redaction sidecar path",
                false,
            ));
            return;
        };
        let sidecar_path = match contained_path(artifact_root, Path::new(sidecar_relative_path)) {
            Ok(path) => path,
            Err(err) => {
                findings.push(err);
                return;
            }
        };
        if symlink_escapes(artifact_root, &sidecar_path) {
            findings.push(artifact_error(
                ArtifactErrorKind::SymlinkEscape,
                sidecar_relative_path.clone(),
                "redaction sidecar path resolves outside the artifact root",
                false,
            ));
            return;
        }
        match fs::read(&sidecar_path) {
            Ok(bytes) => {
                if entry.redaction_sidecar_sha256.as_deref() != Some(hex_sha256(&bytes).as_str()) {
                    findings.push(artifact_error(
                        ArtifactErrorKind::RedactionSidecarMismatch,
                        sidecar_relative_path.clone(),
                        "redaction sidecar sha256 does not match manifest",
                        false,
                    ));
                }
                match serde_json::from_slice::<RedactionSidecar>(&bytes) {
                    Ok(sidecar)
                        if sidecar.artifact_id == entry.artifact_id
                            && sidecar.redacted_sha256 == artifact_sha => {}
                    Ok(_) => findings.push(artifact_error(
                        ArtifactErrorKind::RedactionSidecarMismatch,
                        sidecar_relative_path.clone(),
                        "redaction sidecar does not match artifact metadata",
                        false,
                    )),
                    Err(err) => findings.push(artifact_error(
                        ArtifactErrorKind::RedactionSidecarMismatch,
                        sidecar_relative_path.clone(),
                        format!("redaction sidecar JSON is invalid: {err}"),
                        false,
                    )),
                }
            }
            Err(err) => findings.push(artifact_error(
                ArtifactErrorKind::RedactionSidecarMissing,
                sidecar_relative_path.clone(),
                format!("failed to read redaction sidecar: {err}"),
                false,
            )),
        }
    }

    struct RedactedArtifact {
        contents: String,
        contains_secret: bool,
        redaction_applied: bool,
        redacted_patterns: Vec<String>,
    }

    fn redact(contents: &str) -> RedactedArtifact {
        let secret_markers = ["SECRET=", "TOKEN=", "PASSWORD=", "PRIVATE KEY"];
        let contains_secret = secret_markers
            .iter()
            .any(|marker| contents.contains(marker));
        RedactedArtifact {
            contents: contents.to_string(),
            contains_secret,
            redaction_applied: false,
            redacted_patterns: Vec::new(),
        }
    }

    fn extract_obs_refs(contents: &str) -> Vec<String> {
        let mut refs = Vec::new();
        for token in contents.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
            if token.starts_with("obs_") && !refs.contains(&token.to_string()) {
                refs.push(token.to_string());
            }
        }
        refs
    }

    fn contained_path(root: &Path, relative_path: &Path) -> Result<PathBuf, ArtifactError> {
        reject_unsafe_relative_path(relative_path)?;
        Ok(root.join(relative_path))
    }

    fn reject_unsafe_relative_path(path: &Path) -> Result<(), ArtifactError> {
        if path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::Prefix(_) | Component::RootDir
                )
            })
        {
            return Err(artifact_error(
                ArtifactErrorKind::PathEscape,
                format_path(path),
                "artifact path must stay relative to the artifact root",
                false,
            ));
        }
        Ok(())
    }

    fn symlink_escapes(root: &Path, path: &Path) -> bool {
        let Ok(canonical_root) = root.canonicalize() else {
            return true;
        };
        let Ok(canonical_path) = path.canonicalize() else {
            return false;
        };
        !canonical_path.starts_with(canonical_root)
    }

    fn reject_symlink_components(root: &Path, relative_path: &Path) -> Result<(), ArtifactError> {
        if fs::symlink_metadata(root)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(artifact_error(
                ArtifactErrorKind::SymlinkEscape,
                format_path(root),
                "artifact root must not be a symlink",
                false,
            ));
        }

        let mut current = root.to_path_buf();
        for component in relative_path.components() {
            let Component::Normal(part) = component else {
                continue;
            };
            current.push(part);
            if fs::symlink_metadata(&current)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(artifact_error(
                    ArtifactErrorKind::SymlinkEscape,
                    format_path(relative_path),
                    "artifact path contains a symlink component",
                    false,
                ));
            }
        }
        Ok(())
    }

    fn artifact_error(
        kind: ArtifactErrorKind,
        path: impl Into<String>,
        message: impl Into<String>,
        side_effect_executed: bool,
    ) -> ArtifactError {
        ArtifactError {
            kind,
            path: path.into(),
            message: message.into(),
            side_effect_executed,
        }
    }

    fn format_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }
}

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
    }

    impl ReportClaimSupport {
        fn has_expectations(&self) -> bool {
            self.provider.is_some()
                || self.event_type.is_some()
                || self.decision.is_some()
                || self.execution_status.is_some()
                || self.side_effect_executed.is_some()
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
        if let Some(support) = &claim.support
            && support.has_expectations()
        {
            return observation_matches_structured_support(support, event);
        }

        let text = claim.text.to_ascii_lowercase();
        if text.contains("completed") {
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
        true
    }

    fn observation_matches_structured_support(
        support: &ReportClaimSupport,
        event: &TraceEvent,
    ) -> bool {
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

pub mod audit {
    use std::collections::BTreeMap;

    use runwarden_kernel::evidence::TraceEvent;
    use serde::Serialize;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct ProviderAuditSummary {
        pub completed: usize,
        pub denied: usize,
        pub failed: usize,
        pub requires_review: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct AuditSummary {
        pub total_events: usize,
        pub completed_count: usize,
        pub denied_count: usize,
        pub failed_count: usize,
        pub requires_review_count: usize,
        pub providers: BTreeMap<String, ProviderAuditSummary>,
        pub side_effect_executed: bool,
    }

    pub fn audit_summary(trace_events: &[TraceEvent]) -> AuditSummary {
        let mut summary = AuditSummary {
            total_events: trace_events.len(),
            completed_count: 0,
            denied_count: 0,
            failed_count: 0,
            requires_review_count: 0,
            providers: BTreeMap::new(),
            side_effect_executed: false,
        };

        for event in trace_events {
            let decision = decision_for_event(event);
            match decision {
                Some(AuditDecision::Completed) => summary.completed_count += 1,
                Some(AuditDecision::Denied) => summary.denied_count += 1,
                Some(AuditDecision::Failed) => summary.failed_count += 1,
                Some(AuditDecision::RequiresReview) => summary.requires_review_count += 1,
                None => {}
            }

            if let (Some(provider), Some(decision)) = (event.provider.as_ref(), decision) {
                let provider_summary =
                    summary
                        .providers
                        .entry(provider.clone())
                        .or_insert(ProviderAuditSummary {
                            completed: 0,
                            denied: 0,
                            failed: 0,
                            requires_review: 0,
                        });
                match decision {
                    AuditDecision::Completed => provider_summary.completed += 1,
                    AuditDecision::Denied => provider_summary.denied += 1,
                    AuditDecision::Failed => provider_summary.failed += 1,
                    AuditDecision::RequiresReview => provider_summary.requires_review += 1,
                }
            }
        }

        summary
    }

    #[derive(Debug, Clone, Copy)]
    enum AuditDecision {
        Completed,
        Denied,
        Failed,
        RequiresReview,
    }

    fn decision_for_event(event: &TraceEvent) -> Option<AuditDecision> {
        match event.event_type.as_str() {
            "provider_completed" => Some(AuditDecision::Completed),
            "provider_denied" => Some(AuditDecision::Denied),
            "provider_failed" => Some(AuditDecision::Failed),
            "provider_approval_pending" => Some(AuditDecision::RequiresReview),
            _ => match event
                .payload
                .get("decision")
                .and_then(serde_json::Value::as_str)
            {
                Some("allowed") | Some("completed") => Some(AuditDecision::Completed),
                Some("denied") => Some(AuditDecision::Denied),
                Some("failed") => Some(AuditDecision::Failed),
                Some("requires_review") => Some(AuditDecision::RequiresReview),
                _ => None,
            },
        }
    }
}

pub mod accountability {
    use runwarden_kernel::evidence::TraceEvent;
    use serde::Serialize;
    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct AccountabilityChain {
        pub obs_id: String,
        pub provider: Option<String>,
        pub requester_id: Option<String>,
        pub actor_id: Option<String>,
        pub authz_id: Option<String>,
        pub approval_id: Option<String>,
        pub reviewer: Option<String>,
        pub report_claim_id: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct AccountabilitySummary {
        pub chains: Vec<AccountabilityChain>,
        pub side_effect_executed: bool,
    }

    pub fn accountability_summary(trace_events: &[TraceEvent]) -> AccountabilitySummary {
        AccountabilitySummary {
            chains: trace_events
                .iter()
                .map(|event| AccountabilityChain {
                    obs_id: event.obs_id.clone(),
                    provider: event.provider.clone(),
                    requester_id: payload_str(&event.payload, "requester_id"),
                    actor_id: payload_str(&event.payload, "actor_id"),
                    authz_id: payload_str(&event.payload, "authz_id"),
                    approval_id: payload_str(&event.payload, "approval_id"),
                    reviewer: payload_str(&event.payload, "reviewer"),
                    report_claim_id: payload_str(&event.payload, "report_claim_id"),
                })
                .collect(),
            side_effect_executed: false,
        }
    }

    fn payload_str(payload: &Value, key: &str) -> Option<String> {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    }
}

pub mod eval {
    use super::cert::{AgentConfigExposure, certify_agent_config};
    use super::report::{ReportDraft, lint_report_against_trace};
    use super::*;
    use serde_json::Value;

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentNativeExpectation {
        RunwardenOnlyAllowed,
        RawToolsDenied,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct AgentNativeConfigCase {
        pub id: String,
        pub config: Value,
        pub expectation: AgentNativeExpectation,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct AgentNativeEvalCase {
        pub id: String,
        pub expectation: AgentNativeExpectation,
        pub passed: bool,
        pub exposure: AgentConfigExposure,
        pub findings: Vec<String>,
        pub failure: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct AgentNativeEvalMetrics {
        pub case_count: usize,
        pub runwarden_only_allow_rate: f64,
        pub raw_tool_block_rate: f64,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct AgentNativeEvalReport {
        pub passed: bool,
        pub metrics: AgentNativeEvalMetrics,
        pub cases: Vec<AgentNativeEvalCase>,
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

    pub fn evaluate_agent_native_configs(cases: &[AgentNativeConfigCase]) -> AgentNativeEvalReport {
        let mut evaluated = Vec::new();
        let mut failures = Vec::new();

        for case in cases {
            let cert = certify_agent_config(&case.config);
            let (passed, failure) = match case.expectation {
                AgentNativeExpectation::RunwardenOnlyAllowed
                    if cert.passed && cert.exposure == AgentConfigExposure::RunwardenOnly =>
                {
                    (true, None)
                }
                AgentNativeExpectation::RawToolsDenied
                    if !cert.passed && cert.exposure == AgentConfigExposure::RawToolExposure =>
                {
                    (true, None)
                }
                AgentNativeExpectation::RunwardenOnlyAllowed => (
                    false,
                    Some("expected_runwarden_only_config_to_pass".to_string()),
                ),
                AgentNativeExpectation::RawToolsDenied => (
                    false,
                    Some("expected_raw_tool_exposure_to_be_blocked".to_string()),
                ),
            };

            if let Some(failure) = &failure {
                failures.push(format!("{}:{failure}", case.id));
            }

            evaluated.push(AgentNativeEvalCase {
                id: case.id.clone(),
                expectation: case.expectation,
                passed,
                exposure: cert.exposure,
                findings: cert.findings,
                failure,
            });
        }

        let runwarden_only_total = evaluated
            .iter()
            .filter(|case| case.expectation == AgentNativeExpectation::RunwardenOnlyAllowed)
            .count();
        let runwarden_only_passed = evaluated
            .iter()
            .filter(|case| {
                case.expectation == AgentNativeExpectation::RunwardenOnlyAllowed && case.passed
            })
            .count();
        let raw_tool_total = evaluated
            .iter()
            .filter(|case| case.expectation == AgentNativeExpectation::RawToolsDenied)
            .count();
        let raw_tool_blocked = evaluated
            .iter()
            .filter(|case| {
                case.expectation == AgentNativeExpectation::RawToolsDenied && case.passed
            })
            .count();

        AgentNativeEvalReport {
            passed: failures.is_empty(),
            metrics: AgentNativeEvalMetrics {
                case_count: evaluated.len(),
                runwarden_only_allow_rate: ratio(runwarden_only_passed, runwarden_only_total),
                raw_tool_block_rate: ratio(raw_tool_blocked, raw_tool_total),
            },
            cases: evaluated,
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

pub mod cert {
    use std::fs;
    use std::path::Path;

    use serde::Serialize;
    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct CertCheck {
        pub id: String,
        pub passed: bool,
        pub message: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct CertReport {
        pub passed: bool,
        pub checks: Vec<CertCheck>,
        pub side_effect_executed: bool,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentConfigExposure {
        RunwardenOnly,
        RawToolExposure,
        InvalidConfig,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct AgentConfigCertReport {
        pub passed: bool,
        pub exposure: AgentConfigExposure,
        pub findings: Vec<String>,
        pub side_effect_executed: bool,
    }

    pub fn certify_workspace(root: &Path) -> CertReport {
        let mut checks = vec![
            required_paths(
                root,
                "schema_contracts",
                &[
                    "schemas/provider-call.schema.json",
                    "schemas/provider-outcome.schema.json",
                    "schemas/provider-contract.schema.json",
                    "schemas/provider-manifest.schema.json",
                    "schemas/approval-record.schema.json",
                    "schemas/artifact-manifest.schema.json",
                    "schemas/trace-event.schema.json",
                    "schemas/report.schema.json",
                ],
            ),
            required_paths(
                root,
                "release_scripts",
                &[
                    "scripts/dev_gate.sh",
                    "scripts/check_ts_contracts.sh",
                    "scripts/release_gate_local.sh",
                    "scripts/generate_artifacts.sh",
                    "scripts/artifact_leak_scan.sh",
                ],
            ),
            required_paths(
                root,
                "scenario_evidence",
                &[
                    "scenarios/enterprise-agent-security/manifests/assessment.toml",
                    "scenarios/enterprise-agent-security/expected/denials.json",
                    "scenarios/local-web-risk/expected/eval-baseline.json",
                    "scenarios/workflow-processing-agent/expected/eval-baseline.json",
                    "scenarios/ops-collaboration-agent/expected/eval-baseline.json",
                    "scenarios/knowledge-retrieval-qa/expected/eval-baseline.json",
                    "scenarios/government-office-assistant/expected/eval-baseline.json",
                    "scenarios/offline-evidence/expected/eval-baseline.json",
                    "tests/fixtures/default-trace.json",
                    "tests/fixtures/default-report.json",
                    "examples/providers/external.mcp.browser.open_page.json",
                    "examples/providers/kernel.toml",
                ],
            ),
        ];

        checks.push(agent_config_check(root));
        checks.push(release_artifact_check(root));
        checks.push(ci_tiered_gates_check(root));

        CertReport {
            passed: checks.iter().all(|check| check.passed),
            checks,
            side_effect_executed: false,
        }
    }

    pub fn certify_agent_config(config: &Value) -> AgentConfigCertReport {
        let Some(servers) = config.get("mcpServers").and_then(Value::as_object) else {
            return AgentConfigCertReport {
                passed: false,
                exposure: AgentConfigExposure::InvalidConfig,
                findings: vec!["mcpServers object is required".to_string()],
                side_effect_executed: false,
            };
        };

        let mut findings = Vec::new();
        for (name, server) in servers {
            let command = server
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name != "runwarden" {
                findings.push(format!("raw or downstream MCP exposed: {name} ({command})"));
                continue;
            }
            if command != "runwarden-mcp" {
                findings.push(format!(
                    "runwarden MCP server must execute runwarden-mcp, got: {command}"
                ));
                continue;
            }
            let invalid_args = server
                .get("args")
                .is_some_and(|args| !args.as_array().is_some_and(|args| args.is_empty()));
            if invalid_args
                || server.get("env").is_some()
                || server.get("cwd").is_some()
                || server.get("url").is_some()
                || server.get("transport").is_some()
            {
                findings.push(
                    "runwarden MCP server must not define args/env/cwd/url/transport overrides"
                        .to_string(),
                );
            }
        }
        if !servers.contains_key("runwarden") {
            findings.push("missing runwarden MCP server".to_string());
        }

        if findings.is_empty() && servers.contains_key("runwarden") {
            AgentConfigCertReport {
                passed: true,
                exposure: AgentConfigExposure::RunwardenOnly,
                findings,
                side_effect_executed: false,
            }
        } else {
            AgentConfigCertReport {
                passed: false,
                exposure: AgentConfigExposure::RawToolExposure,
                findings,
                side_effect_executed: false,
            }
        }
    }

    fn agent_config_check(root: &Path) -> CertCheck {
        let path = root.join("examples/agent-configs/claude.runwarden-only.json");
        let report = fs::read_to_string(&path)
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok())
            .map(|config| certify_agent_config(&config));

        match report {
            Some(report) if report.passed => check(
                "agent_config_runwarden_only",
                true,
                "example agent config exposes only runwarden-mcp",
            ),
            Some(report) => check(
                "agent_config_runwarden_only",
                false,
                format!("unsafe agent config: {:?}", report.exposure),
            ),
            None => check(
                "agent_config_runwarden_only",
                false,
                "example agent config is missing or invalid JSON",
            ),
        }
    }

    fn release_artifact_check(root: &Path) -> CertCheck {
        let body =
            fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap_or_default();
        let passed = active_yaml_contains(&body, "matrix:")
            && active_yaml_contains(&body, "cargo build --workspace --release")
            && active_yaml_contains(&body, "tags:")
            && active_yaml_contains(&body, "scripts/release_gate_local.sh")
            && active_yaml_contains(&body, "scripts/generate_artifacts.sh")
            && active_yaml_contains(&body, "scripts/artifact_leak_scan.sh")
            && active_yaml_contains(&body, "actions/upload-artifact")
            && active_yaml_contains(&body, "softprops/action-gh-release");
        check(
            "release_artifact_contract",
            passed,
            "release workflow declares matrix release smoke and release build",
        )
    }

    fn ci_tiered_gates_check(root: &Path) -> CertCheck {
        let body = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap_or_default();
        let passed = active_yaml_contains(&body, "pull_request:")
            && active_yaml_contains(&body, "schedule:")
            && active_yaml_contains(&body, "scripts/pr_fast_gate.sh")
            && active_yaml_contains(&body, "scripts/nightly_full_gate.sh");
        check(
            "ci_tiered_gates",
            passed,
            "CI splits PR fast gate from nightly full gate",
        )
    }

    fn required_paths(root: &Path, id: &str, paths: &[&str]) -> CertCheck {
        let missing: Vec<_> = paths
            .iter()
            .filter(|path| {
                root.join(path)
                    .symlink_metadata()
                    .map(|metadata| !metadata.file_type().is_file())
                    .unwrap_or(true)
            })
            .copied()
            .collect();
        check(
            id,
            missing.is_empty(),
            if missing.is_empty() {
                "required files are present".to_string()
            } else {
                format!("missing {}", missing.join(", "))
            },
        )
    }

    fn check(id: impl Into<String>, passed: bool, message: impl Into<String>) -> CertCheck {
        CertCheck {
            id: id.into(),
            passed,
            message: message.into(),
        }
    }

    fn active_yaml_contains(body: &str, needle: &str) -> bool {
        body.lines().any(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with('#') && trimmed.contains(needle)
        })
    }
}

pub mod bench {
    use std::fs;
    use std::path::Path;

    use serde::Serialize;
    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct BenchmarkMetrics {
        pub scenario_count: usize,
        pub expected_denial_cases: usize,
        pub provider_mediation_rate: f64,
        pub policy_denial_correctness: f64,
    }

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct BenchmarkReport {
        pub passed: bool,
        pub metrics: BenchmarkMetrics,
        pub side_effect_executed: bool,
    }

    pub fn benchmark_workspace(root: &Path) -> std::io::Result<BenchmarkReport> {
        let scenario_count = fs::read_dir(root.join("scenarios"))?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .count();
        let expected_denials = read_expected_denials(root)?;
        let expected_denial_cases = expected_denials.len();
        let denied_cases = expected_denials
            .iter()
            .filter(|case| case.get("decision").and_then(Value::as_str) == Some("denied"))
            .count();

        let provider_mediation_rate = if expected_denial_cases == 0 {
            1.0
        } else {
            expected_denials
                .iter()
                .filter(|case| {
                    case.get("provider")
                        .and_then(Value::as_str)
                        .is_some_and(|provider| !provider.trim().is_empty())
                })
                .count() as f64
                / expected_denial_cases as f64
        };
        let policy_denial_correctness = if expected_denial_cases == 0 {
            1.0
        } else {
            denied_cases as f64 / expected_denial_cases as f64
        };

        Ok(BenchmarkReport {
            passed: scenario_count > 0
                && expected_denial_cases > 0
                && provider_mediation_rate >= 1.0
                && policy_denial_correctness >= 1.0,
            metrics: BenchmarkMetrics {
                scenario_count,
                expected_denial_cases,
                provider_mediation_rate,
                policy_denial_correctness,
            },
            side_effect_executed: false,
        })
    }

    fn read_expected_denials(root: &Path) -> std::io::Result<Vec<Value>> {
        let scenarios_dir = root.join("scenarios");
        let mut entries = fs::read_dir(scenarios_dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());

        let mut denials = Vec::new();
        for entry in entries {
            let scenario_dir = entry.path();
            if !scenario_dir.is_dir() {
                continue;
            }
            let denials_path = scenario_dir.join("expected/denials.json");
            if !denials_path.exists() {
                continue;
            }
            let body = fs::read_to_string(denials_path)?;
            let values: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
            denials.extend(values);
        }
        Ok(denials)
    }
}
