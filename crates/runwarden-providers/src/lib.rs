pub mod runtime {
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::path::{Component, Path, PathBuf};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum NetworkPolicy {
        DenyAll,
        AllowHosts(BTreeSet<String>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProviderRuntimePolicy {
        pub no_shell_by_default: bool,
        pub scrub_environment: bool,
        pub kill_process_tree_on_timeout: bool,
        pub cwd_root: PathBuf,
        pub allowed_env: BTreeSet<String>,
        pub network_policy: NetworkPolicy,
        pub max_timeout_ms: u64,
        pub max_stdout_bytes: usize,
        pub max_stderr_bytes: usize,
    }

    impl ProviderRuntimePolicy {
        pub fn locked_to_root(root: impl Into<PathBuf>) -> Self {
            Self {
                cwd_root: root.into(),
                ..Self::default()
            }
        }

        pub fn allow_env(&mut self, name: impl Into<String>) {
            self.allowed_env.insert(name.into());
        }
    }

    impl Default for ProviderRuntimePolicy {
        fn default() -> Self {
            Self {
                no_shell_by_default: true,
                scrub_environment: true,
                kill_process_tree_on_timeout: true,
                cwd_root: PathBuf::from("/"),
                allowed_env: BTreeSet::new(),
                network_policy: NetworkPolicy::DenyAll,
                max_timeout_ms: 30_000,
                max_stdout_bytes: 1_048_576,
                max_stderr_bytes: 1_048_576,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProviderRuntimeRequest {
        pub executable: String,
        pub args: Vec<String>,
        pub cwd: PathBuf,
        pub use_shell: bool,
        pub inherit_parent_env: bool,
        pub env: BTreeMap<String, String>,
        pub network_hosts: BTreeSet<String>,
        pub timeout_ms: u64,
        pub stdout_limit_bytes: usize,
        pub stderr_limit_bytes: usize,
    }

    impl ProviderRuntimeRequest {
        pub fn new(executable: impl Into<String>) -> Self {
            Self {
                executable: executable.into(),
                args: Vec::new(),
                cwd: PathBuf::from("."),
                use_shell: false,
                inherit_parent_env: false,
                env: BTreeMap::new(),
                network_hosts: BTreeSet::new(),
                timeout_ms: 5_000,
                stdout_limit_bytes: 65_536,
                stderr_limit_bytes: 65_536,
            }
        }

        pub fn arg(mut self, arg: impl Into<String>) -> Self {
            self.args.push(arg.into());
            self
        }

        pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
            self.cwd = cwd.into();
            self
        }

        pub fn use_shell(mut self, use_shell: bool) -> Self {
            self.use_shell = use_shell;
            self
        }

        pub fn inherit_parent_env(mut self, inherit_parent_env: bool) -> Self {
            self.inherit_parent_env = inherit_parent_env;
            self
        }

        pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
            self.env.insert(name.into(), value.into());
            self
        }

        pub fn network_host(mut self, host: impl Into<String>) -> Self {
            self.network_hosts.insert(normalize_host(&host.into()));
            self
        }

        pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
            self.timeout_ms = timeout_ms;
            self
        }

        pub fn stdout_limit_bytes(mut self, stdout_limit_bytes: usize) -> Self {
            self.stdout_limit_bytes = stdout_limit_bytes;
            self
        }

        pub fn stderr_limit_bytes(mut self, stderr_limit_bytes: usize) -> Self {
            self.stderr_limit_bytes = stderr_limit_bytes;
            self
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct PreparedProviderProcess {
        pub executable: String,
        pub args: Vec<String>,
        pub cwd: PathBuf,
        pub env: BTreeMap<String, String>,
        pub network_hosts: BTreeSet<String>,
        pub timeout_ms: u64,
        pub stdout_limit_bytes: usize,
        pub stderr_limit_bytes: usize,
        pub kill_process_tree_on_timeout: bool,
        pub side_effect_executed: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub enum ProviderRuntimeDenialKind {
        ShellDenied,
        CwdEscape,
        EnvInheritanceDenied,
        EnvNotAllowed,
        NetworkDenied,
        TimeoutTooLarge,
        OutputLimitTooLarge,
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
    pub struct ProviderRuntimeDenial {
        pub kind: ProviderRuntimeDenialKind,
        pub reason: String,
        pub side_effect_executed: bool,
    }

    pub struct ProviderRuntime;

    impl ProviderRuntime {
        pub fn prepare(
            policy: &ProviderRuntimePolicy,
            request: &ProviderRuntimeRequest,
        ) -> Result<PreparedProviderProcess, ProviderRuntimeDenial> {
            if policy.no_shell_by_default && request.use_shell {
                return Err(denial(
                    ProviderRuntimeDenialKind::ShellDenied,
                    "shell execution is disabled by default",
                ));
            }

            let cwd_root = policy
                .cwd_root
                .canonicalize()
                .unwrap_or_else(|_| normalize_path(&policy.cwd_root));
            let cwd = request
                .cwd
                .canonicalize()
                .unwrap_or_else(|_| normalize_path(&request.cwd));
            if !cwd.starts_with(&cwd_root) {
                return Err(denial(
                    ProviderRuntimeDenialKind::CwdEscape,
                    "provider cwd escapes the configured runtime root",
                ));
            }

            if policy.scrub_environment && request.inherit_parent_env {
                return Err(denial(
                    ProviderRuntimeDenialKind::EnvInheritanceDenied,
                    "provider cannot inherit the parent process environment",
                ));
            }

            if let Some(env_name) = request
                .env
                .keys()
                .find(|name| !policy.allowed_env.contains(*name))
            {
                return Err(denial(
                    ProviderRuntimeDenialKind::EnvNotAllowed,
                    format!("environment variable {env_name} is not allowlisted"),
                ));
            }

            match &policy.network_policy {
                NetworkPolicy::DenyAll if !request.network_hosts.is_empty() => {
                    return Err(denial(
                        ProviderRuntimeDenialKind::NetworkDenied,
                        "provider network access is denied",
                    ));
                }
                NetworkPolicy::AllowHosts(hosts)
                    if !request
                        .network_hosts
                        .iter()
                        .all(|host| hosts.contains(host)) =>
                {
                    return Err(denial(
                        ProviderRuntimeDenialKind::NetworkDenied,
                        "provider requested a non-allowlisted network host",
                    ));
                }
                NetworkPolicy::DenyAll | NetworkPolicy::AllowHosts(_) => {}
            }

            if request.timeout_ms > policy.max_timeout_ms {
                return Err(denial(
                    ProviderRuntimeDenialKind::TimeoutTooLarge,
                    "provider timeout exceeds runtime policy",
                ));
            }

            if request.stdout_limit_bytes > policy.max_stdout_bytes
                || request.stderr_limit_bytes > policy.max_stderr_bytes
            {
                return Err(denial(
                    ProviderRuntimeDenialKind::OutputLimitTooLarge,
                    "provider output limit exceeds runtime policy",
                ));
            }

            Ok(PreparedProviderProcess {
                executable: request.executable.clone(),
                args: request.args.clone(),
                cwd,
                env: request.env.clone(),
                network_hosts: request.network_hosts.clone(),
                timeout_ms: request.timeout_ms,
                stdout_limit_bytes: request.stdout_limit_bytes,
                stderr_limit_bytes: request.stderr_limit_bytes,
                kill_process_tree_on_timeout: policy.kill_process_tree_on_timeout,
                side_effect_executed: false,
            })
        }
    }

    fn denial(kind: ProviderRuntimeDenialKind, reason: impl Into<String>) -> ProviderRuntimeDenial {
        ProviderRuntimeDenial {
            kind,
            reason: reason.into(),
            side_effect_executed: false,
        }
    }

    fn normalize_host(host: &str) -> String {
        host.trim().trim_end_matches('.').to_ascii_lowercase()
    }

    fn normalize_path(path: &Path) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
                Component::RootDir => normalized.push(component.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    normalized.pop();
                }
                Component::Normal(part) => normalized.push(part),
            }
        }
        if normalized.as_os_str().is_empty() && path.is_relative() {
            env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
        } else {
            normalized
        }
    }
}

pub mod input {
    use std::collections::{BTreeSet, VecDeque};

    use base64::Engine as _;
    use serde::Serialize;
    use unicode_normalization::UnicodeNormalization;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
    pub enum InputSource {
        SystemPrompt,
        UserPrompt,
        AssistantMessage,
        Webpage,
        HttpResponse,
        DocumentAttachment,
        RetrievedKnowledge,
        MemoryEntry,
        ToolInput,
        ToolOutput,
        ToolDescription,
        SkillDescription,
        PluginManifest,
        McpToolSchema,
        WorkflowDefinition,
        LogContent,
        SourceCodeComment,
        ConfigFile,
        ReportDraft,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct InputInspectPolicy {
        pub max_decode_candidates: usize,
        pub max_decoded_bytes: usize,
        pub max_preview_bytes: usize,
        pub max_decode_depth: usize,
    }

    impl Default for InputInspectPolicy {
        fn default() -> Self {
            Self {
                max_decode_candidates: 64,
                max_decoded_bytes: 64 * 1024,
                max_preview_bytes: 4096,
                max_decode_depth: 4,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct InputInspection {
        pub source: InputSource,
        pub invalid_utf8: bool,
        pub truncated: bool,
        pub decode_budget_exhausted: bool,
        pub normalized_segments: Vec<NormalizedSegment>,
        pub risks: Vec<InputRisk>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct NormalizedSegment {
        pub extraction: String,
        pub text: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct InputRisk {
        pub kind: InputRiskKind,
        pub evidence: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub enum InputRiskKind {
        DirectPromptInjection,
        IndirectPromptInjection,
        Jailbreak,
        ScopeMutation,
        PolicyOverride,
        ApprovalBypass,
        ToolMisuse,
        ToolDescriptionPoisoning,
        KnowledgePoisoning,
        MemoryPoisoning,
        CredentialExfiltrationInstruction,
        SchemaManipulation,
        ReportFabrication,
        UncitedClaim,
        TraceDeletion,
        AuditTampering,
        FalseComplianceClaim,
    }

    pub fn inspect_input(
        source: InputSource,
        bytes: &[u8],
        policy: InputInspectPolicy,
    ) -> InputInspection {
        let invalid_utf8 = std::str::from_utf8(bytes).is_err();
        let raw = String::from_utf8_lossy(bytes).into_owned();
        let mut queue = VecDeque::from([(String::from("raw"), raw, 0usize)]);
        let mut seen = BTreeSet::new();
        let mut normalized_segments = Vec::new();
        let mut risks = Vec::new();
        let mut truncated = false;
        let mut decode_budget_exhausted = false;
        let mut processed = 0usize;

        while let Some((extraction, text, depth)) = queue.pop_front() {
            if processed >= policy.max_decode_candidates {
                decode_budget_exhausted = true;
                break;
            }
            processed += 1;

            let mut normalized = normalize_text(&text);
            if normalized.len() > policy.max_decoded_bytes {
                normalized = truncate_to_bytes(&normalized, policy.max_decoded_bytes);
                truncated = true;
                decode_budget_exhausted = true;
            }

            let preview = if normalized.len() > policy.max_preview_bytes {
                truncated = true;
                truncate_to_bytes(&normalized, policy.max_preview_bytes)
            } else {
                normalized.clone()
            };

            push_segment(
                &mut normalized_segments,
                extraction.clone(),
                preview.clone(),
            );
            collect_risks(&preview, &mut risks);

            for (child_extraction, child) in extract_structured_segments(&normalized) {
                if seen.insert(format!("{child_extraction}:{child}")) {
                    queue.push_back((child_extraction, child, depth + 1));
                }
            }

            if depth >= policy.max_decode_depth {
                continue;
            }

            for (child_extraction, child) in decode_candidates(&normalized) {
                if seen.insert(format!("{child_extraction}:{child}")) {
                    queue.push_back((child_extraction, child, depth + 1));
                }
            }
        }

        InputInspection {
            source,
            invalid_utf8,
            truncated,
            decode_budget_exhausted,
            normalized_segments,
            risks,
        }
    }

    fn normalize_text(text: &str) -> String {
        text.nfkc()
            .filter(|ch| !is_zero_width(*ch))
            .map(fold_homoglyph)
            .collect()
    }

    fn is_zero_width(ch: char) -> bool {
        matches!(
            ch,
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
        )
    }

    fn fold_homoglyph(ch: char) -> char {
        match ch {
            '\u{0430}' => 'a',
            '\u{0435}' => 'e',
            '\u{043E}' => 'o',
            '\u{0440}' => 'p',
            '\u{0441}' => 'c',
            '\u{0445}' => 'x',
            _ => ch,
        }
    }

    fn push_segment(segments: &mut Vec<NormalizedSegment>, extraction: String, text: String) {
        if text.trim().is_empty() {
            return;
        }
        segments.push(NormalizedSegment { extraction, text });
    }

    fn extract_structured_segments(text: &str) -> Vec<(String, String)> {
        let mut segments = Vec::new();
        segments.extend(extract_between(text, "<!--", "-->", "html_comment"));
        segments.extend(extract_markdown_links(text));
        segments.extend(extract_markdown_code(text));
        segments.extend(extract_json_strings(text));
        segments.extend(extract_toml_strings(text));
        segments
    }

    fn extract_between(
        text: &str,
        start: &str,
        end: &str,
        extraction: &str,
    ) -> Vec<(String, String)> {
        let mut output = Vec::new();
        let mut rest = text;
        while let Some(start_idx) = rest.find(start) {
            let after_start = &rest[start_idx + start.len()..];
            let Some(end_idx) = after_start.find(end) else {
                break;
            };
            output.push((
                extraction.to_string(),
                after_start[..end_idx].trim().to_string(),
            ));
            rest = &after_start[end_idx + end.len()..];
        }
        output
    }

    fn extract_markdown_links(text: &str) -> Vec<(String, String)> {
        let mut output = Vec::new();
        let mut rest = text;
        while let Some(open_label) = rest.find('[') {
            let after_label = &rest[open_label + 1..];
            let Some(close_label) = after_label.find("](") else {
                break;
            };
            let after_target = &after_label[close_label + 2..];
            let Some(close_target) = after_target.find(')') else {
                break;
            };
            let label = &after_label[..close_label];
            let target = &after_target[..close_target];
            output.push((
                "markdown_link".to_string(),
                format!("{} {}", label.trim(), target.trim()),
            ));
            rest = &after_target[close_target + 1..];
        }
        output
    }

    fn extract_markdown_code(text: &str) -> Vec<(String, String)> {
        let mut output = Vec::new();
        let mut rest = text;
        while let Some(open) = rest.find("```") {
            let after_open = &rest[open + 3..];
            let content_start = after_open.find('\n').map_or(0, |idx| idx + 1);
            let after_lang = &after_open[content_start..];
            let Some(close) = after_lang.find("```") else {
                break;
            };
            output.push((
                "markdown_code".to_string(),
                after_lang[..close].trim().to_string(),
            ));
            rest = &after_lang[close + 3..];
        }
        output
    }

    fn extract_json_strings(text: &str) -> Vec<(String, String)> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
            return Vec::new();
        };

        let mut output = Vec::new();
        collect_json_strings(&value, &mut output);
        output
            .into_iter()
            .map(|text| ("json_string".to_string(), text))
            .collect()
    }

    fn collect_json_strings(value: &serde_json::Value, output: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) => output.push(text.clone()),
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_json_strings(item, output);
                }
            }
            serde_json::Value::Object(map) => {
                for value in map.values() {
                    collect_json_strings(value, output);
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }

    fn extract_toml_strings(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter_map(|line| {
                let (_, value) = line.split_once('=')?;
                let value = value.trim();
                if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                    Some((
                        "toml_string".to_string(),
                        value[1..value.len() - 1].to_string(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    fn decode_candidates(text: &str) -> Vec<(String, String)> {
        let mut candidates = Vec::new();

        if let Some(decoded) = percent_decode(text) {
            candidates.push(("percent_decode".to_string(), decoded));
        }

        let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
        if compact.len() >= 8
            && compact.len().is_multiple_of(4)
            && compact
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
            && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes())
        {
            candidates.push((
                "base64_decode".to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }

        candidates
    }

    fn percent_decode(text: &str) -> Option<String> {
        if !text.contains('%') {
            return None;
        }

        let mut bytes = Vec::with_capacity(text.len());
        let mut chars = text.as_bytes().iter().copied().peekable();
        while let Some(byte) = chars.next() {
            if byte == b'%' {
                let hi = chars.next()?;
                let lo = chars.next()?;
                let hex = [hi, lo];
                let value = u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?;
                bytes.push(value);
            } else {
                bytes.push(byte);
            }
        }

        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn collect_risks(text: &str, risks: &mut Vec<InputRisk>) {
        let lower = text.to_ascii_lowercase();
        let checks = [
            (
                InputRiskKind::PolicyOverride,
                ["ignore policy", "override policy", "bypass policy"].as_slice(),
            ),
            (
                InputRiskKind::TraceDeletion,
                ["delete trace", "remove trace", "erase trace"].as_slice(),
            ),
            (
                InputRiskKind::ApprovalBypass,
                ["approval bypass", "approve everything", "skip approval"].as_slice(),
            ),
            (
                InputRiskKind::UncitedClaim,
                ["uncited report", "uncited claim", "fabricate"].as_slice(),
            ),
            (
                InputRiskKind::CredentialExfiltrationInstruction,
                ["exfiltrate credential", "steal token", "dump secrets"].as_slice(),
            ),
            (
                InputRiskKind::ScopeMutation,
                ["expand scope", "change scope", "scope mutation"].as_slice(),
            ),
            (
                InputRiskKind::SchemaManipulation,
                ["schema manipulation", "change schema", "schema rug"].as_slice(),
            ),
            (
                InputRiskKind::AuditTampering,
                ["audit tamper", "hide audit", "rewrite audit"].as_slice(),
            ),
        ];

        for (kind, phrases) in checks {
            if phrases.iter().any(|phrase| lower.contains(phrase)) {
                push_risk(risks, kind, preview_evidence(text));
            }
        }
    }

    fn push_risk(risks: &mut Vec<InputRisk>, kind: InputRiskKind, evidence: String) {
        if risks
            .iter()
            .any(|risk| risk.kind == kind && risk.evidence == evidence)
        {
            return;
        }
        risks.push(InputRisk { kind, evidence });
    }

    fn preview_evidence(text: &str) -> String {
        truncate_to_bytes(text.trim(), 160)
    }

    fn truncate_to_bytes(text: &str, max_bytes: usize) -> String {
        if text.len() <= max_bytes {
            return text.to_string();
        }

        let mut end = max_bytes;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    }
}

pub mod evidence {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use runwarden_kernel::evidence::hex_sha256;
    use serde::Serialize;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EvidenceInspectPolicy {
        pub max_files: usize,
        pub max_file_bytes: u64,
        pub allowed_extensions: BTreeSet<String>,
    }

    impl Default for EvidenceInspectPolicy {
        fn default() -> Self {
            Self {
                max_files: 10_000,
                max_file_bytes: 16 * 1024 * 1024,
                allowed_extensions: BTreeSet::new(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct EvidenceInspection {
        pub root: PathBuf,
        pub files: Vec<EvidenceFile>,
        pub violations: Vec<EvidenceViolation>,
        pub truncated: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct EvidenceFile {
        pub relative_path: String,
        pub size_bytes: u64,
        pub sha256: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub struct EvidenceViolation {
        pub kind: EvidenceViolationKind,
        pub path: String,
        pub message: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub enum EvidenceViolationKind {
        FileCountLimit,
        FileTooLarge,
        ExtensionDenied,
        SymlinkEscape,
        RootEscape,
        ReadFailed,
    }

    pub fn inspect_evidence_root(
        root: &Path,
        policy: EvidenceInspectPolicy,
    ) -> std::io::Result<EvidenceInspection> {
        let canonical_root = root.canonicalize()?;
        let mut result = EvidenceInspection {
            root: canonical_root.clone(),
            files: Vec::new(),
            violations: Vec::new(),
            truncated: false,
        };

        let mut paths = Vec::new();
        collect_paths(root, &mut paths)?;
        paths.sort();

        for path in paths {
            inspect_path(&canonical_root, &path, &policy, &mut result);
        }

        Ok(result)
    }

    fn collect_paths(root: &Path, paths: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                collect_paths(&path, paths)?;
            } else {
                paths.push(path);
            }
        }
        Ok(())
    }

    fn inspect_path(
        canonical_root: &Path,
        path: &Path,
        policy: &EvidenceInspectPolicy,
        result: &mut EvidenceInspection,
    ) {
        let relative_path = path
            .strip_prefix(canonical_root)
            .or_else(|_| path.strip_prefix(canonical_root.parent().unwrap_or(canonical_root)))
            .map(format_path)
            .unwrap_or_else(|_| format_path(path));

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(err) => {
                result.violations.push(violation(
                    EvidenceViolationKind::ReadFailed,
                    relative_path,
                    format!("failed to read metadata: {err}"),
                ));
                return;
            }
        };

        if metadata.file_type().is_symlink() {
            result.violations.push(violation(
                EvidenceViolationKind::SymlinkEscape,
                relative_path,
                "symlinked evidence files are rejected before reading",
            ));
            return;
        }

        let canonical_path = match path.canonicalize() {
            Ok(canonical_path) => canonical_path,
            Err(err) => {
                result.violations.push(violation(
                    EvidenceViolationKind::ReadFailed,
                    relative_path,
                    format!("failed to canonicalize path: {err}"),
                ));
                return;
            }
        };

        if !canonical_path.starts_with(canonical_root) {
            result.violations.push(violation(
                EvidenceViolationKind::RootEscape,
                relative_path,
                "file path escapes evidence root",
            ));
            return;
        }

        if !extension_allowed(path, &policy.allowed_extensions) {
            result.violations.push(violation(
                EvidenceViolationKind::ExtensionDenied,
                relative_path.clone(),
                "file extension is not allowlisted",
            ));
            return;
        }

        let size_bytes = metadata.len();
        let too_large = size_bytes > policy.max_file_bytes;
        if too_large {
            result.violations.push(violation(
                EvidenceViolationKind::FileTooLarge,
                relative_path.clone(),
                "file exceeds evidence size limit",
            ));
        }

        if result.files.len() >= policy.max_files {
            result.truncated = true;
            result.violations.push(violation(
                EvidenceViolationKind::FileCountLimit,
                relative_path,
                "file count exceeds evidence index limit",
            ));
            return;
        }

        if too_large {
            return;
        }

        match fs::read(path) {
            Ok(bytes) => result.files.push(EvidenceFile {
                relative_path,
                size_bytes,
                sha256: Some(hex_sha256(&bytes)),
            }),
            Err(err) => result.violations.push(violation(
                EvidenceViolationKind::ReadFailed,
                relative_path,
                format!("failed to read file: {err}"),
            )),
        }
    }

    fn extension_allowed(path: &Path, allowed_extensions: &BTreeSet<String>) -> bool {
        if allowed_extensions.is_empty() {
            return true;
        }
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| allowed_extensions.contains(&extension.to_ascii_lowercase()))
            .unwrap_or(false)
    }

    fn violation(
        kind: EvidenceViolationKind,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> EvidenceViolation {
        EvidenceViolation {
            kind,
            path: path.into(),
            message: message.into(),
        }
    }

    fn format_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }
}

pub mod external {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use std::time::{Duration, Instant};

    use runwarden_kernel::{
        ProviderClass, ProviderContract, ProviderKind, ProviderManifest, ProviderRisk,
        SideEffectKind,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};

    use super::runtime::{
        ProviderRuntime, ProviderRuntimeDenialKind, ProviderRuntimePolicy, ProviderRuntimeRequest,
    };

    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct ExternalProviderCertReport {
        pub passed: bool,
        pub findings: Vec<String>,
        pub contract: ProviderContract,
        pub side_effect_executed: bool,
    }

    pub fn load_provider_manifest(input: &str) -> serde_json::Result<ProviderManifest> {
        serde_json::from_str(input)
    }

    #[derive(Debug, Clone, PartialEq, Deserialize)]
    pub struct ExternalMcpAdapterRequest {
        #[serde(default)]
        pub manifest_path: Option<PathBuf>,
        #[serde(default)]
        pub transport: Option<String>,
        #[serde(default)]
        pub command: Option<String>,
        #[serde(default)]
        pub args: Vec<String>,
        #[serde(default)]
        pub cwd: Option<PathBuf>,
        #[serde(default)]
        pub url: Option<String>,
        #[serde(default)]
        pub headers: BTreeMap<String, String>,
        #[serde(default)]
        pub timeout_ms: Option<u64>,
        #[serde(default)]
        pub stdout_limit_bytes: Option<usize>,
        #[serde(default)]
        pub stderr_limit_bytes: Option<usize>,
        #[serde(default)]
        pub request: Value,
    }

    impl Default for ExternalMcpAdapterRequest {
        fn default() -> Self {
            Self {
                manifest_path: None,
                transport: None,
                command: None,
                args: Vec::new(),
                cwd: None,
                url: None,
                headers: BTreeMap::new(),
                timeout_ms: None,
                stdout_limit_bytes: None,
                stderr_limit_bytes: None,
                request: Value::Null,
            }
        }
    }

    pub fn execute_external_mcp_adapter(
        manifest: &ProviderManifest,
        request: &ExternalMcpAdapterRequest,
        runtime_root: Option<&Path>,
    ) -> Value {
        if manifest.provider_class != ProviderClass::External || manifest.kind != ProviderKind::Mcp
        {
            return adapter_denial(
                &manifest.provider_id,
                request.transport.as_deref().unwrap_or("unknown"),
                "provider_not_allowed",
                "external MCP adapter execution requires an external MCP provider manifest",
            );
        }

        let transport = request
            .transport
            .as_deref()
            .or(manifest.transport.as_deref())
            .unwrap_or("stdio");

        match transport {
            "stdio" => execute_stdio(manifest, request, runtime_root),
            "http" => execute_http(manifest, request, "http"),
            "https" => adapter_denial(
                &manifest.provider_id,
                "https",
                "egress_denied",
                "https MCP adapter execution requires a trusted HTTP client adapter",
            ),
            "sse" => execute_sse(manifest, request),
            other => adapter_denial(
                &manifest.provider_id,
                other,
                "provider_not_allowed",
                "unsupported external MCP transport",
            ),
        }
    }

    fn execute_stdio(
        manifest: &ProviderManifest,
        request: &ExternalMcpAdapterRequest,
        runtime_root: Option<&Path>,
    ) -> Value {
        let transport = "stdio";
        let Some(command) = request.command.as_deref() else {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "argument_schema_invalid",
                "stdio MCP adapter requires a command",
            );
        };
        if !command_is_allowlisted(command, &manifest.command_allowlist) {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "provider_not_allowed",
                "stdio MCP adapter command is not allowlisted by the provider manifest",
            );
        }
        if stdio_requires_unsupported_egress_controls(manifest) {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "egress_denied",
                "stdio MCP adapter execution cannot enforce network egress or credential policies",
            );
        }

        let cwd = request
            .cwd
            .clone()
            .or_else(|| manifest.working_root.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("."));
        let root = runtime_root
            .map(Path::to_path_buf)
            .or_else(|| manifest.working_root.as_ref().map(PathBuf::from))
            .unwrap_or_else(|| cwd.clone());
        let policy = ProviderRuntimePolicy::locked_to_root(root);
        let mut runtime_request = ProviderRuntimeRequest::new(command).cwd(cwd);
        for arg in &request.args {
            runtime_request = runtime_request.arg(arg.clone());
        }
        if let Some(timeout_ms) = request.timeout_ms {
            runtime_request = runtime_request.timeout_ms(timeout_ms);
        }
        if let Some(stdout_limit_bytes) = request.stdout_limit_bytes {
            runtime_request = runtime_request.stdout_limit_bytes(stdout_limit_bytes);
        }
        if let Some(stderr_limit_bytes) = request.stderr_limit_bytes {
            runtime_request = runtime_request.stderr_limit_bytes(stderr_limit_bytes);
        }

        let prepared = match ProviderRuntime::prepare(&policy, &runtime_request) {
            Ok(prepared) => prepared,
            Err(denial) => {
                return json!({
                    "provider": manifest.provider_id,
                    "transport": transport,
                    "decision": "denied",
                    "execution_status": "not_executed",
                    "error_kind": runtime_denial_error_kind(&denial.kind),
                    "reason": denial.reason,
                    "side_effect_executed": denial.side_effect_executed
                });
            }
        };

        let body = jsonrpc_request(manifest, request);
        let frame = content_length_frame(&body);
        let mut child = match Command::new(&prepared.executable)
            .args(&prepared.args)
            .current_dir(&prepared.cwd)
            .env_clear()
            .envs(&prepared.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) => {
                return adapter_failure(
                    &manifest.provider_id,
                    transport,
                    format!("failed to spawn stdio MCP adapter: {err}"),
                    false,
                );
            }
        };

        match child.stdin.take() {
            Some(mut stdin) => {
                if let Err(err) = stdin.write_all(frame.as_bytes()) {
                    let _ = child.kill();
                    return adapter_failure(
                        &manifest.provider_id,
                        transport,
                        format!("failed to write MCP frame to adapter stdin: {err}"),
                        true,
                    );
                }
            }
            None => {
                let _ = child.kill();
                return adapter_failure(
                    &manifest.provider_id,
                    transport,
                    "failed to open adapter stdin",
                    true,
                );
            }
        }

        match wait_with_limited_output(
            &mut child,
            prepared.timeout_ms,
            prepared.stdout_limit_bytes,
            prepared.stderr_limit_bytes,
        ) {
            Ok(output) => json!({
                "provider": manifest.provider_id,
                "transport": transport,
                "decision": "allowed",
                "execution_status": if output.status.success() { "completed" } else { "failed" },
                "exit_status": output.status.code(),
                "stdout": bounded_utf8(&output.stdout, prepared.stdout_limit_bytes),
                "stderr": bounded_utf8(&output.stderr, prepared.stderr_limit_bytes),
                "side_effect_executed": true
            }),
            Err(err) => adapter_failure(
                &manifest.provider_id,
                transport,
                format!("failed to wait for stdio MCP adapter: {err}"),
                true,
            ),
        }
    }

    fn execute_http(
        manifest: &ProviderManifest,
        request: &ExternalMcpAdapterRequest,
        transport: &str,
    ) -> Value {
        let Some(url) = request.url.as_deref() else {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "argument_schema_invalid",
                "HTTP MCP adapter requires a url",
            );
        };
        let parsed = match parse_http_url(url) {
            Ok(parsed) => parsed,
            Err(reason) => {
                return adapter_denial(&manifest.provider_id, transport, "egress_denied", reason);
            }
        };
        if !origin_allowed(&parsed.origin, &manifest.allowed_origins) {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "egress_denied",
                "HTTP MCP adapter origin is not allowlisted by the provider manifest",
            );
        }

        let body = serde_json::to_vec(&jsonrpc_request(manifest, request))
            .expect("MCP request serializes");
        let mut header_lines = String::new();
        for (name, value) in &request.headers {
            if safe_header_name(name) && safe_header_value(value) {
                header_lines.push_str(name);
                header_lines.push_str(": ");
                header_lines.push_str(value);
                header_lines.push_str("\r\n");
            }
        }
        let request_text = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
            parsed.path_and_query,
            parsed.host_header,
            body.len(),
            header_lines
        );

        let timeout = match http_timeout(request) {
            Ok(timeout) => timeout,
            Err(reason) => {
                return adapter_denial(&manifest.provider_id, transport, "budget_exceeded", reason);
            }
        };
        let response = match send_http_request(
            &parsed,
            &request_text,
            &body,
            timeout,
            http_response_limit_bytes(request),
        ) {
            Ok(response) => response,
            Err(reason) => {
                return adapter_failure(&manifest.provider_id, transport, reason, true);
            }
        };
        json!({
            "provider": manifest.provider_id,
            "transport": transport,
            "decision": "allowed",
            "execution_status": if (200..300).contains(&response.status) { "completed" } else { "failed" },
            "http_status": response.status,
            "body": response.body,
            "side_effect_executed": true
        })
    }

    fn execute_sse(manifest: &ProviderManifest, request: &ExternalMcpAdapterRequest) -> Value {
        let transport = "sse";
        let Some(url) = request.url.as_deref() else {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "argument_schema_invalid",
                "SSE MCP adapter requires a url",
            );
        };
        let parsed = match parse_http_url(url) {
            Ok(parsed) => parsed,
            Err(reason) => {
                return adapter_denial(&manifest.provider_id, transport, "egress_denied", reason);
            }
        };
        if !origin_allowed(&parsed.origin, &manifest.allowed_origins) {
            return adapter_denial(
                &manifest.provider_id,
                transport,
                "egress_denied",
                "SSE MCP adapter origin is not allowlisted by the provider manifest",
            );
        }

        let request_text = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
            parsed.path_and_query, parsed.host_header
        );
        let timeout = match http_timeout(request) {
            Ok(timeout) => timeout,
            Err(reason) => {
                return adapter_denial(&manifest.provider_id, transport, "budget_exceeded", reason);
            }
        };
        let response = match send_http_request(
            &parsed,
            &request_text,
            &[],
            timeout,
            http_response_limit_bytes(request),
        ) {
            Ok(response) => response,
            Err(reason) => {
                return adapter_failure(&manifest.provider_id, transport, reason, true);
            }
        };
        let event = response
            .body
            .lines()
            .find_map(|line| line.strip_prefix("data:").map(str::trim))
            .unwrap_or_default()
            .to_string();
        json!({
            "provider": manifest.provider_id,
            "transport": transport,
            "decision": "allowed",
            "execution_status": if (200..300).contains(&response.status) && !event.is_empty() { "completed" } else { "failed" },
            "http_status": response.status,
            "event": event,
            "side_effect_executed": true
        })
    }

    pub fn certify_external_provider_manifest(
        manifest: &ProviderManifest,
    ) -> ExternalProviderCertReport {
        let contract = ProviderContract::from_manifest(manifest);
        let mut findings = Vec::new();

        if manifest.provider_class != ProviderClass::External {
            findings.push("provider_class_must_be_external".to_string());
        }
        if !manifest.provider_id.starts_with("external.") {
            findings.push("external_provider_id_prefix_required".to_string());
        }
        if manifest.schema_pin.algorithm != "sha256" {
            findings.push("schema_pin_algorithm_unsupported".to_string());
        }
        if manifest.schema_pin.digest
            != runwarden_kernel::schema_digest(&manifest.schema_pin.schema)
        {
            findings.push("schema_pin_digest_mismatch".to_string());
        }
        if contract.schema_rug_pull_detected {
            findings.push("schema_rug_pull".to_string());
        }
        if manifest.declared_permissions.is_empty() {
            findings.push("declared_permissions_required".to_string());
        }

        match manifest.kind {
            ProviderKind::Mcp => certify_mcp_manifest(manifest, &mut findings),
            ProviderKind::Shell => certify_shell_manifest(manifest, &mut findings),
            ProviderKind::Plugin | ProviderKind::Skill => {
                if manifest.tool_identity.is_none() {
                    findings.push("tool_identity_required".to_string());
                }
            }
            ProviderKind::Api | ProviderKind::Scanner | ProviderKind::Enterprise => {
                if manifest.allowed_origins.is_empty() {
                    findings.push("egress_policy_required".to_string());
                }
            }
            _ => findings.push("external_provider_kind_not_supported".to_string()),
        }

        if requires_egress(manifest) && manifest.allowed_origins.is_empty() {
            findings.push("egress_policy_required".to_string());
        }

        ExternalProviderCertReport {
            passed: findings.is_empty(),
            findings,
            contract,
            side_effect_executed: false,
        }
    }

    fn certify_mcp_manifest(manifest: &ProviderManifest, findings: &mut Vec<String>) {
        match manifest.transport.as_deref() {
            Some("stdio" | "http" | "sse" | "https") => {}
            _ => findings.push("mcp_transport_required".to_string()),
        }
        if manifest.downstream_identity.is_none() {
            findings.push("downstream_identity_required".to_string());
        }
        if manifest.tool_identity.is_none() {
            findings.push("tool_identity_required".to_string());
        }
    }

    fn certify_shell_manifest(manifest: &ProviderManifest, findings: &mut Vec<String>) {
        if manifest.command_allowlist.is_empty() {
            findings.push("shell_command_allowlist_required".to_string());
        }
        if manifest.working_root.is_none() {
            findings.push("shell_working_root_required".to_string());
        }
        if manifest.risk == ProviderRisk::Destructive
            && !manifest.side_effects.contains(&SideEffectKind::Destructive)
        {
            findings.push("destructive_side_effect_required".to_string());
        }
    }

    fn requires_egress(manifest: &ProviderManifest) -> bool {
        matches!(
            manifest.risk,
            ProviderRisk::NetworkActive | ProviderRisk::CredentialUse
        ) || manifest.side_effects.contains(&SideEffectKind::Network)
    }

    fn stdio_requires_unsupported_egress_controls(manifest: &ProviderManifest) -> bool {
        requires_egress(manifest)
            || manifest
                .side_effects
                .contains(&SideEffectKind::CredentialUse)
            || !manifest.allowed_origins.is_empty()
    }

    fn command_is_allowlisted(command: &str, allowlist: &[String]) -> bool {
        allowlist.iter().any(|allowed| allowed == command)
    }

    fn jsonrpc_request(manifest: &ProviderManifest, request: &ExternalMcpAdapterRequest) -> Value {
        if !request.request.is_null() {
            return request.request.clone();
        }
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": manifest.tool_identity.as_deref().unwrap_or("call"),
            "params": {}
        })
    }

    fn content_length_frame(value: &Value) -> String {
        let body = serde_json::to_string(value).expect("MCP request serializes");
        format!("Content-Length: {}\r\n\r\n{}", body.len(), body)
    }

    fn bounded_utf8(bytes: &[u8], limit: usize) -> String {
        let end = bytes.len().min(limit);
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    struct StdioOutput {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    fn wait_with_limited_output(
        child: &mut std::process::Child,
        timeout_ms: u64,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Result<StdioOutput, String> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "failed to open adapter stdout".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "failed to open adapter stderr".to_string())?;
        let output_exceeded = Arc::new(AtomicBool::new(false));
        let stdout_handle = read_limited_pipe(stdout, stdout_limit, output_exceeded.clone());
        let stderr_handle = read_limited_pipe(stderr, stderr_limit, output_exceeded.clone());
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let status = loop {
            if output_exceeded.load(Ordering::SeqCst) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("stdio MCP adapter exceeded output limit".to_string());
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|err| format!("failed to poll stdio MCP adapter: {err}"))?
            {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("stdio MCP adapter timed out".to_string());
            }
            thread::sleep(Duration::from_millis(10));
        };

        let stdout = stdout_handle
            .join()
            .map_err(|_| "failed to join stdout reader".to_string())?;
        let stderr = stderr_handle
            .join()
            .map_err(|_| "failed to join stderr reader".to_string())?;
        if output_exceeded.load(Ordering::SeqCst) {
            return Err("stdio MCP adapter exceeded output limit".to_string());
        }
        Ok(StdioOutput {
            status,
            stdout,
            stderr,
        })
    }

    fn read_limited_pipe<R: Read + Send + 'static>(
        mut reader: R,
        limit: usize,
        output_exceeded: Arc<AtomicBool>,
    ) -> thread::JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        let remaining = limit.saturating_sub(output.len());
                        if read > remaining {
                            output.extend_from_slice(&buffer[..remaining]);
                            output_exceeded.store(true, Ordering::SeqCst);
                            break;
                        }
                        output.extend_from_slice(&buffer[..read]);
                    }
                    Err(_) => break,
                }
            }
            output
        })
    }

    fn adapter_denial(
        provider: &str,
        transport: &str,
        error_kind: &str,
        reason: impl Into<String>,
    ) -> Value {
        json!({
            "provider": provider,
            "transport": transport,
            "decision": "denied",
            "execution_status": "not_executed",
            "error_kind": error_kind,
            "reason": reason.into(),
            "side_effect_executed": false
        })
    }

    fn adapter_failure(
        provider: &str,
        transport: &str,
        reason: impl Into<String>,
        side_effect_executed: bool,
    ) -> Value {
        json!({
            "provider": provider,
            "transport": transport,
            "decision": "allowed",
            "execution_status": "failed",
            "reason": reason.into(),
            "side_effect_executed": side_effect_executed
        })
    }

    fn runtime_denial_error_kind(kind: &ProviderRuntimeDenialKind) -> &'static str {
        match kind {
            ProviderRuntimeDenialKind::ShellDenied => "provider_not_allowed",
            ProviderRuntimeDenialKind::CwdEscape => "root_escape",
            ProviderRuntimeDenialKind::EnvInheritanceDenied
            | ProviderRuntimeDenialKind::EnvNotAllowed => "scope_violation",
            ProviderRuntimeDenialKind::NetworkDenied => "egress_denied",
            ProviderRuntimeDenialKind::TimeoutTooLarge
            | ProviderRuntimeDenialKind::OutputLimitTooLarge => "budget_exceeded",
        }
    }

    struct ParsedHttpUrl {
        origin: String,
        host_header: String,
        socket_addr: String,
        path_and_query: String,
    }

    fn parse_http_url(url: &str) -> Result<ParsedHttpUrl, String> {
        let Some(rest) = url.strip_prefix("http://") else {
            return Err(
                "only http:// MCP adapter URLs are supported by this local executor".into(),
            );
        };
        let (authority, path_and_query) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err("HTTP MCP adapter URL authority is invalid".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| "HTTP MCP adapter URL port is invalid".to_string())?;
                (host.to_string(), port)
            }
            _ => (authority.to_string(), 80),
        };
        let host_header = if port == 80 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        Ok(ParsedHttpUrl {
            origin: format!("http://{host_header}"),
            socket_addr: format!("{host}:{port}"),
            host_header,
            path_and_query,
        })
    }

    fn origin_allowed(origin: &str, allowed_origins: &[String]) -> bool {
        allowed_origins.iter().any(|allowed| allowed == origin)
    }

    fn safe_header_name(name: &str) -> bool {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-'))
    }

    fn safe_header_value(value: &str) -> bool {
        !value.contains('\r') && !value.contains('\n')
    }

    struct HttpResponse {
        status: u16,
        body: String,
    }

    fn http_response_limit_bytes(request: &ExternalMcpAdapterRequest) -> usize {
        const DEFAULT_HTTP_RESPONSE_LIMIT_BYTES: usize = 65_536;
        const MAX_HTTP_RESPONSE_LIMIT_BYTES: usize = 1_048_576;

        request
            .stdout_limit_bytes
            .unwrap_or(DEFAULT_HTTP_RESPONSE_LIMIT_BYTES)
            .min(MAX_HTTP_RESPONSE_LIMIT_BYTES)
    }

    fn http_timeout(request: &ExternalMcpAdapterRequest) -> Result<Duration, String> {
        let timeout_ms = request.timeout_ms.unwrap_or(5_000);
        let max_timeout_ms = ProviderRuntimePolicy::default().max_timeout_ms;
        if timeout_ms > max_timeout_ms {
            return Err("HTTP MCP adapter timeout exceeds runtime policy".to_string());
        }
        Ok(Duration::from_millis(timeout_ms))
    }

    fn send_http_request(
        parsed: &ParsedHttpUrl,
        request_text: &str,
        body: &[u8],
        timeout: Duration,
        response_limit_bytes: usize,
    ) -> Result<HttpResponse, String> {
        let socket_addr = parsed
            .socket_addr
            .to_socket_addrs()
            .map_err(|err| format!("failed to resolve MCP adapter URL: {err}"))?
            .next()
            .ok_or_else(|| "failed to resolve MCP adapter URL".to_string())?;
        let mut stream = TcpStream::connect_timeout(&socket_addr, timeout)
            .map_err(|err| format!("failed to connect to MCP adapter: {err}"))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| format!("failed to set MCP adapter read timeout: {err}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| format!("failed to set MCP adapter write timeout: {err}"))?;
        stream
            .write_all(request_text.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|err| format!("failed to write MCP adapter HTTP request: {err}"))?;
        let mut response = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = stream
                .read(&mut buffer)
                .map_err(|err| format!("failed to read MCP adapter HTTP response: {err}"))?;
            if read == 0 {
                break;
            }
            if response.len().saturating_add(read) > response_limit_bytes {
                return Err("MCP adapter HTTP response exceeded output limit".to_string());
            }
            response.extend_from_slice(&buffer[..read]);
        }
        parse_http_response(&response)
    }

    fn parse_http_response(response: &[u8]) -> Result<HttpResponse, String> {
        let response = String::from_utf8_lossy(response);
        let (head, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| "MCP adapter HTTP response is malformed".to_string())?;
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or_else(|| "MCP adapter HTTP status is malformed".to_string())?;
        Ok(HttpResponse {
            status,
            body: body.to_string(),
        })
    }
}

pub mod catalog {
    use runwarden_kernel::kernel::ProviderRegistry;
    use runwarden_kernel::{
        KernelProvider, ProviderClass, ProviderContract, ProviderKind, ProviderManifest,
        ProviderRisk, ProviderSchemaPin, SideEffectKind,
    };
    use serde_json::{Value, json};

    pub const FIRST_PARTY_PROVIDER_IDS: &[&str] = &[
        "runwarden.input.inspect",
        "runwarden.evidence.inspect",
        "runwarden.trace.verify",
        "runwarden.trace.export",
        "runwarden.report.scaffold",
        "runwarden.report.lint",
        "runwarden.report.render",
        "runwarden.audit.summary",
        "runwarden.accountability.summary",
        "runwarden.cert.all",
        "runwarden.eval.all",
        "runwarden.eval.agent-native",
        "runwarden.bench.run",
    ];

    pub const EXTERNAL_PROVIDER_IDS: &[&str] = &[
        "external.mcp.browser.open_page",
        "external.mcp.filesystem.read_file",
        "external.mcp.api.request",
        "external.mcp.scanner.run",
        "external.shell.command",
        "external.plugin.security_scan",
        "external.skill.assessment_helper",
        "external.enterprise.ticket_lookup",
    ];

    pub fn default_first_party_providers() -> Vec<KernelProvider> {
        vec![
            provider(
                "runwarden.input.inspect",
                ProviderKind::Input,
                ProviderRisk::Low,
                vec![SideEffectKind::FileRead],
                "normalize and inspect bounded user-controlled input",
            ),
            provider(
                "runwarden.evidence.inspect",
                ProviderKind::Evidence,
                ProviderRisk::Low,
                vec![SideEffectKind::FileRead],
                "index and inspect bounded evidence roots",
            ),
            provider(
                "runwarden.trace.verify",
                ProviderKind::Trace,
                ProviderRisk::Low,
                vec![SideEffectKind::None],
                "verify trace hash-chain integrity",
            ),
            provider(
                "runwarden.trace.export",
                ProviderKind::Trace,
                ProviderRisk::Low,
                vec![SideEffectKind::ArtifactWrite],
                "export verified trace evidence",
            ),
            provider(
                "runwarden.report.scaffold",
                ProviderKind::Report,
                ProviderRisk::Low,
                vec![SideEffectKind::None],
                "scaffold a draft report from verified trace observations",
            ),
            provider(
                "runwarden.report.lint",
                ProviderKind::Report,
                ProviderRisk::Low,
                vec![SideEffectKind::None],
                "reject uncited or drifting report claims",
            ),
            provider(
                "runwarden.report.render",
                ProviderKind::Report,
                ProviderRisk::ReportClaim,
                vec![SideEffectKind::ArtifactWrite],
                "render cited reports into submission formats",
            ),
            provider(
                "runwarden.audit.summary",
                ProviderKind::Audit,
                ProviderRisk::Low,
                vec![SideEffectKind::None],
                "summarize allowed, denied, and failed decisions from trace",
            ),
            provider(
                "runwarden.accountability.summary",
                ProviderKind::Accountability,
                ProviderRisk::Low,
                vec![SideEffectKind::None],
                "derive requester, agent, reviewer, authz, and report responsibility chain",
            ),
            provider(
                "runwarden.cert.all",
                ProviderKind::Cert,
                ProviderRisk::ReportClaim,
                vec![SideEffectKind::ArtifactWrite],
                "certify agent config, manifests, MCP, scripts, packages, and release artifacts",
            ),
            provider(
                "runwarden.eval.all",
                ProviderKind::Eval,
                ProviderRisk::Medium,
                vec![SideEffectKind::None],
                "run policy, prompt-injection, scope, authz, trace, and report evaluations",
            ),
            provider(
                "runwarden.eval.agent-native",
                ProviderKind::Eval,
                ProviderRisk::Medium,
                vec![SideEffectKind::None],
                "prove agent configuration exposes Runwarden only and blocks raw tool exposure",
            ),
            provider(
                "runwarden.bench.run",
                ProviderKind::Bench,
                ProviderRisk::Medium,
                vec![SideEffectKind::None],
                "measure scenario pass rate and policy-denial correctness",
            ),
        ]
    }

    pub fn first_party_registry() -> ProviderRegistry {
        let mut registry = ProviderRegistry::default();
        for provider in default_first_party_providers() {
            registry.register(provider);
        }
        registry
    }

    pub fn default_external_providers() -> Vec<KernelProvider> {
        default_external_specs()
            .into_iter()
            .map(external_provider)
            .collect()
    }

    pub fn default_external_provider_manifests() -> Vec<ProviderManifest> {
        default_external_specs()
            .into_iter()
            .map(external_provider_manifest)
            .collect()
    }

    pub fn default_external_provider_manifest(provider_id: &str) -> Option<ProviderManifest> {
        default_external_provider_manifests()
            .into_iter()
            .find(|manifest| manifest.provider_id == provider_id)
    }

    fn default_external_specs() -> Vec<ExternalProviderSpec> {
        vec![
            ExternalProviderSpec {
                id: "external.mcp.browser.open_page",
                kind: ProviderKind::Mcp,
                risk: ProviderRisk::NetworkActive,
                side_effects: vec![SideEffectKind::Network],
                transport: "stdio",
                downstream_identity: "browser-mcp",
                tool_identity: "open_page",
                declared_permissions: vec!["network"],
                allowed_origins: vec!["https://example.com"],
            },
            ExternalProviderSpec {
                id: "external.mcp.filesystem.read_file",
                kind: ProviderKind::Mcp,
                risk: ProviderRisk::High,
                side_effects: vec![SideEffectKind::FileRead],
                transport: "stdio",
                downstream_identity: "filesystem-mcp",
                tool_identity: "read_file",
                declared_permissions: vec!["file_read"],
                allowed_origins: vec![],
            },
            ExternalProviderSpec {
                id: "external.mcp.api.request",
                kind: ProviderKind::Api,
                risk: ProviderRisk::NetworkActive,
                side_effects: vec![SideEffectKind::Network],
                transport: "https",
                downstream_identity: "api-mcp",
                tool_identity: "request",
                declared_permissions: vec!["network"],
                allowed_origins: vec!["https://api.example.com"],
            },
            ExternalProviderSpec {
                id: "external.mcp.scanner.run",
                kind: ProviderKind::Scanner,
                risk: ProviderRisk::High,
                side_effects: vec![SideEffectKind::FileRead],
                transport: "stdio",
                downstream_identity: "scanner-mcp",
                tool_identity: "run",
                declared_permissions: vec!["file_read"],
                allowed_origins: vec![],
            },
            ExternalProviderSpec {
                id: "external.shell.command",
                kind: ProviderKind::Shell,
                risk: ProviderRisk::Destructive,
                side_effects: vec![SideEffectKind::ProcessSpawn, SideEffectKind::Destructive],
                transport: "stdio",
                downstream_identity: "local-shell",
                tool_identity: "command",
                declared_permissions: vec!["process_spawn"],
                allowed_origins: vec![],
            },
            ExternalProviderSpec {
                id: "external.plugin.security_scan",
                kind: ProviderKind::Plugin,
                risk: ProviderRisk::High,
                side_effects: vec![SideEffectKind::FileRead],
                transport: "stdio",
                downstream_identity: "security-plugin",
                tool_identity: "scan",
                declared_permissions: vec!["file_read"],
                allowed_origins: vec![],
            },
            ExternalProviderSpec {
                id: "external.skill.assessment_helper",
                kind: ProviderKind::Skill,
                risk: ProviderRisk::Medium,
                side_effects: vec![SideEffectKind::None],
                transport: "stdio",
                downstream_identity: "assessment-skill",
                tool_identity: "run",
                declared_permissions: vec!["analysis"],
                allowed_origins: vec![],
            },
            ExternalProviderSpec {
                id: "external.enterprise.ticket_lookup",
                kind: ProviderKind::Enterprise,
                risk: ProviderRisk::CredentialUse,
                side_effects: vec![SideEffectKind::Network, SideEffectKind::CredentialUse],
                transport: "https",
                downstream_identity: "enterprise-ticketing",
                tool_identity: "lookup",
                declared_permissions: vec!["network", "credential_use"],
                allowed_origins: vec!["https://tickets.example.com"],
            },
        ]
    }

    pub fn full_provider_registry() -> ProviderRegistry {
        let mut registry = first_party_registry();
        for provider in default_external_providers() {
            registry.register(provider);
        }
        registry
    }

    fn provider(
        id: &str,
        kind: ProviderKind,
        risk: ProviderRisk,
        side_effects: Vec<SideEffectKind>,
        description: &str,
    ) -> KernelProvider {
        KernelProvider {
            id: id.to_string(),
            class: ProviderClass::FirstParty,
            kind,
            authority_requirements: authority_requirements(&risk, &side_effects),
            risk,
            side_effects,
            input_schema: object_schema(description),
            output_schema: object_schema("Runwarden provider outcome payload"),
            evidence_contract: json!({
                "description": description,
                "obs_refs_required": true
            }),
        }
    }

    struct ExternalProviderSpec {
        id: &'static str,
        kind: ProviderKind,
        risk: ProviderRisk,
        side_effects: Vec<SideEffectKind>,
        transport: &'static str,
        downstream_identity: &'static str,
        tool_identity: &'static str,
        declared_permissions: Vec<&'static str>,
        allowed_origins: Vec<&'static str>,
    }

    fn external_provider(spec: ExternalProviderSpec) -> KernelProvider {
        let manifest = external_provider_manifest(spec);
        ProviderContract::from_manifest(&manifest).provider
    }

    fn external_provider_manifest(spec: ExternalProviderSpec) -> ProviderManifest {
        let schema = json!({"type":"object"});
        ProviderManifest {
            schema_version: "1".to_string(),
            provider_id: spec.id.to_string(),
            provider_class: ProviderClass::External,
            kind: spec.kind,
            risk: spec.risk,
            side_effects: spec.side_effects,
            transport: Some(spec.transport.to_string()),
            downstream_identity: Some(spec.downstream_identity.to_string()),
            tool_identity: Some(spec.tool_identity.to_string()),
            declared_permissions: spec
                .declared_permissions
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            allowed_origins: spec
                .allowed_origins
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            command_allowlist: if spec.id == "external.shell.command" {
                vec!["git".to_string(), "cargo".to_string(), "pnpm".to_string()]
            } else {
                Vec::new()
            },
            working_root: if spec.id == "external.shell.command" {
                Some(".".to_string())
            } else {
                None
            },
            schema_pin: ProviderSchemaPin::new(schema.clone()),
            observed_schema: schema,
        }
    }

    fn object_schema(description: &str) -> Value {
        json!({
            "type": "object",
            "description": description,
            "additionalProperties": true
        })
    }

    fn authority_requirements(risk: &ProviderRisk, side_effects: &[SideEffectKind]) -> Value {
        let approval_required = matches!(
            risk,
            ProviderRisk::High
                | ProviderRisk::NetworkActive
                | ProviderRisk::FileWrite
                | ProviderRisk::CredentialUse
                | ProviderRisk::Destructive
                | ProviderRisk::ReportClaim
        ) || side_effects
            .iter()
            .any(|side_effect| matches!(side_effect, SideEffectKind::ArtifactWrite));

        json!({
            "authz_required": true,
            "approval_required": approval_required,
            "kernel_managed": true
        })
    }
}
