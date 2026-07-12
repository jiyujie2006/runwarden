use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use runwarden_kernel::resource::DataClass;
use runwarden_kernel::session::{
    AuthoritySnapshot, BudgetSnapshot, EmailAuthority, EvidenceAuthority, InputAuthority,
};
use runwarden_kernel::story::{
    EnforcementMode, EvidenceStatus, OperationId, RunMode, SchemaVersion, SecurityStory, SessionId,
    StoryIdentity, StoryProvenance, StoryStatus,
};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::executor::{DefaultProviderExecutor, ExecutorConfig, PermitAuthority};
use runwarden_runtime::{
    ApprovalWaitPolicy, McpRuntime, OperationRuntime, RuntimeContextLoader, RuntimeError,
    RuntimeRequest, RuntimeResponse, RuntimeStartup, SystemClock,
};
use runwarden_state::{DemoActivation, SessionRecord, StateStore};
use serde_json::Value;
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::{InvocationKeyDeriver, McpServer};

const DEFAULT_MAX_REQUEST_BYTES: usize = 1_048_576;
const OPENCODE_1_17_13_BUILTIN_TOOLS: &[&str] = &[
    "apply_patch",
    "bash",
    "edit",
    "glob",
    "grep",
    "list",
    "lsp",
    "question",
    "read",
    "skill",
    "todoread",
    "todowrite",
    "webfetch",
    "websearch",
    "write",
];

pub type ProductionRuntime = OperationRuntime<StateStore, DefaultProviderExecutor, SystemClock>;

struct CompatibilityRuntime {
    runtime: ProductionRuntime,
    _temp: tempfile::TempDir,
}

impl McpRuntime for CompatibilityRuntime {
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError> {
        self.runtime.invoke(request)
    }

    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        self.runtime.operation_status(operation_id)
    }

    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError> {
        self.runtime.resume(operation_id)
    }
}

pub(crate) fn handle_compatibility_jsonrpc(
    body: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    isolated_compatibility_server()?.handle_jsonrpc(body)
}

fn isolated_compatibility_server() -> anyhow::Result<McpServer<CompatibilityRuntime>> {
    let temp = tempfile::tempdir()?;
    let state_dir = temp.path().join("state");
    let sandbox_root = temp.path().join("sandbox");
    let trusted_runtime_root = temp.path().join("runtime");
    std::fs::create_dir_all(&sandbox_root)?;
    std::fs::create_dir_all(&trusted_runtime_root)?;

    let store = StateStore::open(&state_dir)?;
    let expires_at = OffsetDateTime::now_utc() + TimeDuration::hours(1);
    let story = compatibility_story(expires_at);
    store.create_story(&story)?;
    store.create_session(&SessionRecord {
        session_id: story.authority.session_id,
        story_id: story.story_id,
        authority: story.authority.clone(),
        policy_snapshot_hash: story.authority.policy_snapshot_hash.clone(),
        expires_at,
    })?;

    let instance_id = format!("mcp-compatibility-{}", OperationId::new());
    let instance_token =
        Zeroizing::new(format!("mcp-compatibility-token-{}", OperationId::new()).into_bytes());
    let now = OffsetDateTime::now_utc();
    store.activate_demo(&DemoActivation {
        instance_id: instance_id.clone(),
        story_id: story.story_id,
        session_id: story.authority.session_id,
        process_id: std::process::id(),
        host_id: "isolated-test-runtime".to_owned(),
        instance_token_hash: Sha256Digest::from_bytes(instance_token.as_slice())
            .as_str()
            .to_owned(),
        now,
    })?;
    let instance_token_text = std::str::from_utf8(instance_token.as_slice())?;
    let context = RuntimeContextLoader::load(&store, instance_token_text, now)?;
    let (issuer, verifier) = PermitAuthority::generate()?;
    let executor = DefaultProviderExecutor::new(ExecutorConfig::new(
        sandbox_root,
        trusted_runtime_root,
        256 * 1_024,
        Duration::from_secs(2),
        verifier,
    )?);
    let runtime = OperationRuntime::new(
        store,
        executor,
        SystemClock,
        context,
        issuer,
        format!("mcp-compatibility-lease-{}", OperationId::new()),
        ApprovalWaitPolicy::immediate(),
    )?;
    let invocation_keys = InvocationKeyDeriver::from_trusted_instance(instance_id, instance_token)?;
    Ok(McpServer::new(
        Arc::new(CompatibilityRuntime {
            runtime,
            _temp: temp,
        }),
        DEFAULT_MAX_REQUEST_BYTES,
        invocation_keys,
    ))
}

fn compatibility_story(expires_at: OffsetDateTime) -> SecurityStory {
    let session_id = SessionId::new();
    let policy_snapshot_hash = Sha256Digest::from_bytes(b"isolated-mcp-compatibility-policy")
        .as_str()
        .to_owned();
    SecurityStory {
        schema_version: SchemaVersion::current(),
        story_id: runwarden_kernel::story::StoryId::new(),
        title: "Isolated MCP compatibility runtime".to_owned(),
        scenario_id: "mcp-compatibility".to_owned(),
        attack_category: "protocol_test".to_owned(),
        run_mode: RunMode::Deterministic,
        enforcement_mode: EnforcementMode::Enforced,
        provenance: StoryProvenance::Native,
        status: StoryStatus::Running,
        evidence_status: EvidenceStatus::Pending,
        identity: StoryIdentity {
            agent_id: "mcp-compatibility-agent".to_owned(),
            model_id: "mcp-compatibility-model".to_owned(),
            actor_id: "mcp-compatibility-actor".to_owned(),
            reviewer_id: Some("mcp-compatibility-reviewer".to_owned()),
        },
        authority: AuthoritySnapshot {
            session_id,
            actor_id: "mcp-compatibility-actor".to_owned(),
            authz_id: "mcp-compatibility-authz".to_owned(),
            authz_state: "active".to_owned(),
            expires_at,
            allowed_providers: vec![
                "runwarden.input.inspect".to_owned(),
                "external.email.send".to_owned(),
            ],
            files: Vec::new(),
            networks: Vec::new(),
            email: Some(EmailAuthority {
                allowed_recipients: vec![
                    "judge@example.test".to_owned(),
                    "ops@example.com".to_owned(),
                ],
                maximum_classification: DataClass::Internal,
            }),
            stores: Vec::new(),
            code: None,
            inputs: vec![InputAuthority {
                allowed_sources: vec!["tool_input".to_owned()],
                maximum_classification: DataClass::Internal,
            }],
            evidence: EvidenceAuthority {
                current_story_only: true,
                allowed_operations: Vec::new(),
            },
            artifacts: Vec::new(),
            budgets: BudgetSnapshot {
                max_argument_bytes: 256 * 1_024,
                max_file_bytes: 256 * 1_024,
                max_network_bytes: 256 * 1_024,
                max_calls: 1_024,
                max_wall_time_ms: 10_000,
                max_model_calls: 16,
                max_model_input_bytes: 256 * 1_024,
                max_model_output_bytes: 64 * 1_024,
            },
            policy_snapshot_hash,
        },
        safe_attack_preview: "Compatibility protocol test".to_owned(),
        attack_content_hash: Sha256Digest::from_bytes(b"isolated-mcp-compatibility-attack")
            .as_str()
            .to_owned(),
        stage_statuses: Vec::new(),
        operations: Vec::new(),
        event_count: 0,
        report_claims: Vec::new(),
        final_outcome_summary: "Compatibility runtime active".to_owned(),
        final_event_hash: None,
    }
}

pub fn production_server_from_env() -> anyhow::Result<McpServer<ProductionRuntime>> {
    let startup = RuntimeStartup::from_env()?;
    let state_dir = startup.state_dir;
    let instance_token = Zeroizing::new(startup.instance_token.into_bytes());
    let store = StateStore::open(&state_dir)?;
    let instance_token_text = std::str::from_utf8(instance_token.as_slice())?;
    let context =
        RuntimeContextLoader::load(&store, instance_token_text, time::OffsetDateTime::now_utc())?;
    let active_instance_id = context.active_instance().instance_id.clone();

    let sandbox_root = std::env::var_os("RUNWARDEN_SANDBOX_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("runwarden-sandbox"));
    let trusted_runtime_root = std::env::var_os("RUNWARDEN_TRUSTED_RUNTIME_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("runtime"));
    std::fs::create_dir_all(&sandbox_root)?;
    std::fs::create_dir_all(&trusted_runtime_root)?;
    let sandbox_root = sandbox_root.canonicalize()?;
    let trusted_runtime_root = trusted_runtime_root.canonicalize()?;

    let (issuer, verifier) = PermitAuthority::generate()?;
    let executor = DefaultProviderExecutor::new(ExecutorConfig::new(
        sandbox_root,
        trusted_runtime_root,
        256 * 1_024,
        Duration::from_secs(5),
        verifier,
    )?);
    let wait_policy = trusted_wait_policy()?;
    let runtime = Arc::new(OperationRuntime::new(
        store,
        executor,
        SystemClock,
        context,
        issuer,
        format!("mcp-{}-{}", std::process::id(), OperationId::new()),
        wait_policy,
    )?);
    let invocation_keys =
        InvocationKeyDeriver::from_trusted_instance(active_instance_id, instance_token)?;
    Ok(McpServer::new(
        runtime,
        DEFAULT_MAX_REQUEST_BYTES,
        invocation_keys,
    ))
}

fn trusted_wait_policy() -> anyhow::Result<ApprovalWaitPolicy> {
    let Some(raw) = std::env::var_os("RUNWARDEN_MCP_APPROVAL_WAIT_MS") else {
        return Ok(ApprovalWaitPolicy::contest_default());
    };
    let milliseconds = raw
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("RUNWARDEN_MCP_APPROVAL_WAIT_MS is not UTF-8"))?
        .parse::<u64>()?;
    if milliseconds > 120_000 {
        anyhow::bail!("RUNWARDEN_MCP_APPROVAL_WAIT_MS exceeds 120 seconds");
    }
    Ok(ApprovalWaitPolicy {
        timeout: Duration::from_millis(milliseconds),
        poll_interval: Duration::from_millis(100),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfigValidation {
    pub ok: bool,
    pub errors: Vec<String>,
    pub side_effect_executed: bool,
}

pub fn validate_runwarden_only_agent_config(config: &Value) -> AgentConfigValidation {
    let mut errors = Vec::new();
    let has_claude_shape = config.get("mcpServers").is_some();
    let has_opencode_shape = config.get("mcp").is_some();
    match (has_claude_shape, has_opencode_shape) {
        (true, false) => validate_claude_mcp_config(config, &mut errors),
        (false, true) => validate_opencode_mcp_config(config, &mut errors),
        (true, true) => {
            errors.push("agent config must not define both mcpServers and mcp".to_owned())
        }
        (false, false) => {
            errors.push("agent config must define exactly one Runwarden MCP server".to_owned())
        }
    }
    AgentConfigValidation {
        ok: errors.is_empty(),
        errors,
        side_effect_executed: false,
    }
}

fn validate_claude_mcp_config(config: &Value, errors: &mut Vec<String>) {
    let Some(servers) = config.get("mcpServers").and_then(Value::as_object) else {
        errors.push("mcpServers must be an object".to_owned());
        return;
    };
    validate_single_runwarden_server(servers, "mcpServers", errors);
    let Some(server) = servers.get("runwarden") else {
        return;
    };
    validate_common_runwarden_server_fields(server, "mcpServers.runwarden", errors);
    if server.get("command").and_then(Value::as_str) != Some("runwarden-mcp") {
        errors.push("mcpServers.runwarden.command must be exactly runwarden-mcp".to_owned());
    }
}

fn validate_opencode_mcp_config(config: &Value, errors: &mut Vec<String>) {
    let Some(servers) = config.get("mcp").and_then(Value::as_object) else {
        errors.push("mcp must be an object".to_owned());
        return;
    };
    validate_single_runwarden_server(servers, "mcp", errors);
    let Some(server) = servers.get("runwarden") else {
        return;
    };
    validate_common_runwarden_server_fields(server, "mcp.runwarden", errors);
    if server.get("type").and_then(Value::as_str) != Some("local") {
        errors.push("mcp.runwarden.type must be local".to_owned());
    }
    if server.get("enabled").and_then(Value::as_bool) == Some(false) {
        errors.push("mcp.runwarden.enabled must not be false".to_owned());
    }
    let command_ok = server
        .get("command")
        .and_then(Value::as_array)
        .is_some_and(|items| items.len() == 1 && items[0].as_str() == Some("runwarden-mcp"));
    if !command_ok {
        errors.push("mcp.runwarden.command must be exactly [\"runwarden-mcp\"]".to_owned());
    }
    let Some(tools) = config.get("tools").and_then(Value::as_object) else {
        errors.push("OpenCode config must disable built-in tools".to_owned());
        return;
    };
    for name in OPENCODE_1_17_13_BUILTIN_TOOLS {
        if tools.get(*name).and_then(Value::as_bool) != Some(false) {
            errors.push(format!(
                "OpenCode 1.17.13 built-in tool must be explicitly disabled: {name}"
            ));
        }
    }
    for (name, value) in tools {
        if value.as_bool() != Some(false) {
            errors.push(format!("OpenCode built-in tool must be disabled: {name}"));
        }
    }
}

fn validate_single_runwarden_server(
    servers: &serde_json::Map<String, Value>,
    label: &str,
    errors: &mut Vec<String>,
) {
    if servers.len() != 1 || !servers.contains_key("runwarden") {
        errors.push(format!(
            "{label} must contain exactly one server named runwarden"
        ));
    }
}

fn validate_common_runwarden_server_fields(server: &Value, label: &str, errors: &mut Vec<String>) {
    let Some(server_object) = server.as_object() else {
        errors.push(format!("{label} must be an object"));
        return;
    };
    for field in ["env", "environment", "cwd", "url", "transport"] {
        if server_object.contains_key(field) {
            errors.push(format!("{label}.{field} must not be set"));
        }
    }
    if let Some(args) = server_object.get("args")
        && !args.as_array().is_some_and(Vec::is_empty)
    {
        errors.push(format!("{label}.args must be an empty array when present"));
    }
}
