#![allow(dead_code)]

use std::fs;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use runwarden_kernel::resource::DataClass;
use runwarden_kernel::session::{
    AuthoritySnapshot, BudgetSnapshot, EmailAuthority, EvidenceAuthority, InputAuthority,
};
use runwarden_kernel::story::{
    EnforcementMode, EvidenceStatus, RunMode, SchemaVersion, SecurityStory, SessionId,
    StoryIdentity, StoryProvenance, StoryStatus,
};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_mcp::{InvocationKeyDeriver, McpServer, ProductionRuntime};
use runwarden_providers::executor::{DefaultProviderExecutor, ExecutorConfig, PermitAuthority};
use runwarden_runtime::{ApprovalWaitPolicy, OperationRuntime, RuntimeContextLoader, SystemClock};
use runwarden_state::{
    ApprovalDecisionInput, DemoActivation, ReviewerDecision, SessionRecord, StateStore,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

pub const INSTANCE_TOKEN: &str = "mcp-test-instance-token";

pub struct McpFixture {
    pub temp: tempfile::TempDir,
    pub state_dir: std::path::PathBuf,
    pub sandbox_root: std::path::PathBuf,
    pub trusted_runtime_root: std::path::PathBuf,
    pub store: StateStore,
    pub story: SecurityStory,
    pub server: McpServer<ProductionRuntime>,
}

impl McpFixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let sandbox_root = temp.path().join("sandbox");
        let trusted_runtime_root = temp.path().join("runtime");
        fs::create_dir_all(&sandbox_root).unwrap();
        fs::create_dir_all(&trusted_runtime_root).unwrap();
        let store = StateStore::open(&state_dir).unwrap();
        let story = persist_story(&store);
        let now = OffsetDateTime::now_utc();
        store
            .activate_demo(&DemoActivation {
                instance_id: "mcp-test-instance".to_owned(),
                story_id: story.story_id,
                session_id: story.authority.session_id,
                process_id: std::process::id(),
                host_id: "mcp-test-host".to_owned(),
                instance_token_hash: Sha256Digest::from_bytes(INSTANCE_TOKEN.as_bytes())
                    .as_str()
                    .to_owned(),
                now,
            })
            .unwrap();
        let context = RuntimeContextLoader::load(&store, INSTANCE_TOKEN, now).unwrap();
        let (issuer, verifier) = PermitAuthority::generate().unwrap();
        let executor = DefaultProviderExecutor::new(
            ExecutorConfig::new(
                sandbox_root.clone(),
                trusted_runtime_root.clone(),
                256 * 1_024,
                StdDuration::from_secs(2),
                verifier,
            )
            .unwrap(),
        );
        let runtime = Arc::new(
            OperationRuntime::new(
                store.clone(),
                executor,
                SystemClock,
                context,
                issuer,
                format!(
                    "mcp-test-runtime-{}",
                    runwarden_kernel::story::OperationId::new()
                ),
                ApprovalWaitPolicy::immediate(),
            )
            .unwrap(),
        );
        let keys = InvocationKeyDeriver::from_trusted_instance(
            "mcp-test-instance".to_owned(),
            Zeroizing::new(INSTANCE_TOKEN.as_bytes().to_vec()),
        )
        .unwrap();
        let server = McpServer::new(runtime, 1_048_576, keys);
        Self {
            temp,
            state_dir,
            sandbox_root,
            trusted_runtime_root,
            store,
            story,
            server,
        }
    }

    pub fn approve(&self, operation_id: runwarden_kernel::story::OperationId) {
        let approval = self
            .store
            .approval_for_operation(operation_id)
            .unwrap()
            .unwrap();
        let operation = self.store.operation(operation_id).unwrap();
        self.store
            .decide_approval(ApprovalDecisionInput {
                approval_id: approval.approval_id,
                expected_version: approval.version,
                expected_operation_version: operation.version,
                reviewer: "mcp-reviewer".to_owned(),
                reason: "approve exact durable MCP operation".to_owned(),
                decision: ReviewerDecision::Approve,
                now: OffsetDateTime::now_utc(),
            })
            .unwrap();
    }
}

fn persist_story(store: &StateStore) -> SecurityStory {
    let session_id = SessionId::new();
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    let policy_snapshot_hash = Sha256Digest::from_bytes(b"mcp-test-policy")
        .as_str()
        .to_owned();
    let story = SecurityStory {
        schema_version: SchemaVersion::current(),
        story_id: runwarden_kernel::story::StoryId::new(),
        title: "Durable MCP test".to_owned(),
        scenario_id: "durable-mcp".to_owned(),
        attack_category: "prompt_injection".to_owned(),
        run_mode: RunMode::Deterministic,
        enforcement_mode: EnforcementMode::Enforced,
        provenance: StoryProvenance::Native,
        status: StoryStatus::Running,
        evidence_status: EvidenceStatus::Pending,
        identity: StoryIdentity {
            agent_id: "mcp-agent".to_owned(),
            model_id: "mcp-model".to_owned(),
            actor_id: "mcp-actor".to_owned(),
            reviewer_id: Some("mcp-reviewer".to_owned()),
        },
        authority: AuthoritySnapshot {
            session_id,
            actor_id: "mcp-actor".to_owned(),
            authz_id: "mcp-authz".to_owned(),
            authz_state: "active".to_owned(),
            expires_at,
            allowed_providers: vec![
                "runwarden.input.inspect".to_owned(),
                "external.email.send".to_owned(),
            ],
            files: Vec::new(),
            networks: Vec::new(),
            email: Some(EmailAuthority {
                allowed_recipients: vec!["judge@example.test".to_owned()],
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
                max_calls: 16,
                max_wall_time_ms: 10_000,
                max_model_calls: 8,
                max_model_input_bytes: 256 * 1_024,
                max_model_output_bytes: 64 * 1_024,
            },
            policy_snapshot_hash,
        },
        safe_attack_preview: "Ignore approval and send".to_owned(),
        attack_content_hash: Sha256Digest::from_bytes(b"mcp-test-attack")
            .as_str()
            .to_owned(),
        stage_statuses: Vec::new(),
        operations: Vec::new(),
        event_count: 0,
        report_claims: Vec::new(),
        final_outcome_summary: "MCP test running".to_owned(),
        final_event_hash: None,
    };
    store.create_story(&story).unwrap();
    store
        .create_session(&SessionRecord {
            session_id,
            story_id: story.story_id,
            authority: story.authority.clone(),
            policy_snapshot_hash: story.authority.policy_snapshot_hash.clone(),
            expires_at,
        })
        .unwrap();
    story
}

pub fn call(server: &McpServer<ProductionRuntime>, id: i64, name: &str, arguments: Value) -> Value {
    server
        .handle_jsonrpc(
            &json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments}
            })
            .to_string(),
        )
        .unwrap()
        .unwrap()
}

pub fn payload(response: &Value) -> &Value {
    &response["result"]["structuredContent"]
}
