use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ErrorKind;
use crate::evidence::hex_sha256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderClass {
    FirstParty,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Input,
    Evidence,
    Trace,
    Report,
    Audit,
    Accountability,
    Cert,
    Eval,
    Bench,
    WebStatic,
    HttpReplay,
    Mcp,
    Shell,
    Plugin,
    Skill,
    Api,
    Scanner,
    Enterprise,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRisk {
    Low,
    Medium,
    High,
    NetworkActive,
    FileWrite,
    CredentialUse,
    Destructive,
    ReportClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectKind {
    None,
    Network,
    FileRead,
    FileWrite,
    ProcessSpawn,
    CredentialUse,
    Destructive,
    ArtifactWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allowed,
    Denied,
    RequiresReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    NotExecuted,
    Running,
    Completed,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    DryRun,
    Enforced,
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactRef {
    pub id: String,
    #[schemars(
        length(min = 1),
        regex(pattern = r"^(?!/)(?![A-Za-z]:[\\/])(?!.*(^|[\\/])\.\.([\\/]|$)).+$")
    )]
    pub path: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KernelProvider {
    pub id: String,
    pub class: ProviderClass,
    pub kind: ProviderKind,
    pub risk: ProviderRisk,
    pub side_effects: Vec<SideEffectKind>,
    pub input_schema: Value,
    pub output_schema: Value,
    pub evidence_contract: Value,
    pub authority_requirements: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderSchemaPin {
    pub algorithm: String,
    pub digest: String,
    pub schema: Value,
}

impl ProviderSchemaPin {
    pub fn new(schema: Value) -> Self {
        let digest = schema_digest(&schema);
        Self {
            algorithm: "sha256".to_string(),
            digest,
            schema,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderManifest {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_class: ProviderClass,
    pub kind: ProviderKind,
    pub risk: ProviderRisk,
    #[serde(default)]
    pub side_effects: Vec<SideEffectKind>,
    pub transport: Option<String>,
    pub downstream_identity: Option<String>,
    pub tool_identity: Option<String>,
    #[serde(default)]
    pub declared_permissions: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub command_allowlist: Vec<String>,
    pub working_root: Option<String>,
    pub schema_pin: ProviderSchemaPin,
    pub observed_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderEnforcementContract {
    pub requires_kernel_mediation: bool,
    pub requires_schema_pin: bool,
    pub requires_egress_policy: bool,
    pub requires_resource_limits: bool,
    pub requires_approval_gate: bool,
    pub requires_trace: bool,
    pub requires_redaction: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderContract {
    pub provider: KernelProvider,
    pub schema_pin: ProviderSchemaPin,
    pub observed_schema_digest: String,
    pub schema_rug_pull_detected: bool,
    pub enforcement: ProviderEnforcementContract,
}

impl ProviderContract {
    pub fn from_manifest(manifest: &ProviderManifest) -> Self {
        let observed_schema_digest = schema_digest(&manifest.observed_schema);
        let schema_rug_pull_detected = observed_schema_digest != manifest.schema_pin.digest;
        let requires_approval_gate = matches!(
            manifest.risk,
            ProviderRisk::High
                | ProviderRisk::NetworkActive
                | ProviderRisk::FileWrite
                | ProviderRisk::CredentialUse
                | ProviderRisk::Destructive
                | ProviderRisk::ReportClaim
        ) || manifest.side_effects.iter().any(|effect| {
            matches!(
                effect,
                SideEffectKind::Network
                    | SideEffectKind::FileWrite
                    | SideEffectKind::ProcessSpawn
                    | SideEffectKind::CredentialUse
                    | SideEffectKind::Destructive
                    | SideEffectKind::ArtifactWrite
            )
        });

        Self {
            provider: KernelProvider {
                id: manifest.provider_id.clone(),
                class: manifest.provider_class.clone(),
                kind: manifest.kind.clone(),
                risk: manifest.risk.clone(),
                side_effects: manifest.side_effects.clone(),
                input_schema: manifest.observed_schema.clone(),
                output_schema: Value::Object(Default::default()),
                evidence_contract: serde_json::json!({
                    "obs_refs_required": true,
                    "downstream_identity": manifest.downstream_identity,
                    "tool_identity": manifest.tool_identity
                }),
                authority_requirements: serde_json::json!({
                    "approval_required": requires_approval_gate,
                    "schema_pin_required": true,
                    "kernel_mediation_required": true
                }),
            },
            schema_pin: manifest.schema_pin.clone(),
            observed_schema_digest,
            schema_rug_pull_detected,
            enforcement: ProviderEnforcementContract {
                requires_kernel_mediation: true,
                requires_schema_pin: true,
                requires_egress_policy: matches!(
                    manifest.kind,
                    ProviderKind::Mcp
                        | ProviderKind::Api
                        | ProviderKind::Scanner
                        | ProviderKind::Enterprise
                ) || manifest
                    .side_effects
                    .contains(&SideEffectKind::Network),
                requires_resource_limits: true,
                requires_approval_gate,
                requires_trace: true,
                requires_redaction: true,
            },
        }
    }
}

pub fn schema_digest(schema: &Value) -> String {
    let bytes = serde_json::to_vec(schema).expect("provider schema serializes");
    format!("sha256:{}", hex_sha256(&bytes))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderCall {
    pub session_id: String,
    pub provider: String,
    pub action: String,
    pub arguments: Value,
    pub actor_id: Option<String>,
    pub authz_id: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecisionEnvelope {
    pub decision: PolicyDecision,
    pub gate_id: String,
    pub error_kind: Option<ErrorKind>,
    pub denied_by: Option<String>,
    pub reason: String,
    pub provider: String,
    pub action: String,
    pub target: String,
    pub authz_id: Option<String>,
    pub actor_id: Option<String>,
    pub approval_id: Option<String>,
    pub execution_mode: ExecutionMode,
    pub side_effect_executed: bool,
    pub trace_event: Option<String>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderOutcome {
    pub decision: PolicyDecision,
    pub execution_status: ExecutionStatus,
    pub output: Value,
    pub envelope: DecisionEnvelope,
    pub observation_id: String,
    pub artifacts: Vec<ArtifactRef>,
    pub next_actions: Vec<String>,
}

impl ProviderOutcome {
    pub fn before_side_effect(
        decision: PolicyDecision,
        call: &ProviderCall,
        gate_id: impl Into<String>,
        reason: impl Into<String>,
        error_kind: Option<ErrorKind>,
    ) -> Self {
        Self::new_before_side_effect(BeforeSideEffect {
            decision,
            session_id: call.session_id.clone(),
            provider: call.provider.clone(),
            action: call.action.clone(),
            argument_hash: hex_sha256(
                &serde_json::to_vec(&call.arguments)
                    .expect("provider call arguments must serialize"),
            ),
            authz_id: call.authz_id.clone(),
            actor_id: call.actor_id.clone(),
            approval_id: call.approval_id.clone(),
            gate_id: gate_id.into(),
            reason: reason.into(),
            error_kind,
        })
    }

    pub fn denied_before_side_effect(
        provider: impl Into<String>,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new_before_side_effect(BeforeSideEffect {
            decision: PolicyDecision::Denied,
            session_id: String::new(),
            provider: provider.into(),
            action: action.into(),
            argument_hash: String::new(),
            authz_id: None,
            actor_id: None,
            approval_id: None,
            gate_id: "policy".to_string(),
            reason: reason.into(),
            error_kind: None,
        })
    }

    fn new_before_side_effect(input: BeforeSideEffect) -> Self {
        let trace_event = trace_event_for_decision(&input.decision);
        let observation_id = observation_id_for_before_side_effect(&input, trace_event);
        Self {
            decision: input.decision.clone(),
            execution_status: ExecutionStatus::NotExecuted,
            output: Value::Null,
            envelope: DecisionEnvelope {
                decision: input.decision,
                gate_id: input.gate_id,
                error_kind: input.error_kind,
                denied_by: Some("kernel".to_string()),
                reason: input.reason,
                provider: input.provider,
                action: input.action,
                target: String::new(),
                authz_id: input.authz_id,
                actor_id: input.actor_id,
                approval_id: input.approval_id,
                execution_mode: ExecutionMode::Enforced,
                side_effect_executed: false,
                trace_event: Some(trace_event.to_string()),
                suggestion: None,
            },
            observation_id,
            artifacts: Vec::new(),
            next_actions: Vec::new(),
        }
    }
}

fn trace_event_for_decision(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allowed => "provider_policy_evaluated",
        PolicyDecision::Denied => "provider_denied",
        PolicyDecision::RequiresReview => "provider_requires_review",
    }
}

fn observation_id_for_before_side_effect(input: &BeforeSideEffect, trace_event: &str) -> String {
    let material = serde_json::json!({
        "trace_event": trace_event,
        "decision": &input.decision,
        "session_id": &input.session_id,
        "provider": &input.provider,
        "action": &input.action,
        "argument_hash": &input.argument_hash,
        "gate_id": &input.gate_id,
        "reason": &input.reason,
        "error_kind": &input.error_kind,
        "authz_id": &input.authz_id,
        "actor_id": &input.actor_id,
        "approval_id": &input.approval_id
    });
    format!(
        "obs_{}",
        &hex_sha256(
            &serde_json::to_vec(&material).expect("provider outcome trace material serializes")
        )[..16]
    )
}

struct BeforeSideEffect {
    decision: PolicyDecision,
    session_id: String,
    provider: String,
    action: String,
    argument_hash: String,
    authz_id: Option<String>,
    actor_id: Option<String>,
    approval_id: Option<String>,
    gate_id: String,
    reason: String,
    error_kind: Option<ErrorKind>,
}
