use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use runwarden_assurance::accountability::accountability_summary;
use runwarden_assurance::audit::audit_summary;
use runwarden_assurance::bench::benchmark_workspace;
use runwarden_assurance::cert::certify_workspace;
use runwarden_assurance::eval::{
    AgentNativeConfigCase, AgentNativeExpectation, EvalThresholds, evaluate_agent_native_configs,
    evaluate_report_assurance,
};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report, scaffold_report_from_trace,
};
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::contracts::{
    ErrorKind, ExecutionStatus, PolicyDecision, ProviderCall, ProviderClass, ProviderKind,
    ProviderOutcome, SideEffectKind,
};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery, hex_sha256};
use runwarden_kernel::kernel::{KernelEnforcer, KernelPolicy, ScopedRoot};
use runwarden_kernel::manifest::SessionManifest;
use runwarden_providers::catalog::{default_external_provider_manifest, full_provider_registry};
use runwarden_providers::evidence::{EvidenceInspectPolicy, inspect_evidence_root};
use runwarden_providers::external::{
    ExternalMcpAdapterRequest, execute_external_mcp_adapter, load_provider_manifest,
};
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use runwarden_providers::runtime::{
    ProviderRuntime, ProviderRuntimeDenialKind, ProviderRuntimePolicy, ProviderRuntimeRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::{PlatformError, PlatformEvent, RunwardenPlatform};

#[derive(Debug, Clone)]
pub struct ProviderExecutionRequest {
    pub call: ProviderCall,
    pub session: Option<SessionManifest>,
}

#[derive(Debug, Clone)]
pub struct ProviderExecutionResult {
    pub outcome: ProviderOutcome,
    pub output: Value,
    pub call: ProviderCall,
    pub record_id: String,
    pub record_path: PathBuf,
}

impl RunwardenPlatform {
    pub fn submit_provider_call(
        &mut self,
        request: ProviderExecutionRequest,
    ) -> Result<ProviderExecutionResult, PlatformError> {
        self.state.ensure_layout()?;

        let mut call = request.call;
        self.state.append_event(&PlatformEvent::new(
            "provider_call_requested",
            json!({
                "session_id": call.session_id,
                "provider": call.provider,
                "action": call.action,
                "actor_id": call.actor_id,
                "authz_id": call.authz_id,
                "approval_id": call.approval_id,
                "side_effect_executed": false
            }),
        ))?;

        if let Err(err) =
            resolve_session_provider_argument_paths(request.session.as_ref(), &mut call)
        {
            let outcome = failed_before_side_effect(
                &call,
                "scope",
                err.to_string(),
                ErrorKind::ScopeViolation,
            );
            return self.finish_provider_call(call, outcome, Value::Null);
        }

        let mut outcome = evaluate_call_without_approvals(&call, request.session.as_ref());
        if outcome.decision == PolicyDecision::Denied {
            return self.finish_provider_call(call, outcome, Value::Null);
        }

        if provider_is_external_mcp(&call.provider) {
            if let Some(input_path) = call
                .arguments
                .get("input_path")
                .and_then(Value::as_str)
                .map(PathBuf::from)
            {
                if let Err(err) = resolve_external_mcp_manifest_argument(
                    call.arguments.as_object_mut().ok_or_else(|| {
                        PlatformError::ProviderExecution(
                            "provider call arguments must be an object".to_string(),
                        )
                    })?,
                    &input_path,
                ) {
                    let outcome = failed_before_side_effect(
                        &call,
                        "external_mcp_manifest",
                        err.to_string(),
                        ErrorKind::ArgumentSchemaInvalid,
                    );
                    return self.finish_provider_call(call, outcome, Value::Null);
                }
                outcome = evaluate_call_without_approvals(&call, request.session.as_ref());
                if outcome.decision == PolicyDecision::Denied {
                    return self.finish_provider_call(call, outcome, Value::Null);
                }
            }
        }

        if let Err(err) = bind_file_digests(&mut call) {
            let outcome = failed_before_side_effect(
                &call,
                "digest",
                err.to_string(),
                ErrorKind::ArgumentSchemaInvalid,
            );
            return self.finish_provider_call(call, outcome, Value::Null);
        }
        attach_matching_approval(self, &mut call)?;

        let mut enforcer = KernelEnforcer::new(
            full_provider_registry(),
            provider_policy(request.session.as_ref(), &call),
        );
        for approval in self.list_approvals(crate::ApprovalListFilter::All)? {
            enforcer.add_approval(approval);
        }
        outcome = enforcer.evaluate_call(&call);

        if outcome.decision == PolicyDecision::RequiresReview {
            let binding = enforcer.approval_binding_for_call(&call);
            self.enqueue_pending_approval(&mut outcome, binding)?;
            return self.finish_provider_call(call, outcome, Value::Null);
        }

        if outcome.decision == PolicyDecision::Denied {
            return self.finish_provider_call(call, outcome, Value::Null);
        }

        if let Err(err) = verify_file_digests(&call) {
            let outcome = failed_before_side_effect(
                &call,
                "digest",
                err.to_string(),
                ErrorKind::ApprovalInvalid,
            );
            return self.finish_provider_call(call, outcome, Value::Null);
        }
        if call
            .approval_id
            .as_deref()
            .and_then(|approval_id| enforcer.approval_state(approval_id))
            == Some(ApprovalState::Consumed)
        {
            persist_consumed_approval(self, &call, &enforcer.approval_binding_for_call(&call))?;
        }

        let output = execute_provider(self.state.workspace_root(), &call, request.session.as_ref());
        match output {
            Ok(output) => {
                apply_provider_output_to_outcome(&mut outcome, &call, &output);
                self.finish_provider_call(call, outcome, output)
            }
            Err(message) => {
                let outcome = failed_before_side_effect(
                    &call,
                    "provider_execution",
                    message,
                    ErrorKind::Internal,
                );
                self.finish_provider_call(call, outcome, Value::Null)
            }
        }
    }

    fn enqueue_pending_approval(
        &self,
        outcome: &mut ProviderOutcome,
        binding: ApprovalBinding,
    ) -> Result<(), PlatformError> {
        let approval_id = pending_approval_id_for_binding(&binding);
        let existing = self.read_approval(&approval_id).ok();
        if existing
            .as_ref()
            .is_none_or(|approval| !matches!(approval.state, ApprovalState::Pending))
        {
            self.write_approval(&ApprovalRecord::new(&approval_id, binding))?;
        }
        let approval = self.read_approval(&approval_id)?;
        outcome.envelope.approval_id = Some(approval_id.clone());
        outcome.output = json!({
            "approval": approval,
            "approval_id": approval_id,
            "side_effect_executed": false
        });
        if !outcome
            .next_actions
            .iter()
            .any(|action| action == "review_approval")
        {
            outcome.next_actions.push("review_approval".to_string());
        }
        Ok(())
    }

    fn finish_provider_call(
        &self,
        call: ProviderCall,
        outcome: ProviderOutcome,
        output: Value,
    ) -> Result<ProviderExecutionResult, PlatformError> {
        let event_type = match outcome.decision {
            PolicyDecision::Denied => {
                if outcome.execution_status == ExecutionStatus::Failed {
                    "provider_call_failed"
                } else {
                    "provider_call_denied"
                }
            }
            PolicyDecision::RequiresReview => "provider_call_requires_review",
            PolicyDecision::Allowed => {
                if outcome.execution_status == ExecutionStatus::Failed {
                    "provider_call_failed"
                } else {
                    "provider_call_completed"
                }
            }
        };
        self.state.append_event(&PlatformEvent::new(
            event_type,
            json!({
                "session_id": call.session_id,
                "provider": call.provider,
                "action": call.action,
                "decision": outcome.decision,
                "execution_status": outcome.execution_status,
                "approval_id": outcome.envelope.approval_id,
                "observation_id": outcome.observation_id,
                "side_effect_executed": outcome.envelope.side_effect_executed
            }),
        ))?;

        let record_id = provider_call_record_id();
        let record = json!({
            "record_id": record_id,
            "call": call,
            "outcome": outcome,
            "output": output
        });
        let record_path = self.state.write_provider_call_record(&record_id, &record)?;
        Ok(ProviderExecutionResult {
            outcome,
            output,
            call,
            record_id,
            record_path,
        })
    }
}

fn evaluate_call_without_approvals(
    call: &ProviderCall,
    session: Option<&SessionManifest>,
) -> ProviderOutcome {
    KernelEnforcer::new(full_provider_registry(), provider_policy(session, call))
        .evaluate_call(call)
}

fn failed_before_side_effect(
    call: &ProviderCall,
    gate_id: &str,
    reason: String,
    error_kind: ErrorKind,
) -> ProviderOutcome {
    let mut outcome = ProviderOutcome::before_side_effect(
        PolicyDecision::Denied,
        call,
        gate_id,
        reason,
        Some(error_kind),
    );
    outcome.execution_status = ExecutionStatus::Failed;
    outcome.envelope.side_effect_executed = false;
    outcome
}

fn provider_policy(session: Option<&SessionManifest>, call: &ProviderCall) -> KernelPolicy {
    session
        .map(SessionManifest::to_kernel_policy)
        .unwrap_or_else(|| default_provider_policy(call))
}

fn default_provider_policy(call: &ProviderCall) -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.allow_provider(call.provider.clone());
    policy.active_assessment = true;
    add_default_scoped_roots(&mut policy, &call.arguments);
    policy
}

fn add_default_scoped_roots(policy: &mut KernelPolicy, arguments: &Value) {
    for field in [
        "input_path",
        "root_path",
        "trace_path",
        "report_path",
        "manifest_path",
    ] {
        let Some(path) = arguments.get(field).and_then(Value::as_str) else {
            continue;
        };
        let path = PathBuf::from(path);
        let root = if path.is_dir() {
            Some(path)
        } else {
            path.parent().map(Path::to_path_buf)
        };
        if let Some(root) = root {
            policy.add_scoped_root(ScopedRoot::new(format!("cli-{field}"), root));
        }
    }
}

fn resolve_session_provider_argument_paths(
    session: Option<&SessionManifest>,
    call: &mut ProviderCall,
) -> Result<(), PlatformError> {
    let Some(session) = session else {
        return Ok(());
    };
    let Some(arguments) = call.arguments.as_object_mut() else {
        return Ok(());
    };
    let selected_root = arguments
        .get("root")
        .and_then(Value::as_str)
        .and_then(|root_name| {
            session
                .roots
                .iter()
                .find(|root| root.name == root_name)
                .map(|root| root.path.clone())
        });
    let implicit_root = if selected_root.is_none() && session.roots.len() == 1 {
        Some(session.roots[0].path.clone())
    } else {
        None
    };
    let scoped_root = selected_root.or(implicit_root);

    for field in ["input_path", "trace_path", "report_path", "manifest_path"] {
        resolve_session_provider_path_field(arguments, field, scoped_root.as_ref())?;
    }

    Ok(())
}

fn resolve_session_provider_path_field(
    arguments: &mut serde_json::Map<String, Value>,
    field: &str,
    scoped_root: Option<&PathBuf>,
) -> Result<(), PlatformError> {
    let Some(path_text) = arguments
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return Ok(());
    };
    let path = PathBuf::from(path_text);
    if path.is_absolute() {
        return Ok(());
    }
    let Some(scoped_root) = scoped_root else {
        return Err(PlatformError::ProviderExecution(format!(
            "session relative provider path {field} requires a scoped root or exactly one session root"
        )));
    };
    arguments.insert(
        field.to_string(),
        Value::String(scoped_root.join(path).to_string_lossy().into_owned()),
    );
    Ok(())
}

fn bind_file_digests(call: &mut ProviderCall) -> Result<(), PlatformError> {
    let Some(arguments) = call.arguments.as_object_mut() else {
        return Ok(());
    };
    for &field in provider_path_digest_fields() {
        let Some(path) = arguments.get(field).and_then(Value::as_str) else {
            continue;
        };
        let digest = digest_file(Path::new(path))?;
        arguments.insert(format!("{field}_sha256"), Value::String(digest));
    }
    Ok(())
}

fn verify_file_digests(call: &ProviderCall) -> Result<(), PlatformError> {
    let Some(arguments) = call.arguments.as_object() else {
        return Ok(());
    };
    for &field in provider_path_digest_fields() {
        let Some(path) = arguments.get(field).and_then(Value::as_str) else {
            continue;
        };
        let digest_key = format!("{field}_sha256");
        let Some(expected) = arguments.get(&digest_key).and_then(Value::as_str) else {
            continue;
        };
        let actual = digest_file(Path::new(path))?;
        if actual != expected {
            return Err(PlatformError::ProviderExecution(format!(
                "{field} changed after approval binding"
            )));
        }
    }
    Ok(())
}

fn provider_path_digest_fields() -> &'static [&'static str] {
    &["input_path", "trace_path", "report_path", "manifest_path"]
}

fn digest_file(path: &Path) -> Result<String, PlatformError> {
    let bytes = fs::read(path)?;
    Ok(hex_sha256(&bytes))
}

fn attach_matching_approval(
    platform: &RunwardenPlatform,
    call: &mut ProviderCall,
) -> Result<(), PlatformError> {
    if call.approval_id.is_some() {
        return Ok(());
    }
    let binding = approval_binding(call)?;
    if let Some(approval) = platform
        .list_approvals(crate::ApprovalListFilter::All)?
        .into_iter()
        .find(|approval| approval.binding == binding && approval_is_usable(approval))
    {
        call.approval_id = Some(approval.approval_id);
    }
    Ok(())
}

fn approval_binding(call: &ProviderCall) -> Result<ApprovalBinding, PlatformError> {
    Ok(ApprovalBinding {
        session_id: call.session_id.clone(),
        provider: call.provider.clone(),
        action: call.action.clone(),
        argument_hash: hex_sha256(&serde_json::to_vec(&call.arguments)?),
        authz_id: call.authz_id.clone(),
        actor_id: call.actor_id.clone(),
    })
}

fn approval_is_usable(approval: &ApprovalRecord) -> bool {
    approval.state == ApprovalState::Approved
        && approval
            .expires_at
            .is_none_or(|expires_at| expires_at > OffsetDateTime::now_utc())
}

fn persist_consumed_approval(
    platform: &RunwardenPlatform,
    call: &ProviderCall,
    binding: &ApprovalBinding,
) -> Result<(), PlatformError> {
    let Some(approval_id) = call.approval_id.as_deref() else {
        return Ok(());
    };
    let mut approval = platform.read_approval(approval_id)?;
    if approval.state == ApprovalState::Approved {
        approval.consume_once(binding)?;
        platform.write_approval(&approval)?;
    }
    Ok(())
}

fn pending_approval_id_for_binding(binding: &ApprovalBinding) -> String {
    let digest = hex_sha256(&serde_json::to_vec(binding).expect("approval binding serializes"));
    format!("approval_{}", &digest[..16])
}

fn provider_call_record_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("call_{}_{}", std::process::id(), nanos)
}

fn execute_provider(
    workspace_root: &Path,
    call: &ProviderCall,
    session: Option<&SessionManifest>,
) -> Result<Value, String> {
    let registry = full_provider_registry();
    let Some(provider) = registry.get(&call.provider) else {
        return Err(format!("unsupported provider call: {}", call.provider));
    };
    if provider.class == ProviderClass::External {
        return call_external_provider(&call.provider, &call.arguments, session);
    }
    call_first_party_provider(workspace_root, call, session)
}

fn call_first_party_provider(
    workspace_root: &Path,
    call: &ProviderCall,
    session: Option<&SessionManifest>,
) -> Result<Value, String> {
    let arguments = resolve_execution_arguments(session, &call.arguments)?;
    let output = match call.provider.as_str() {
        "runwarden.input.inspect" => {
            let bytes = if let Some(text) = string_field(&arguments, "input_text") {
                text.into_bytes()
            } else {
                let path = string_field(&arguments, "input_path")
                    .ok_or_else(|| "input_text or input_path is required".to_string())?;
                fs::read(&path).map_err(|err| format!("failed to read input {path}: {err}"))?
            };
            json!(inspect_input(
                InputSource::UserPrompt,
                &bytes,
                InputInspectPolicy::default()
            ))
        }
        "runwarden.evidence.inspect" => {
            let root = string_field(&arguments, "root_path")
                .or_else(|| resolve_session_root_path(session, &arguments))
                .or_else(|| string_field(&arguments, "root"))
                .ok_or_else(|| "root_path is required".to_string())?;
            json!(
                inspect_evidence_root(Path::new(&root), EvidenceInspectPolicy::default())
                    .map_err(|err| err.to_string())?
            )
        }
        "runwarden.audit.summary" => {
            let events = read_trace_from_arguments(&arguments)?;
            json!(audit_summary(&events))
        }
        "runwarden.accountability.summary" => {
            let events = read_trace_from_arguments(&arguments)?;
            json!(accountability_summary(&events))
        }
        "runwarden.trace.verify" => {
            let events = read_trace_from_arguments(&arguments)?;
            verify_trace_events(events)
        }
        "runwarden.trace.export" => {
            let events = read_trace_from_arguments(&arguments)?;
            let verification = verify_trace_events(events.clone());
            if verification["verified"].as_bool() != Some(true) {
                return Ok(json!({
                    "provider": call.provider,
                    "decision": "denied",
                    "execution_status": "failed",
                    "side_effect_executed": false,
                    "output": {
                        "verification": verification
                    }
                }));
            }
            let mut store = InMemoryTraceStore::default();
            for event in events {
                store.append(event);
            }
            json!({
                "verification": verification,
                "events": store.query(trace_query_from_arguments(&arguments)).events
            })
        }
        "runwarden.report.scaffold" => {
            let events = read_trace_from_arguments(&arguments)?;
            json!(scaffold_report_from_trace(&events))
        }
        "runwarden.report.lint" => {
            let (report, trace) = read_report_and_trace_from_arguments(&arguments)?;
            let lint = lint_report_against_trace(&report, &trace);
            if !lint.ok {
                let output = json!(lint);
                let reason = output["errors"][0]["message"]
                    .as_str()
                    .unwrap_or("report lint failed")
                    .to_string();
                let error_kind = if output["errors"][0]["kind"].as_str() == Some("TraceTampered") {
                    "trace_tampered"
                } else {
                    "report_citation_invalid"
                };
                return Ok(json!({
                    "provider": call.provider,
                    "decision": "denied",
                    "execution_status": "failed",
                    "gate_id": "report_lint",
                    "error_kind": error_kind,
                    "reason": reason,
                    "side_effect_executed": false,
                    "output": output
                }));
            }
            json!(lint)
        }
        "runwarden.report.render" => {
            let (report, trace) = read_report_and_trace_from_arguments(&arguments)?;
            let format = parse_render_format(
                string_field(&arguments, "format")
                    .as_deref()
                    .unwrap_or("markdown"),
            )?;
            json!(render_report(&report, &trace, format).map_err(|err| err.message)?)
        }
        "runwarden.cert.all" => {
            let root = find_workspace_root(workspace_root.to_path_buf())?;
            json!(certify_workspace(&root))
        }
        "runwarden.eval.all" => {
            let (report, trace) = read_report_and_trace_from_arguments(&arguments)?;
            let expected_obs: Vec<_> = trace.iter().map(|event| event.obs_id.clone()).collect();
            json!(evaluate_report_assurance(
                &report,
                &trace,
                expected_obs,
                EvalThresholds::strict()
            ))
        }
        "runwarden.eval.agent-native" => {
            let root = find_workspace_root(workspace_root.to_path_buf())?;
            let cases = load_agent_native_cases(&root, Vec::new())?;
            json!(evaluate_agent_native_configs(&cases))
        }
        "runwarden.bench.run" => {
            let root = find_workspace_root(workspace_root.to_path_buf())?;
            json!(benchmark_workspace(&root).map_err(|err| err.to_string())?)
        }
        other => return Err(format!("unsupported first-party provider call: {other}")),
    };

    Ok(json!({
        "provider": call.provider,
        "decision": "allowed",
        "execution_status": "completed",
        "side_effect_executed": first_party_output_side_effect_executed(&output),
        "output": output
    }))
}

#[derive(Debug, Deserialize)]
struct ExternalShellRequest {
    executable: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<PathBuf>,
    #[serde(default)]
    use_shell: bool,
    timeout_ms: Option<u64>,
    stdout_limit_bytes: Option<usize>,
    stderr_limit_bytes: Option<usize>,
}

fn call_external_provider(
    provider: &str,
    arguments: &Value,
    session: Option<&SessionManifest>,
) -> Result<Value, String> {
    let registry = full_provider_registry();
    let Some(provider_record) = registry.get(provider) else {
        return Err(format!("unsupported external provider call: {provider}"));
    };
    if provider_record.class != ProviderClass::External {
        return Err(format!("unsupported external provider call: {provider}"));
    }

    match &provider_record.kind {
        ProviderKind::Shell if provider == "external.shell.command" => {
            let input_path = string_field(arguments, "input_path").ok_or_else(|| {
                "--input JSON is required for external.shell.command mediated calls".to_string()
            })?;
            let request_body = fs::read_to_string(&input_path).map_err(|err| {
                format!("failed to read external shell request {input_path}: {err}")
            })?;
            let shell_request: ExternalShellRequest =
                serde_json::from_str(&request_body).map_err(|err| err.to_string())?;
            let command_allowlist = ["git", "cargo", "pnpm"];
            if !command_allowlist.contains(&shell_request.executable.as_str()) {
                return Ok(json!({
                    "provider": provider,
                    "decision": "denied",
                    "execution_status": "not_executed",
                    "error_kind": "provider_not_allowed",
                    "reason": "external shell executable is not allowlisted",
                    "side_effect_executed": false
                }));
            }

            let cwd = shell_request.cwd.unwrap_or_else(|| PathBuf::from("."));
            let runtime_root = string_field(arguments, "root_path")
                .map(PathBuf::from)
                .or_else(|| resolve_session_root_path(session, arguments).map(PathBuf::from))
                .unwrap_or_else(|| cwd.clone());
            let policy = ProviderRuntimePolicy::locked_to_root(runtime_root);
            let mut runtime_request = ProviderRuntimeRequest::new(shell_request.executable.clone())
                .cwd(cwd)
                .use_shell(shell_request.use_shell);
            for arg in shell_request.args {
                runtime_request = runtime_request.arg(arg);
            }
            if let Some(timeout_ms) = shell_request.timeout_ms {
                runtime_request = runtime_request.timeout_ms(timeout_ms);
            }
            if let Some(stdout_limit_bytes) = shell_request.stdout_limit_bytes {
                runtime_request = runtime_request.stdout_limit_bytes(stdout_limit_bytes);
            }
            if let Some(stderr_limit_bytes) = shell_request.stderr_limit_bytes {
                runtime_request = runtime_request.stderr_limit_bytes(stderr_limit_bytes);
            }

            match ProviderRuntime::prepare(&policy, &runtime_request) {
                Ok(prepared_process) => Ok(json!({
                    "provider": provider,
                    "decision": "requires_review",
                    "execution_status": "not_executed",
                    "reason": "external shell command was prepared by runtime mediation and awaits human approval",
                    "prepared_process": prepared_process,
                    "side_effect_executed": false
                })),
                Err(denial) => Ok(json!({
                    "provider": provider,
                    "decision": "denied",
                    "execution_status": "not_executed",
                    "error_kind": runtime_denial_error_kind(&denial.kind),
                    "reason": denial.reason,
                    "side_effect_executed": denial.side_effect_executed
                })),
            }
        }
        ProviderKind::Mcp => {
            let input_path = string_field(arguments, "input_path").ok_or_else(|| {
                "--input JSON is required for external MCP adapter calls".to_string()
            })?;
            let request_body = fs::read_to_string(&input_path).map_err(|err| {
                format!("failed to read external MCP request {input_path}: {err}")
            })?;
            let request: ExternalMcpAdapterRequest =
                serde_json::from_str(&request_body).map_err(|err| err.to_string())?;
            let manifest = if let Some(manifest_path) = &request.manifest_path {
                let manifest_path =
                    resolve_external_mcp_manifest_path(Path::new(&input_path), manifest_path);
                let manifest_body = fs::read_to_string(manifest_path)
                    .map_err(|err| format!("failed to read external MCP manifest: {err}"))?;
                load_provider_manifest(&manifest_body).map_err(|err| err.to_string())?
            } else {
                default_external_provider_manifest(provider).ok_or_else(|| {
                    format!("missing default external provider manifest: {provider}")
                })?
            };
            if manifest.provider_id != provider {
                return Err(format!(
                    "external MCP manifest provider_id {} does not match requested provider {provider}",
                    manifest.provider_id
                ));
            }
            Ok(execute_external_mcp_adapter(
                &manifest,
                &request,
                string_field(arguments, "root_path")
                    .as_deref()
                    .map(Path::new),
            ))
        }
        _ => Ok(json!({
            "provider": provider,
            "decision": "requires_review",
            "execution_status": "not_executed",
            "external_adapter_required": true,
            "reason": "external provider is registered and must be invoked through its mediated downstream adapter",
            "side_effect_executed": false
        })),
    }
}

fn resolve_external_mcp_manifest_argument(
    arguments: &mut serde_json::Map<String, Value>,
    input_path: &Path,
) -> Result<(), PlatformError> {
    if arguments.contains_key("manifest_path") {
        return Ok(());
    }
    let request_body = fs::read_to_string(input_path)?;
    let request: ExternalMcpAdapterRequest = serde_json::from_str(&request_body)?;
    let Some(manifest_path) = request.manifest_path.as_ref() else {
        return Ok(());
    };
    let resolved = resolve_external_mcp_manifest_path(input_path, manifest_path);
    arguments.insert(
        "manifest_path".to_string(),
        Value::String(resolved.to_string_lossy().into_owned()),
    );
    Ok(())
}

fn resolve_external_mcp_manifest_path(input_path: &Path, manifest_path: &Path) -> PathBuf {
    if manifest_path.is_absolute() {
        manifest_path.to_path_buf()
    } else {
        input_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(manifest_path)
    }
}

fn provider_is_external_mcp(provider: &str) -> bool {
    default_external_provider_manifest(provider)
        .is_some_and(|manifest| manifest.kind == ProviderKind::Mcp)
}

fn runtime_denial_error_kind(kind: &ProviderRuntimeDenialKind) -> &'static str {
    match kind {
        ProviderRuntimeDenialKind::ShellDenied
        | ProviderRuntimeDenialKind::CwdEscape
        | ProviderRuntimeDenialKind::EnvInheritanceDenied
        | ProviderRuntimeDenialKind::EnvNotAllowed
        | ProviderRuntimeDenialKind::NetworkDenied => "provider_not_allowed",
        ProviderRuntimeDenialKind::TimeoutTooLarge
        | ProviderRuntimeDenialKind::OutputLimitTooLarge => "budget_exceeded",
    }
}

fn resolve_execution_arguments(
    session: Option<&SessionManifest>,
    arguments: &Value,
) -> Result<Value, String> {
    let mut resolved = arguments.clone();
    let Some(object) = resolved.as_object_mut() else {
        return Ok(resolved);
    };
    let selected_root = object
        .get("root")
        .and_then(Value::as_str)
        .and_then(|root_name| {
            session.and_then(|session| {
                session
                    .roots
                    .iter()
                    .find(|root| root.name == root_name)
                    .map(|root| root.path.clone())
            })
        });
    let implicit_root = session.and_then(|session| {
        if selected_root.is_none() && session.roots.len() == 1 {
            Some(session.roots[0].path.clone())
        } else {
            None
        }
    });
    let scoped_root = selected_root.or(implicit_root);
    for field in ["input_path", "trace_path", "report_path", "root_path"] {
        let Some(path_text) = object.get(field).and_then(Value::as_str) else {
            continue;
        };
        let path = PathBuf::from(path_text);
        if path.is_absolute() {
            continue;
        }
        if let Some(scoped_root) = scoped_root.as_ref() {
            object.insert(
                field.to_string(),
                Value::String(scoped_root.join(path).to_string_lossy().into_owned()),
            );
        }
    }
    Ok(resolved)
}

fn resolve_session_root_path(
    session: Option<&SessionManifest>,
    arguments: &Value,
) -> Option<String> {
    let session = session?;
    let root_name = string_field(arguments, "root")?;
    session
        .roots
        .iter()
        .find(|root| root.name == root_name)
        .map(|root| root.path.to_string_lossy().into_owned())
}

fn read_trace_from_arguments(arguments: &Value) -> Result<Vec<TraceEvent>, String> {
    if let Some(trace) = arguments.get("trace") {
        return serde_json::from_value(trace.clone())
            .map_err(|err| format!("trace is invalid: {err}"));
    }
    let path = string_field(arguments, "trace_path")
        .ok_or_else(|| "trace_path is required".to_string())?;
    let body =
        fs::read_to_string(&path).map_err(|err| format!("failed to read trace {path}: {err}"))?;
    serde_json::from_str(&body).map_err(|err| format!("failed to parse trace {path}: {err}"))
}

fn read_report_from_arguments(arguments: &Value) -> Result<ReportDraft, String> {
    if let Some(report) = arguments.get("report") {
        return serde_json::from_value(report.clone())
            .map_err(|err| format!("report is invalid: {err}"));
    }
    let path = string_field(arguments, "report_path")
        .ok_or_else(|| "report_path is required".to_string())?;
    let body =
        fs::read_to_string(&path).map_err(|err| format!("failed to read report {path}: {err}"))?;
    serde_json::from_str(&body).map_err(|err| format!("failed to parse report {path}: {err}"))
}

fn read_report_and_trace_from_arguments(
    arguments: &Value,
) -> Result<(ReportDraft, Vec<TraceEvent>), String> {
    Ok((
        read_report_from_arguments(arguments)?,
        read_trace_from_arguments(arguments)?,
    ))
}

fn verify_trace_events(events: Vec<TraceEvent>) -> Value {
    let event_count = events.len();
    let mut store = InMemoryTraceStore::default();
    for event in events {
        store.append(event);
    }
    match store.verify_hash_chain() {
        Ok(()) => json!({
            "verified": true,
            "event_count": event_count
        }),
        Err(err) => json!({
            "verified": false,
            "event_count": event_count,
            "error": {
                "kind": "trace_tampered",
                "offset": err.offset,
                "obs_id": err.obs_id,
                "message": err.reason
            }
        }),
    }
}

fn trace_query_from_arguments(arguments: &Value) -> TraceQuery {
    TraceQuery {
        offset: number_field(arguments, "offset").unwrap_or(0),
        limit: number_field(arguments, "limit").unwrap_or(100),
        provider: string_field(arguments, "provider_filter")
            .or_else(|| string_field(arguments, "provider")),
        event_type: string_field(arguments, "event_type"),
        obs_prefix: string_field(arguments, "obs_prefix"),
        max_bytes: number_field(arguments, "max_bytes"),
    }
}

fn parse_render_format(format: &str) -> Result<RenderFormat, String> {
    match format {
        "markdown" | "md" => Ok(RenderFormat::Markdown),
        "json" => Ok(RenderFormat::Json),
        "html" => Ok(RenderFormat::Html),
        "sarif" | "sarif.json" => Ok(RenderFormat::Sarif),
        other => Err(format!("unsupported report render format: {other}")),
    }
}

fn provider_output_side_effect_executed(provider_id: &str, output: &Value) -> bool {
    if let Some(side_effect_executed) = output.get("side_effect_executed").and_then(Value::as_bool)
    {
        return side_effect_executed;
    }

    let registry = full_provider_registry();
    registry.get(provider_id).is_some_and(|provider| {
        provider
            .side_effects
            .iter()
            .any(|side_effect| side_effect != &SideEffectKind::None)
    })
}

fn apply_provider_output_to_outcome(
    outcome: &mut ProviderOutcome,
    call: &ProviderCall,
    output: &Value,
) {
    let decision = provider_output_decision(output).unwrap_or(PolicyDecision::Allowed);
    let execution_status = provider_output_execution_status(output).unwrap_or_else(|| {
        if output
            .get("external_adapter_required")
            .and_then(Value::as_bool)
            == Some(true)
        {
            ExecutionStatus::Incomplete
        } else {
            ExecutionStatus::Completed
        }
    });
    let side_effect_executed = provider_output_side_effect_executed(&call.provider, output);

    if decision != PolicyDecision::Allowed {
        let gate_id = output
            .get("gate_id")
            .and_then(Value::as_str)
            .unwrap_or("provider_adapter");
        let reason = output
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("provider adapter did not allow execution");
        let error_kind = output
            .get("error_kind")
            .cloned()
            .and_then(|value| serde_json::from_value::<ErrorKind>(value).ok());
        let mut final_outcome =
            ProviderOutcome::before_side_effect(decision, call, gate_id, reason, error_kind);
        final_outcome.execution_status = execution_status;
        final_outcome.envelope.denied_by = Some(gate_id.to_string());
        final_outcome.envelope.side_effect_executed = side_effect_executed;
        final_outcome.output = output.clone();
        final_outcome.artifacts = outcome.artifacts.clone();
        final_outcome.next_actions = outcome.next_actions.clone();
        *outcome = final_outcome;
        return;
    }

    outcome.decision = decision.clone();
    outcome.execution_status = execution_status;
    outcome.envelope.decision = decision.clone();
    outcome.envelope.side_effect_executed = side_effect_executed;
    outcome.envelope.trace_event = Some(provider_trace_event_for_decision(&decision).to_string());
    outcome.output = output.clone();
}

fn provider_output_decision(output: &Value) -> Option<PolicyDecision> {
    match output.get("decision").and_then(Value::as_str)? {
        "allowed" => Some(PolicyDecision::Allowed),
        "denied" => Some(PolicyDecision::Denied),
        "requires_review" => Some(PolicyDecision::RequiresReview),
        _ => None,
    }
}

fn provider_output_execution_status(output: &Value) -> Option<ExecutionStatus> {
    match output.get("execution_status").and_then(Value::as_str)? {
        "not_executed" => Some(ExecutionStatus::NotExecuted),
        "running" => Some(ExecutionStatus::Running),
        "completed" => Some(ExecutionStatus::Completed),
        "failed" => Some(ExecutionStatus::Failed),
        "incomplete" => Some(ExecutionStatus::Incomplete),
        _ => None,
    }
}

fn provider_trace_event_for_decision(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allowed => "provider_policy_evaluated",
        PolicyDecision::Denied => "provider_denied",
        PolicyDecision::RequiresReview => "provider_requires_review",
    }
}

fn first_party_output_side_effect_executed(output: &Value) -> bool {
    output
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn load_agent_native_cases(
    root: &Path,
    configs: Vec<PathBuf>,
) -> Result<Vec<AgentNativeConfigCase>, String> {
    let paths = if configs.is_empty() {
        vec![
            (
                root.join("examples/agent-configs/claude.runwarden-only.json"),
                AgentNativeExpectation::RunwardenOnlyAllowed,
            ),
            (
                root.join("examples/agent-configs/unsafe.raw-filesystem.json"),
                AgentNativeExpectation::RawToolsDenied,
            ),
            (
                root.join("examples/agent-configs/unsafe.raw-shell.json"),
                AgentNativeExpectation::RawToolsDenied,
            ),
        ]
    } else {
        configs
            .into_iter()
            .map(|path| {
                let expectation = expectation_for_config_path(&path);
                (path, expectation)
            })
            .collect()
    };

    paths
        .into_iter()
        .map(|(path, expectation)| {
            let body = fs::read_to_string(&path)
                .map_err(|err| format!("failed to read agent config {}: {err}", path.display()))?;
            let config = serde_json::from_str(&body)
                .map_err(|err| format!("failed to parse agent config {}: {err}", path.display()))?;
            Ok(AgentNativeConfigCase {
                id: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("agent-config")
                    .to_string(),
                config,
                expectation,
            })
        })
        .collect()
}

fn expectation_for_config_path(path: &Path) -> AgentNativeExpectation {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("unsafe") || name.contains("raw-") || name.contains("raw_") {
        AgentNativeExpectation::RawToolsDenied
    } else {
        AgentNativeExpectation::RunwardenOnlyAllowed
    }
}

fn find_workspace_root(mut current: PathBuf) -> Result<PathBuf, String> {
    loop {
        if current.join("Cargo.toml").exists() && current.join("package.json").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err("could not find Runwarden workspace root".to_string());
        }
    }
}

fn string_field(body: &Value, name: &str) -> Option<String> {
    body.get(name)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn number_field(body: &Value, name: &str) -> Option<usize> {
    body.get(name)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
}
