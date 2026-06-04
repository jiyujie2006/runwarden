use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use runwarden_assurance::accountability::accountability_summary;
use runwarden_assurance::artifact::{seal_artifact, verify_artifact_manifest};
use runwarden_assurance::audit::audit_summary;
use runwarden_assurance::bench::benchmark_workspace;
use runwarden_assurance::cert::{certify_agent_config, certify_workspace};
use runwarden_assurance::eval::{
    AgentNativeConfigCase, AgentNativeExpectation, EvalThresholds, evaluate_agent_native_configs,
    evaluate_report_assurance,
};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report, scaffold_report_from_trace,
};
use runwarden_kernel::artifact::ArtifactManifest;
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::contracts::{
    ErrorKind, ExecutionStatus, PolicyDecision, ProviderCall, ProviderClass, ProviderOutcome,
    SideEffectKind,
};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery, hex_sha256};
use runwarden_kernel::kernel::{KernelEnforcer, KernelPolicy};
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_providers::catalog::{
    EXTERNAL_PROVIDER_IDS, FIRST_PARTY_PROVIDER_IDS, full_provider_registry,
};
use runwarden_providers::evidence::{EvidenceInspectPolicy, inspect_evidence_root};
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use serde_json::{Value, json};

pub const LOCAL_API_SECURITY_MODEL: &str =
    "launch token + host/origin checks + kernel-owned decisions";
const MAX_LOCAL_API_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_LOCAL_API_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const REVIEWER_CONSOLE_SCRIPT_NAME: &str = "reviewer-console.js";

#[derive(Debug, Clone)]
pub struct LocalApiRequest {
    pub method: String,
    pub path: String,
    headers: BTreeMap<String, String>,
}

impl LocalApiRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into().to_ascii_uppercase(),
            path: path.into(),
            headers: BTreeMap::new(),
        }
    }

    pub fn header(mut self, name: impl AsRef<str>, value: impl Into<String>) -> Self {
        self.headers
            .insert(normalize_header_name(name.as_ref()), value.into());
        self
    }

    pub fn bearer_token(self, token: impl AsRef<str>) -> Self {
        self.header("Authorization", format!("Bearer {}", token.as_ref()))
    }

    pub fn remove_header(&mut self, name: impl AsRef<str>) {
        self.headers.remove(&normalize_header_name(name.as_ref()));
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&normalize_header_name(name))
            .map(String::as_str)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalApiResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone)]
pub struct LocalApiServerConfig {
    pub launch_token: String,
    pub allowed_host: String,
    pub allowed_origin: String,
}

pub struct LocalApiRouter {
    security: LocalApiSecurity,
}

struct OperationFailure {
    http_status: u16,
    operation_status: &'static str,
    kind: &'static str,
    message: String,
    data: Value,
    side_effect_executed: bool,
}

impl LocalApiRouter {
    pub fn new(security: LocalApiSecurity) -> Self {
        Self { security }
    }

    pub fn from_config(config: LocalApiServerConfig) -> Self {
        Self::new(LocalApiSecurity::new(
            config.launch_token,
            [config.allowed_host],
            [config.allowed_origin],
        ))
    }

    pub fn handle(&mut self, request: LocalApiRequest, body: Option<Value>) -> LocalApiResponse {
        let route_path = route_path(&request.path);
        if request.method == "OPTIONS" {
            return self.security.authorize_preflight(&request);
        }
        if route_path != "/health" && route_path != "/artifacts/download" {
            let authorization = self.security.authorize_control_plane(&request);
            if authorization.status != 200 {
                return authorization;
            }
        }
        if request.method == "GET"
            && route_path.starts_with("/providers/")
            && route_path.ends_with("/status")
        {
            let provider_id = route_path
                .trim_start_matches("/providers/")
                .trim_end_matches("/status")
                .trim_end_matches('/');
            return self.provider_status(&request, provider_id);
        }
        if request.method == "POST"
            && route_path.starts_with("/approvals/")
            && route_path.ends_with("/approve")
        {
            let approval_id = route_path
                .trim_start_matches("/approvals/")
                .trim_end_matches("/approve")
                .trim_end_matches('/');
            return self.approval_decision(&request, approval_id, ApprovalDecision::Approve, body);
        }
        if request.method == "POST"
            && route_path.starts_with("/approvals/")
            && route_path.ends_with("/deny")
        {
            let approval_id = route_path
                .trim_start_matches("/approvals/")
                .trim_end_matches("/deny")
                .trim_end_matches('/');
            return self.approval_decision(&request, approval_id, ApprovalDecision::Deny, body);
        }

        match (request.method.as_str(), route_path) {
            ("GET", "/health") => LocalApiResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: json!({
                    "ok": true,
                    "service": "runwarden-local-api",
                    "side_effect_executed": false
                }),
            },
            ("GET", "/approvals") => self.security.approval_queue(&request),
            ("GET", "/dashboard") => self.operation_response(
                &request,
                json!({
                    "risk_status": "ready",
                    "trace_integrity": "verified_before_export",
                    "pending_approvals": self.security.pending_approval_count(),
                    "session_count": self.security.sessions.len(),
                    "fast_gate": "available",
                    "full_gate": "available"
                }),
                false,
                [],
            ),
            ("GET", "/agent-boundary") => self.operation_response(
                &request,
                json!({
                    "agent_only_sees_runwarden": true,
                    "raw_side_effect_tools_allowed": false,
                    "kernel_managed_providers": true
                }),
                false,
                [],
            ),
            ("GET", "/providers") => self.provider_list(&request),
            ("POST", "/provider-calls") => self.provider_call(&request, body),
            ("POST", "/sessions") => self.session_create(&request, body),
            ("POST", "/trace/export") => self.trace_export(&request, body),
            ("GET", "/audit/summary") => self.audit_summary(&request),
            ("GET", "/accountability/summary") => self.accountability_summary(&request),
            ("POST", "/reports/lint") => self.report_lint(&request, body),
            ("POST", "/reports/render") => self.report_render(&request, body, false),
            ("POST", "/reports/preview") => self.report_render(&request, body, true),
            ("POST", "/artifacts/verify") => self.artifact_verify(&request, body),
            ("POST", "/artifacts/token") => self.artifact_token(&request, body),
            ("GET", "/artifacts/download") | ("POST", "/artifacts/download") => {
                self.artifact_download(&request, body)
            }
            ("POST", "/artifacts/submission") => self.artifact_submission(&request, body),
            ("POST", "/eval/agent-native") => self.eval_agent_native(&request, body),
            ("POST", "/release/smoke") => self.release_smoke(&request),
            ("POST", "/ui/launch") => self.ui_launch(&request, body),
            ("POST", "/agent/config/check") => self.agent_config_check(&request, body),
            _ => {
                let authorization = self.security.authorize_control_plane(&request);
                if authorization.status != 200 {
                    return authorization;
                }
                response_with_headers(
                    404,
                    authorization.headers,
                    json!({
                        "error": "Runwarden Local API route not found",
                        "path": request.path,
                        "side_effect_executed": false
                    }),
                )
            }
        }
    }

    fn provider_list(&self, request: &LocalApiRequest) -> LocalApiResponse {
        if let Some(session_id) = query_param(&request.path, "session") {
            let Some(session) = self.security.sessions.get(&session_id) else {
                return self.operation_error(
                    request,
                    404,
                    "denied",
                    "manifest_invalid",
                    "session was not found",
                    false,
                );
            };
            return self.operation_response(
                request,
                json!({ "providers": session.allowed_providers }),
                false,
                [],
            );
        }

        let providers: Vec<_> = FIRST_PARTY_PROVIDER_IDS
            .iter()
            .chain(EXTERNAL_PROVIDER_IDS.iter())
            .map(|provider| (*provider).to_string())
            .collect();
        self.operation_response(
            request,
            json!({
                "providers": providers,
                "security_model": LOCAL_API_SECURITY_MODEL
            }),
            false,
            [],
        )
    }

    fn provider_status(&self, request: &LocalApiRequest, provider_id: &str) -> LocalApiResponse {
        let registry = full_provider_registry();
        let Some(provider) = registry.get(provider_id) else {
            return self.operation_error(
                request,
                404,
                "denied",
                "provider_unknown",
                "provider is not registered",
                false,
            );
        };

        self.operation_response(
            request,
            json!({
                "provider": provider,
                "registered": true,
                "kernel_managed": true
            }),
            false,
            [],
        )
    }

    fn approval_decision(
        &mut self,
        request: &LocalApiRequest,
        approval_id: &str,
        decision: ApprovalDecision,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let Some(body) = body else {
            return self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                "approval review body is required",
                false,
            );
        };
        let input = ApprovalDecisionInput {
            decision,
            reviewer: string_field(&body, "reviewer").unwrap_or_default(),
            reason: string_field(&body, "reason").unwrap_or_default(),
        };
        self.security.decide_approval(request, approval_id, input)
    }

    fn session_create(
        &mut self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let Some(body) = body else {
            return operation_error_with_headers(
                400,
                authorization.headers,
                "failed",
                "argument_schema_invalid",
                "session manifest body is required",
                false,
            );
        };
        let session_id = match string_field(&body, "session_id") {
            Some(value) => value,
            None => {
                return operation_error_with_headers(
                    400,
                    authorization.headers,
                    "failed",
                    "argument_schema_invalid",
                    "session_id is required",
                    false,
                );
            }
        };
        let manifest_toml = match string_field(&body, "manifest_toml") {
            Some(value) => value,
            None => {
                return operation_error_with_headers(
                    400,
                    authorization.headers,
                    "failed",
                    "argument_schema_invalid",
                    "manifest_toml is required",
                    false,
                );
            }
        };
        let assessment = match AssessmentManifest::from_toml_str(&manifest_toml) {
            Ok(assessment) => assessment,
            Err(err) => {
                return operation_error_with_headers(
                    400,
                    authorization.headers,
                    "failed",
                    "manifest_invalid",
                    format!("assessment manifest is invalid: {err}"),
                    false,
                );
            }
        };
        let session = SessionManifest::from_assessment(session_id, &assessment);
        self.security
            .sessions
            .insert(session.session_id.clone(), session.clone());

        operation_response_with_headers(
            200,
            authorization.headers,
            json!({ "session": session }),
            true,
            ["inspect_session_manifest"],
        )
    }

    fn provider_call(
        &mut self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let authorization_headers = authorization.headers;
        let Some(body) = body else {
            return operation_error_with_headers(
                400,
                authorization_headers,
                "failed",
                "argument_schema_invalid",
                "provider call body is required",
                false,
            );
        };
        let call: ProviderCall = match serde_json::from_value(body) {
            Ok(call) => call,
            Err(err) => {
                return operation_error_with_headers(
                    400,
                    authorization_headers,
                    "failed",
                    "argument_schema_invalid",
                    format!("provider call body is invalid: {err}"),
                    false,
                );
            }
        };
        let Some(session) = self.security.sessions.get(&call.session_id).cloned() else {
            return operation_error_with_headers(
                404,
                authorization_headers,
                "denied",
                "manifest_invalid",
                "session was not found",
                false,
            );
        };

        let mut enforcer =
            KernelEnforcer::new(full_provider_registry(), session.to_kernel_policy());
        for approval in self.security.approvals.values().cloned() {
            enforcer.add_approval(approval);
        }
        let mut outcome = enforcer.evaluate_call(&call);
        if outcome.decision == PolicyDecision::RequiresReview
            && outcome.envelope.approval_id.is_none()
        {
            let binding = enforcer.approval_binding_for_call(&call);
            self.enqueue_pending_approval(&mut outcome, binding);
        }
        if outcome.decision == PolicyDecision::Allowed {
            if call
                .approval_id
                .as_deref()
                .and_then(|approval_id| enforcer.approval_state(approval_id))
                == Some(ApprovalState::Consumed)
            {
                self.security
                    .persist_consumed_approval(&call, &enforcer.approval_binding_for_call(&call));
            }
            match execute_first_party_provider_call(&call, Some(&session)) {
                Ok(output) => {
                    let side_effect_executed =
                        provider_output_side_effect_executed(&call.provider, &output);
                    outcome.execution_status = if output
                        .get("external_adapter_required")
                        .and_then(Value::as_bool)
                        == Some(true)
                    {
                        ExecutionStatus::Incomplete
                    } else {
                        ExecutionStatus::Completed
                    };
                    outcome.envelope.side_effect_executed = side_effect_executed;
                    outcome.output = output;
                }
                Err(message) => {
                    outcome.decision = PolicyDecision::Denied;
                    outcome.execution_status = ExecutionStatus::Failed;
                    outcome.envelope.decision = PolicyDecision::Denied;
                    outcome.envelope.error_kind = Some(ErrorKind::Internal);
                    outcome.envelope.reason = message;
                }
            }
        }

        let side_effect_executed = outcome.envelope.side_effect_executed;
        operation_response_with_headers(
            200,
            authorization_headers,
            json!({
                "outcome": outcome,
                "api_owns_security_decision": false,
                "kernel_enforcement_required": true
            }),
            side_effect_executed,
            ["inspect_provider_outcome"],
        )
    }

    fn trace_export(&self, request: &LocalApiRequest, body: Option<Value>) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let authorization_headers = authorization.headers;
        let Some(body) = body else {
            return operation_error_with_headers(
                400,
                authorization_headers,
                "failed",
                "argument_schema_invalid",
                "trace export body is required",
                false,
            );
        };
        let events = match read_trace_from_body(&body) {
            Ok(events) => events,
            Err(message) => {
                return operation_error_with_headers(
                    400,
                    authorization_headers,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        let mut store = InMemoryTraceStore::default();
        for event in events {
            store.append(event);
        }
        let query = trace_query_from_body(&body);
        match store.stream_export(query) {
            Ok(page) => operation_response_with_headers(
                200,
                authorization_headers,
                json!(page),
                false,
                ["query_next_trace_page"],
            ),
            Err(err) => operation_error_with_headers(
                422,
                authorization_headers,
                "denied",
                "trace_tampered",
                err.to_string(),
                false,
            ),
        }
    }

    fn audit_summary(&self, request: &LocalApiRequest) -> LocalApiResponse {
        let events = query_param(&request.path, "trace_path")
            .map(|path| read_trace_file(Path::new(&path)))
            .transpose();
        match events {
            Ok(events) => self.operation_response(
                request,
                json!(audit_summary(&events.unwrap_or_default())),
                false,
                [],
            ),
            Err(message) => self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                message,
                false,
            ),
        }
    }

    fn accountability_summary(&self, request: &LocalApiRequest) -> LocalApiResponse {
        let events = query_param(&request.path, "trace_path")
            .map(|path| read_trace_file(Path::new(&path)))
            .transpose();
        match events {
            Ok(events) => self.operation_response(
                request,
                json!(accountability_summary(&events.unwrap_or_default())),
                false,
                [],
            ),
            Err(message) => self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                message,
                false,
            ),
        }
    }

    fn report_lint(&self, request: &LocalApiRequest, body: Option<Value>) -> LocalApiResponse {
        let Some(body) = body else {
            return self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                "report lint body is required",
                false,
            );
        };
        let (report, trace) = match read_report_and_trace_from_body(&body) {
            Ok(values) => values,
            Err(message) => {
                return self.operation_error(
                    request,
                    400,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        let lint = lint_report_against_trace(&report, &trace);
        if lint.ok {
            self.operation_response(request, json!(lint), false, ["render_report_after_lint"])
        } else {
            self.operation_failure_data(
                request,
                OperationFailure {
                    http_status: 422,
                    operation_status: "denied",
                    kind: "report_citation_invalid",
                    message: "report citation lint failed".to_string(),
                    data: json!(lint),
                    side_effect_executed: false,
                },
            )
        }
    }

    fn report_render(
        &mut self,
        request: &LocalApiRequest,
        body: Option<Value>,
        preview: bool,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let authorization_headers = authorization.headers;
        let Some(body) = body else {
            return operation_error_with_headers(
                400,
                authorization_headers,
                "failed",
                "argument_schema_invalid",
                "report render body is required",
                false,
            );
        };
        if !preview {
            let call = local_api_report_render_call(&body);
            let policy = match string_field(&body, "session_id") {
                Some(session_id) => match self.security.sessions.get(&session_id) {
                    Some(session) => session.to_kernel_policy(),
                    None => {
                        return operation_error_with_headers(
                            404,
                            authorization_headers,
                            "denied",
                            "manifest_invalid",
                            "session was not found",
                            false,
                        );
                    }
                },
                None => local_api_default_report_render_policy(),
            };
            let mut enforcer = KernelEnforcer::new(full_provider_registry(), policy);
            for approval in self.security.approvals.values().cloned() {
                enforcer.add_approval(approval);
            }
            let mut outcome = enforcer.evaluate_call(&call);
            if outcome.decision == PolicyDecision::RequiresReview
                && outcome.envelope.approval_id.is_none()
            {
                let binding = enforcer.approval_binding_for_call(&call);
                self.enqueue_pending_approval(&mut outcome, binding);
            }
            if outcome.decision != PolicyDecision::Allowed {
                return operation_response_with_headers(
                    200,
                    authorization_headers,
                    json!({
                        "outcome": outcome,
                        "api_owns_security_decision": false,
                        "kernel_enforcement_required": true
                    }),
                    false,
                    ["review_approval"],
                );
            }
            if call
                .approval_id
                .as_deref()
                .and_then(|approval_id| enforcer.approval_state(approval_id))
                == Some(ApprovalState::Consumed)
            {
                self.security
                    .persist_consumed_approval(&call, &enforcer.approval_binding_for_call(&call));
            }
        }
        let (report, trace) = match read_report_and_trace_from_body(&body) {
            Ok(values) => values,
            Err(message) => {
                return operation_error_with_headers(
                    400,
                    authorization_headers,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        let format = match parse_render_format(
            string_field(&body, "format")
                .as_deref()
                .unwrap_or("markdown"),
        ) {
            Ok(format) => format,
            Err(message) => {
                return operation_error_with_headers(
                    400,
                    authorization_headers,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        match render_report(&report, &trace, format) {
            Ok(rendered) => operation_response_with_headers(
                200,
                authorization_headers,
                json!({ "preview": preview, "rendered": rendered }),
                false,
                ["download_rendered_artifact_with_token"],
            ),
            Err(err) => operation_error_with_headers(
                422,
                authorization_headers,
                "denied",
                "report_citation_invalid",
                err.message,
                false,
            ),
        }
    }

    fn enqueue_pending_approval(
        &mut self,
        outcome: &mut ProviderOutcome,
        binding: ApprovalBinding,
    ) {
        let approval_id = pending_approval_id_for_binding(&binding);
        let should_insert = self
            .security
            .approvals
            .get(&approval_id)
            .map(|approval| {
                !matches!(
                    approval.state,
                    ApprovalState::Pending | ApprovalState::Approved
                )
            })
            .unwrap_or(true);
        if should_insert {
            self.security
                .insert_approval(ApprovalRecord::new(&approval_id, binding));
        }
        let approval = self
            .security
            .approvals
            .get(&approval_id)
            .cloned()
            .expect("pending approval was inserted");
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
    }

    fn artifact_verify(&self, request: &LocalApiRequest, body: Option<Value>) -> LocalApiResponse {
        let Some(body) = body else {
            return self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                "artifact verify body is required",
                false,
            );
        };
        let artifacts_path = match string_field(&body, "artifacts_path") {
            Some(path) => PathBuf::from(path),
            None => {
                return self.operation_error(
                    request,
                    400,
                    "failed",
                    "argument_schema_invalid",
                    "artifacts_path is required",
                    false,
                );
            }
        };
        let manifest = match read_artifact_manifest_from_body(&body) {
            Ok(manifest) => manifest,
            Err(message) => {
                return self.operation_error(
                    request,
                    400,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        let verification = verify_artifact_manifest(&artifacts_path, &manifest);
        if verification.findings.is_empty() {
            self.operation_response(request, json!(verification), false, [])
        } else {
            self.operation_failure_data(
                request,
                OperationFailure {
                    http_status: 422,
                    operation_status: "denied",
                    kind: "artifact_invalid",
                    message: "artifact manifest verification failed".to_string(),
                    data: json!(verification),
                    side_effect_executed: false,
                },
            )
        }
    }

    fn artifact_token(
        &mut self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let artifact_id = match body
            .as_ref()
            .and_then(|body| string_field(body, "artifact_id"))
        {
            Some(artifact_id) => artifact_id,
            None => {
                return operation_error_with_headers(
                    400,
                    authorization.headers,
                    "failed",
                    "argument_schema_invalid",
                    "artifact_id is required",
                    false,
                );
            }
        };
        let token = self.security.issue_artifact_download_token(&artifact_id);
        operation_response_with_headers(
            200,
            authorization.headers,
            json!({
                "artifact_id": artifact_id,
                "token": token,
                "token_policy": "single_use",
                "issued": true,
                "expires_after_seconds": 300
            }),
            true,
            ["consume_token_once_when_downloading_artifact"],
        )
    }

    fn artifact_download(
        &mut self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let token = query_param(&request.path, "token")
            .or_else(|| body.as_ref().and_then(|body| string_field(body, "token")));
        let Some(token) = token else {
            return operation_error_with_headers(
                400,
                BTreeMap::new(),
                "failed",
                "argument_schema_invalid",
                "artifact download token is required",
                false,
            );
        };

        let mut response = self.security.consume_artifact_download_token(&token);
        response
            .headers
            .extend(self.security.optional_cors_headers(request));
        response
    }

    fn artifact_submission(
        &self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let authorization_headers = authorization.headers;
        let output_path = body
            .as_ref()
            .and_then(|body| string_field(body, "output_path"))
            .unwrap_or_else(|| "artifacts".to_string());
        let full = body
            .as_ref()
            .and_then(|body| body.get("full"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let root = match find_workspace_root(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ) {
            Ok(root) => root,
            Err(message) => {
                return operation_error_with_headers(
                    500,
                    authorization_headers,
                    "failed",
                    "internal",
                    message,
                    false,
                );
            }
        };
        let output_path = match resolve_local_artifact_output_path(&root, &output_path) {
            Ok(path) => path,
            Err(message) => {
                return operation_error_with_headers(
                    400,
                    authorization_headers,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        match write_submission_bundle(&root, &output_path, full) {
            Ok(result) => operation_response_with_headers(
                200,
                authorization_headers,
                result,
                true,
                ["verify_artifacts"],
            ),
            Err(message) => operation_error_with_headers(
                500,
                authorization_headers,
                "failed",
                "internal",
                message,
                true,
            ),
        }
    }

    fn eval_agent_native(
        &self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let root = match find_workspace_root(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ) {
            Ok(root) => root,
            Err(message) => {
                return self.operation_error(request, 500, "failed", "internal", message, false);
            }
        };
        let config_paths = body
            .as_ref()
            .and_then(|body| body.get("config_paths"))
            .and_then(Value::as_array)
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(Value::as_str)
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        match load_agent_native_cases(&root, config_paths) {
            Ok(cases) => self.operation_response(
                request,
                json!(evaluate_agent_native_configs(&cases)),
                false,
                [],
            ),
            Err(message) => self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                message,
                false,
            ),
        }
    }

    fn release_smoke(&self, request: &LocalApiRequest) -> LocalApiResponse {
        let root = match find_workspace_root(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ) {
            Ok(root) => root,
            Err(message) => {
                return self.operation_error(request, 500, "failed", "internal", message, false);
            }
        };
        match release_smoke_report(&root) {
            Ok(report) => self.operation_response(request, report, false, []),
            Err(message) => {
                self.operation_error(request, 500, "failed", "internal", message, false)
            }
        }
    }

    fn ui_launch(&self, request: &LocalApiRequest, body: Option<Value>) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        let authorization_headers = authorization.headers;
        let Some(body) = body else {
            return operation_error_with_headers(
                400,
                authorization_headers,
                "failed",
                "argument_schema_invalid",
                "ui launch body is required",
                false,
            );
        };
        let bind = string_field(&body, "bind").unwrap_or_else(|| "127.0.0.1".to_string());
        let port = number_field(&body, "port").unwrap_or(8088);
        let artifacts_path =
            string_field(&body, "artifacts_path").unwrap_or_else(|| "artifacts".to_string());
        let root = match find_workspace_root(
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        ) {
            Ok(root) => root,
            Err(message) => {
                return operation_error_with_headers(
                    500,
                    authorization_headers,
                    "failed",
                    "internal",
                    message,
                    false,
                );
            }
        };
        let artifacts_path = match resolve_local_artifact_output_path(&root, &artifacts_path) {
            Ok(path) => path,
            Err(message) => {
                return operation_error_with_headers(
                    400,
                    authorization_headers,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        let snapshot = UiLaunchSnapshot {
            approvals: self.security.approvals.values().cloned().collect(),
            sessions: self.security.sessions.values().cloned().collect(),
        };
        match write_ui_launch_bundle(&bind, port as u16, &artifacts_path, snapshot) {
            Ok(result) => {
                operation_response_with_headers(200, authorization_headers, result, true, [])
            }
            Err(message) => operation_error_with_headers(
                500,
                authorization_headers,
                "failed",
                "internal",
                message,
                true,
            ),
        }
    }

    fn agent_config_check(
        &self,
        request: &LocalApiRequest,
        body: Option<Value>,
    ) -> LocalApiResponse {
        let Some(body) = body else {
            return self.operation_error(
                request,
                400,
                "failed",
                "argument_schema_invalid",
                "agent config check body is required",
                false,
            );
        };
        let client = string_field(&body, "client").unwrap_or_else(|| "generic".to_string());
        let input_path = match string_field(&body, "input_path") {
            Some(path) => path,
            None => {
                return self.operation_error(
                    request,
                    400,
                    "failed",
                    "argument_schema_invalid",
                    "input_path is required",
                    false,
                );
            }
        };
        let config = match read_json_file(Path::new(&input_path)) {
            Ok(config) => config,
            Err(message) => {
                return self.operation_error(
                    request,
                    400,
                    "failed",
                    "argument_schema_invalid",
                    message,
                    false,
                );
            }
        };
        let report = certify_agent_config(&config);
        self.operation_response(
            request,
            json!({
                "client": client,
                "safe": report.passed,
                "cert": report
            }),
            false,
            [],
        )
    }

    fn operation_response<const N: usize>(
        &self,
        request: &LocalApiRequest,
        data: Value,
        side_effect_executed: bool,
        next_actions: [&str; N],
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        operation_response_with_headers(
            200,
            authorization.headers,
            data,
            side_effect_executed,
            next_actions,
        )
    }

    fn operation_error(
        &self,
        request: &LocalApiRequest,
        http_status: u16,
        operation_status: &str,
        kind: &str,
        message: impl Into<String>,
        side_effect_executed: bool,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        operation_error_with_headers(
            http_status,
            authorization.headers,
            operation_status,
            kind,
            message,
            side_effect_executed,
        )
    }

    fn operation_failure_data(
        &self,
        request: &LocalApiRequest,
        failure: OperationFailure,
    ) -> LocalApiResponse {
        let authorization = self.security.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }
        operation_failure_data_with_headers(
            failure.http_status,
            authorization.headers,
            failure.operation_status,
            failure.kind,
            failure.message,
            failure.data,
            failure.side_effect_executed,
        )
    }
}

fn route_path(path: &str) -> &str {
    path.split_once('?').map(|(route, _)| route).unwrap_or(path)
}

fn query_param(path: &str, name: &str) -> Option<String> {
    let (_, query) = path.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| value.to_string())
    })
}

fn pending_approval_id_for_binding(binding: &ApprovalBinding) -> String {
    let digest = hex_sha256(&serde_json::to_vec(binding).expect("approval binding serializes"));
    format!("approval_{}", &digest[..16])
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

fn operation_response_with_headers<const N: usize>(
    status: u16,
    headers: BTreeMap<String, String>,
    data: Value,
    side_effect_executed: bool,
    next_actions: [&str; N],
) -> LocalApiResponse {
    let next_actions: Vec<_> = next_actions.into_iter().collect();
    response_with_headers(
        status,
        headers,
        json!({
            "operation": {
                "ok": true,
                "status": "ok",
                "data": data,
                "error": null,
                "obs_refs": [],
                "artifacts": [],
                "next_actions": next_actions
            },
            "side_effect_executed": side_effect_executed
        }),
    )
}

fn operation_error_with_headers(
    status: u16,
    headers: BTreeMap<String, String>,
    operation_status: &str,
    kind: &str,
    message: impl Into<String>,
    side_effect_executed: bool,
) -> LocalApiResponse {
    operation_failure_data_with_headers(
        status,
        headers,
        operation_status,
        kind,
        message,
        Value::Null,
        side_effect_executed,
    )
}

fn operation_failure_data_with_headers(
    status: u16,
    headers: BTreeMap<String, String>,
    operation_status: &str,
    kind: &str,
    message: impl Into<String>,
    data: Value,
    side_effect_executed: bool,
) -> LocalApiResponse {
    let message = message.into();
    response_with_headers(
        status,
        headers,
        json!({
            "operation": {
                "ok": false,
                "status": operation_status,
                "data": data,
                "error": {
                    "kind": kind,
                    "code": format!("RW_{}", kind),
                    "user_message": message,
                    "developer_message": "Runwarden rejected or failed the operation before treating it as trusted.",
                    "obs_refs": [],
                    "retryable": false,
                    "side_effect_executed": side_effect_executed
                },
                "obs_refs": [],
                "artifacts": [],
                "next_actions": []
            },
            "side_effect_executed": side_effect_executed
        }),
    )
}

fn string_field(body: &Value, name: &str) -> Option<String> {
    body.get(name)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn local_api_default_report_render_policy() -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.allow_provider("runwarden.report.render");
    policy.active_assessment = true;
    policy
}

fn local_api_report_render_call(body: &Value) -> ProviderCall {
    ProviderCall {
        session_id: string_field(body, "session_id")
            .unwrap_or_else(|| "local-api-report-render".to_string()),
        provider: "runwarden.report.render".to_string(),
        action: "render".to_string(),
        arguments: provider_arguments_from_local_api_body(body),
        actor_id: string_field(body, "actor_id"),
        authz_id: string_field(body, "authz_id"),
        approval_id: string_field(body, "approval_id"),
    }
}

fn provider_arguments_from_local_api_body(body: &Value) -> Value {
    let mut arguments = body.clone();
    if let Some(object) = arguments.as_object_mut() {
        for key in ["session_id", "actor_id", "authz_id", "approval_id"] {
            object.remove(key);
        }
    }
    arguments
}

fn number_field(body: &Value, name: &str) -> Option<usize> {
    body.get(name)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn read_json_file(path: &Path) -> Result<Value, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&body).map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn read_trace_file(path: &Path) -> Result<Vec<TraceEvent>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("failed to read trace {}: {err}", path.display()))?;
    serde_json::from_str(&body)
        .map_err(|err| format!("failed to parse trace {}: {err}", path.display()))
}

fn read_trace_from_body(body: &Value) -> Result<Vec<TraceEvent>, String> {
    if let Some(trace) = body.get("trace") {
        return serde_json::from_value(trace.clone())
            .map_err(|err| format!("trace is invalid: {err}"));
    }
    let path =
        string_field(body, "trace_path").ok_or_else(|| "trace_path is required".to_string())?;
    read_trace_file(Path::new(&path))
}

fn read_report_from_body(body: &Value) -> Result<ReportDraft, String> {
    if let Some(report) = body.get("report") {
        return serde_json::from_value(report.clone())
            .map_err(|err| format!("report is invalid: {err}"));
    }
    let path =
        string_field(body, "report_path").ok_or_else(|| "report_path is required".to_string())?;
    let body =
        fs::read_to_string(&path).map_err(|err| format!("failed to read report {path}: {err}"))?;
    serde_json::from_str(&body).map_err(|err| format!("failed to parse report {path}: {err}"))
}

fn read_report_and_trace_from_body(body: &Value) -> Result<(ReportDraft, Vec<TraceEvent>), String> {
    Ok((read_report_from_body(body)?, read_trace_from_body(body)?))
}

fn read_artifact_manifest_from_body(body: &Value) -> Result<ArtifactManifest, String> {
    if let Some(manifest) = body.get("manifest") {
        return serde_json::from_value(manifest.clone())
            .map_err(|err| format!("artifact manifest is invalid: {err}"));
    }
    let path = string_field(body, "manifest_path")
        .ok_or_else(|| "manifest_path is required".to_string())?;
    let body = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read artifact manifest {path}: {err}"))?;
    serde_json::from_str(&body)
        .map_err(|err| format!("failed to parse artifact manifest {path}: {err}"))
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
            "error_kind": "trace_tampered",
            "event_count": event_count,
            "offset": err.offset,
            "obs_id": err.obs_id,
            "message": err.reason
        }),
    }
}

fn execute_first_party_provider_call(
    call: &ProviderCall,
    session: Option<&SessionManifest>,
) -> Result<Value, String> {
    let registry = full_provider_registry();
    if registry
        .get(&call.provider)
        .is_some_and(|provider| provider.class == ProviderClass::External)
    {
        return Ok(json!({
            "provider": call.provider,
            "execution_status": "not_executed",
            "external_adapter_required": true,
            "side_effect_executed": false
        }));
    }
    let arguments = resolve_session_path_arguments(session, &call.arguments)?;

    match call.provider.as_str() {
        "runwarden.input.inspect" => {
            let bytes = if let Some(text) = string_field(&arguments, "input_text") {
                text.into_bytes()
            } else {
                let path = string_field(&arguments, "input_path")
                    .ok_or_else(|| "input_text or input_path is required".to_string())?;
                fs::read(&path).map_err(|err| format!("failed to read input {path}: {err}"))?
            };
            Ok(json!(inspect_input(
                InputSource::UserPrompt,
                &bytes,
                InputInspectPolicy::default()
            )))
        }
        "runwarden.evidence.inspect" => {
            let root = string_field(&arguments, "root_path")
                .or_else(|| resolve_session_root_path(session, &arguments))
                .or_else(|| string_field(&arguments, "root"))
                .ok_or_else(|| "root_path is required".to_string())?;
            inspect_evidence_root(Path::new(&root), EvidenceInspectPolicy::default())
                .map(|inspection| json!(inspection))
                .map_err(|err| err.to_string())
        }
        "runwarden.trace.verify" => read_trace_from_body(&arguments).map(verify_trace_events),
        "runwarden.trace.export" => {
            let events = read_trace_from_body(&arguments)?;
            let mut store = InMemoryTraceStore::default();
            for event in events {
                store.append(event);
            }
            store
                .stream_export(trace_query_from_body(&arguments))
                .map(|page| json!(page))
                .map_err(|err| err.to_string())
        }
        "runwarden.report.scaffold" => {
            let events = read_trace_from_body(&arguments)?;
            Ok(json!(scaffold_report_from_trace(&events)))
        }
        "runwarden.report.lint" => {
            let (report, trace) = read_report_and_trace_from_body(&arguments)?;
            Ok(json!(lint_report_against_trace(&report, &trace)))
        }
        "runwarden.report.render" => {
            let (report, trace) = read_report_and_trace_from_body(&arguments)?;
            let format = parse_render_format(
                string_field(&arguments, "format")
                    .as_deref()
                    .unwrap_or("markdown"),
            )?;
            render_report(&report, &trace, format)
                .map(|rendered| json!(rendered))
                .map_err(|err| err.message)
        }
        "runwarden.audit.summary" => {
            let events = read_trace_from_body(&arguments)?;
            Ok(json!(audit_summary(&events)))
        }
        "runwarden.accountability.summary" => {
            let events = read_trace_from_body(&arguments)?;
            Ok(json!(accountability_summary(&events)))
        }
        "runwarden.cert.all" => {
            let root = find_workspace_root(
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?;
            Ok(json!(certify_workspace(&root)))
        }
        "runwarden.eval.all" => {
            let (report, trace) = read_report_and_trace_from_body(&arguments)?;
            let expected_obs: Vec<_> = trace.iter().map(|event| event.obs_id.clone()).collect();
            Ok(json!(evaluate_report_assurance(
                &report,
                &trace,
                expected_obs,
                EvalThresholds::strict()
            )))
        }
        "runwarden.eval.agent-native" => {
            let root = find_workspace_root(
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?;
            let cases = load_agent_native_cases(&root, Vec::new())?;
            Ok(json!(evaluate_agent_native_configs(&cases)))
        }
        "runwarden.bench.run" => {
            let root = find_workspace_root(
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?;
            benchmark_workspace(&root)
                .map(|report| json!(report))
                .map_err(|err| err.to_string())
        }
        other => Err(format!("unsupported first-party provider call: {other}")),
    }
}

fn trace_query_from_body(body: &Value) -> TraceQuery {
    TraceQuery {
        offset: number_field(body, "offset").unwrap_or(0),
        limit: number_field(body, "limit").unwrap_or(100),
        provider: string_field(body, "provider"),
        event_type: string_field(body, "event_type"),
        obs_prefix: string_field(body, "obs_prefix"),
        max_bytes: number_field(body, "max_bytes"),
    }
}

fn resolve_session_path_arguments(
    session: Option<&SessionManifest>,
    arguments: &Value,
) -> Result<Value, String> {
    let mut resolved = arguments.clone();
    let Some(object) = resolved.as_object_mut() else {
        return Ok(resolved);
    };
    for field in ["input_path", "trace_path", "report_path", "root_path"] {
        let Some(path) = object.get(field).and_then(Value::as_str) else {
            continue;
        };
        let path = PathBuf::from(path);
        if path.is_absolute() {
            if !session_path_is_allowed(session, arguments, &path)? {
                return Err(format!("{field} is outside the session scope"));
            }
            continue;
        }
        let Some(resolved_path) = resolve_session_relative_path(session, arguments, &path)? else {
            continue;
        };
        if !session_path_is_allowed(session, arguments, &resolved_path)? {
            return Err(format!("{field} is outside the session scope"));
        }
        object.insert(
            field.to_string(),
            Value::String(resolved_path.to_string_lossy().into_owned()),
        );
    }
    Ok(resolved)
}

fn session_path_is_allowed(
    session: Option<&SessionManifest>,
    arguments: &Value,
    path: &Path,
) -> Result<bool, String> {
    let Some(session) = session else {
        return Ok(true);
    };
    if let Some(root_name) = string_field(arguments, "root") {
        let root = session
            .roots
            .iter()
            .find(|root| root.name == root_name)
            .ok_or_else(|| "requested root is outside the session scope".to_string())?;
        return Ok(path_is_within_root(path, &root.path));
    }
    Ok(session
        .roots
        .iter()
        .any(|root| path_is_within_root(path, &root.path)))
}

fn path_is_within_root(path: &Path, root: &Path) -> bool {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let Ok(canonical_root) = root.canonicalize() else {
        return normalize_path(&candidate).starts_with(normalize_path(root));
    };
    match candidate.canonicalize() {
        Ok(canonical_candidate) => canonical_candidate.starts_with(&canonical_root),
        Err(_) => canonical_existing_parent(&candidate)
            .map(|parent| parent.starts_with(&canonical_root))
            .unwrap_or_else(|| normalize_path(&candidate).starts_with(normalize_path(root))),
    }
}

fn canonical_existing_parent(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent()?.to_path_buf();
    loop {
        if fs::symlink_metadata(&current).is_ok() {
            return current.canonicalize().ok();
        }
        if !current.pop() {
            return None;
        }
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn resolve_local_artifact_output_path(root: &Path, requested: &str) -> Result<PathBuf, String> {
    let requested = Path::new(requested);
    if requested.as_os_str().is_empty()
        || requested.is_absolute()
        || requested.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
            )
        })
    {
        return Err(
            "artifact output path must be a relative path inside the workspace".to_string(),
        );
    }
    let output_path = root.join(requested);
    if !path_is_within_root(&output_path, root) {
        return Err(
            "artifact output path must be a relative path inside the workspace".to_string(),
        );
    }
    Ok(output_path)
}

fn resolve_session_relative_path(
    session: Option<&SessionManifest>,
    arguments: &Value,
    path: &Path,
) -> Result<Option<PathBuf>, String> {
    let Some(session) = session else {
        return Ok(None);
    };
    if let Some(root_name) = string_field(arguments, "root") {
        let root = session
            .roots
            .iter()
            .find(|root| root.name == root_name)
            .ok_or_else(|| "relative path root is outside the session scope".to_string())?;
        return Ok(Some(root.path.join(path)));
    }
    match session.roots.as_slice() {
        [root] => Ok(Some(root.path.join(path))),
        [] => Ok(None),
        _ => Err("relative path requires an explicit scoped root".to_string()),
    }
}

fn resolve_session_root_path(
    session: Option<&SessionManifest>,
    arguments: &Value,
) -> Option<String> {
    let root = string_field(arguments, "root")?;
    let session = session?;
    session
        .roots
        .iter()
        .find(|candidate| candidate.name == root)
        .map(|candidate| candidate.path.to_string_lossy().into_owned())
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
                .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
            let config = serde_json::from_str(&body)
                .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
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

fn write_submission_bundle(root: &Path, output: &Path, full: bool) -> Result<Value, String> {
    fs::create_dir_all(output)
        .map_err(|err| format!("failed to create {}: {err}", output.display()))?;

    let cert_report = certify_workspace(root);
    let bench_report = benchmark_workspace(root).map_err(|err| err.to_string())?;
    let agent_native = evaluate_agent_native_configs(&load_agent_native_cases(root, Vec::new())?);

    let mut manifest = ArtifactManifest {
        schema_version: "0.1".to_string(),
        artifacts: Vec::new(),
    };

    push_sealed_artifact(
        output,
        &mut manifest,
        "submission-report",
        "reports/submission.md",
        "# Runwarden Enterprise Submission\n\nLocal release evidence cites obs_release_gate and obs_agent_native.\n",
    )?;
    push_sealed_artifact(
        output,
        &mut manifest,
        "cert-release-artifact",
        "release/cert-release-artifact.json",
        &serde_json::to_string_pretty(&cert_report).map_err(|err| err.to_string())?,
    )?;
    push_sealed_artifact(
        output,
        &mut manifest,
        "bench-report",
        "release/bench-report.json",
        &serde_json::to_string_pretty(&bench_report).map_err(|err| err.to_string())?,
    )?;
    push_sealed_artifact(
        output,
        &mut manifest,
        "agent-native-eval",
        "release/agent-native-eval.json",
        &serde_json::to_string_pretty(&agent_native).map_err(|err| err.to_string())?,
    )?;

    if full {
        push_sealed_artifact(
            output,
            &mut manifest,
            "sbom",
            "release/sbom.spdx.json",
            &serde_json::to_string_pretty(&workspace_sbom()).map_err(|err| err.to_string())?,
        )?;
        push_sealed_artifact(
            output,
            &mut manifest,
            "provenance",
            "release/provenance.json",
            &serde_json::to_string_pretty(&workspace_provenance())
                .map_err(|err| err.to_string())?,
        )?;
    }

    let manifest_path = output.join("artifact-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(|err| err.to_string())?,
    )
    .map_err(|err| format!("failed to write {}: {err}", manifest_path.display()))?;
    let verification = verify_artifact_manifest(output, &manifest);
    if !verification.findings.is_empty() {
        return Err("generated submission bundle did not verify".to_string());
    }

    Ok(json!({
        "manifest_path": manifest_path.to_string_lossy(),
        "artifact_root": output.to_string_lossy(),
        "artifact_count": manifest.artifacts.len(),
        "artifacts": manifest.artifacts,
        "verification": verification,
        "side_effect_executed": true
    }))
}

fn push_sealed_artifact(
    output: &Path,
    manifest: &mut ArtifactManifest,
    artifact_id: &str,
    relative_path: &str,
    contents: &str,
) -> Result<(), String> {
    let sealed = seal_artifact(output, artifact_id, relative_path, contents).map_err(|err| {
        format!(
            "failed to seal artifact {} at {}: {}",
            artifact_id, err.path, err.message
        )
    })?;
    manifest.artifacts.extend(sealed.artifacts);
    Ok(())
}

fn workspace_sbom() -> Value {
    json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "name": "runwarden-enterprise",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://runwarden.local/sbom/runwarden-enterprise"
    })
}

fn workspace_provenance() -> Value {
    let workspace_digest = hex_sha256(b"workspace-local-release-evidence");
    json!({
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "runwarden"}],
        "buildType": "runwarden.local.release-evidence.v1",
        "builder": {"id": "runwarden local api"},
        "materials": [{"uri": "git+file://runwarden", "digest": {"sha256": workspace_digest}}]
    })
}

fn release_smoke_report(root: &Path) -> Result<Value, String> {
    let cert = certify_workspace(root);
    let bench = benchmark_workspace(root).map_err(|err| err.to_string())?;
    let agent_native = evaluate_agent_native_configs(&load_agent_native_cases(root, Vec::new())?);
    let passed = cert.passed && bench.passed && agent_native.passed;

    Ok(json!({
        "passed": passed,
        "checks": [
            {"id": "cert", "passed": cert.passed, "details": cert.checks},
            {"id": "bench", "passed": bench.passed, "metrics": bench.metrics},
            {
                "id": "agent_native",
                "passed": agent_native.passed,
                "metrics": agent_native.metrics,
                "cases": agent_native.cases
            }
        ],
        "side_effect_executed": false
    }))
}

#[derive(Debug, Clone, Default)]
pub struct UiLaunchSnapshot {
    pub approvals: Vec<ApprovalRecord>,
    pub sessions: Vec<SessionManifest>,
}

#[derive(Debug, Clone, Default)]
struct UiArtifactSummary {
    report_files: Vec<String>,
    artifact_ids: Vec<String>,
    assurance_files: Vec<String>,
}

pub fn write_ui_launch_bundle(
    bind: &str,
    port: u16,
    artifact_root: &Path,
    snapshot: UiLaunchSnapshot,
) -> Result<Value, String> {
    let artifact_summary = collect_ui_artifact_summary(artifact_root);
    fs::create_dir_all(artifact_root)
        .map_err(|err| format!("failed to create {}: {err}", artifact_root.display()))?;
    let html_path = artifact_root.join("reviewer-console.html");
    fs::write(
        &html_path,
        reviewer_console_html(bind, port, &snapshot, &artifact_summary),
    )
    .map_err(|err| format!("failed to write {}: {err}", html_path.display()))?;
    let script_path = artifact_root.join(REVIEWER_CONSOLE_SCRIPT_NAME);
    fs::write(&script_path, reviewer_console_js())
        .map_err(|err| format!("failed to write {}: {err}", script_path.display()))?;
    let launch_path = html_path
        .canonicalize()
        .unwrap_or_else(|_| html_path.clone());

    Ok(json!({
        "bind": bind,
        "port": port,
        "artifact_root": artifact_root.to_string_lossy(),
        "html_path": html_path.to_string_lossy(),
        "script_path": script_path.to_string_lossy(),
        "launch_url": file_url_for_path(&launch_path),
        "local_api_url": format!("http://{bind}:{port}/"),
        "mode": "static_reviewer_console_bundle",
        "side_effect_executed": true
    }))
}

fn reviewer_console_html(
    bind: &str,
    port: u16,
    snapshot: &UiLaunchSnapshot,
    artifacts: &UiArtifactSummary,
) -> String {
    let mut pending: Vec<_> = snapshot
        .approvals
        .iter()
        .filter(|approval| approval.state == ApprovalState::Pending)
        .collect();
    pending.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));

    let session_label = match snapshot.sessions.len() {
        0 => "No assessment loaded".to_string(),
        1 => snapshot.sessions[0].session_id.clone(),
        count => format!("{count} sessions loaded"),
    };
    let session_count = snapshot.sessions.len();
    let agent_message = if session_count == 0 {
        "No agent config checked".to_string()
    } else {
        format!(
            "{} {} loaded",
            session_count,
            plural(session_count, "session boundary", "session boundaries")
        )
    };
    let provider_count = snapshot
        .sessions
        .first()
        .map(|session| session.allowed_providers.len())
        .unwrap_or(0);
    let provider_message = snapshot
        .sessions
        .first()
        .map(|session| {
            let providers = join_preview(&session.allowed_providers, 4);
            format!(
                "{} allowed {}: {}",
                session.allowed_providers.len(),
                plural(session.allowed_providers.len(), "provider", "providers"),
                providers
            )
        })
        .unwrap_or_else(|| "No providers allowed for this session".to_string());
    let approvals_message = if pending.is_empty() {
        "No actions waiting for review".to_string()
    } else {
        format!(
            "{} {} waiting for review",
            pending.len(),
            plural(pending.len(), "action", "actions")
        )
    };
    let report_message = if artifacts.report_files.is_empty() {
        "No report rendered".to_string()
    } else {
        format!(
            "{} {}: {}",
            artifacts.report_files.len(),
            plural(artifacts.report_files.len(), "report file", "report files"),
            join_preview(&artifacts.report_files, 4)
        )
    };
    let artifact_message = if artifacts.artifact_ids.is_empty() {
        "No artifacts generated".to_string()
    } else {
        format!(
            "{} {}: {}",
            artifacts.artifact_ids.len(),
            plural(
                artifacts.artifact_ids.len(),
                "sealed artifact",
                "sealed artifacts"
            ),
            join_preview(&artifacts.artifact_ids, 4)
        )
    };
    let assurance_message = if artifacts.assurance_files.is_empty() {
        "No eval run yet".to_string()
    } else {
        format!(
            "{} {}: {}",
            artifacts.assurance_files.len(),
            plural(
                artifacts.assurance_files.len(),
                "assurance result",
                "assurance results"
            ),
            join_preview(&artifacts.assurance_files, 4)
        )
    };
    let approval_rows = if pending.is_empty() {
        String::new()
    } else {
        let rows = pending
            .iter()
            .enumerate()
            .map(|(index, approval)| render_approval_row(approval, index == 0))
            .collect::<Vec<_>>()
            .join("");
        format!(r#"<div class="approval-list" role="list">{rows}</div>"#)
    };
    let details = pending
        .first()
        .map(|approval| render_approval_details(approval))
        .unwrap_or_else(render_empty_approval_details);

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Runwarden Reviewer Console</title>
  <style>{}</style>
  <script src="{}" defer></script>
</head>
<body>
<main class="runwarden-workbench assurance-ops-shell" data-local-api-url="{}">
  {}
  <section class="workbench-main" id="dashboard" aria-label="Reviewer workspace">
    {}
    <header class="top-status-strip" role="status" aria-label="Assessment status">
      {}
    </header>
    <section class="assurance-ops-layout">
      {}
      {}
      <article class="module approval-module review-queue-panel {}" id="approval-queue" data-filter-status="all"><div class="module-head"><h2>Approval Queue</h2><span class="state-badge">{} pending</span></div>{}<p>{}</p>{}<p class="queue-empty" data-queue-empty hidden>No matching approvals.</p></article>
      <section class="workspace-grid supporting-modules">
        {}
        {}
        {}
        {}
        {}
        {}
        {}
        {}
        {}
      </section>
    </section>
  </section>
  {}
</main>
</body>
</html>
"##,
        reviewer_console_css(),
        REVIEWER_CONSOLE_SCRIPT_NAME,
        escape_attr(&format!("http://{bind}:{port}")),
        render_nav(),
        render_command_bar(),
        [
            render_status_pill("Session", &session_label, "neutral"),
            render_status_pill("Local API", &format!("{bind}:{port}"), "neutral"),
            render_status_pill(
                "Risk",
                if pending.is_empty() {
                    "incomplete"
                } else {
                    "requires_review"
                },
                if pending.is_empty() {
                    "review"
                } else {
                    "danger"
                },
            ),
            render_status_pill("Trace", "missing", "review"),
            render_status_pill(
                "Approvals",
                &pending.len().to_string(),
                if pending.is_empty() {
                    "neutral"
                } else {
                    "review"
                }
            ),
            render_status_pill("Gates", "missing", "review"),
        ]
        .join(""),
        render_assurance_map(
            pending.len(),
            if pending.is_empty() {
                "incomplete"
            } else {
                "requires_review"
            },
            "missing",
            module_state(!artifacts.report_files.is_empty()),
            module_state(!artifacts.artifact_ids.is_empty()),
            module_state(!artifacts.assurance_files.is_empty()),
        ),
        render_evidence_timeline(
            &session_label,
            if pending.is_empty() {
                "incomplete"
            } else {
                "requires_review"
            },
            "missing",
            pending
                .first()
                .map(|approval| approval.approval_id.as_str())
                .unwrap_or("no pending approval"),
            &artifact_message,
            &assurance_message,
        ),
        if pending.is_empty() {
            "module-empty"
        } else {
            "module-partial"
        },
        pending.len(),
        render_queue_toolbar(),
        escape_html_text(&approvals_message),
        approval_rows,
        render_module(
            "agent-boundary",
            "Agent Boundary",
            &agent_message,
            module_state(!snapshot.sessions.is_empty()),
            optional_count(snapshot.sessions.len()),
        ),
        render_module(
            "provider-registry",
            "Provider Registry",
            &provider_message,
            module_state(provider_count > 0),
            optional_count(provider_count),
        ),
        render_approval_summary(pending.len()),
        render_module(
            "trace",
            "Trace Explorer",
            "No trace events yet",
            "empty",
            None
        ),
        render_module(
            "accountability",
            "Accountability",
            "No accountability chain reconstructed",
            "empty",
            None,
        ),
        render_module(
            "reports",
            "Reports",
            &report_message,
            module_state(!artifacts.report_files.is_empty()),
            optional_count(artifacts.report_files.len()),
        ),
        render_module(
            "artifacts",
            "Artifacts",
            &artifact_message,
            module_state(!artifacts.artifact_ids.is_empty()),
            optional_count(artifacts.artifact_ids.len()),
        ),
        render_module(
            "assurance",
            "Assurance",
            &assurance_message,
            module_state(!artifacts.assurance_files.is_empty()),
            optional_count(artifacts.assurance_files.len()),
        ),
        render_settings_module(),
        details,
    )
}

fn collect_ui_artifact_summary(artifact_root: &Path) -> UiArtifactSummary {
    let mut summary = UiArtifactSummary {
        report_files: direct_child_file_names(&artifact_root.join("reports"), |name| {
            !name.ends_with(".redaction.json")
                && (name.ends_with(".md")
                    || name.ends_with(".html")
                    || name.ends_with(".json")
                    || name.ends_with(".sarif"))
        }),
        artifact_ids: Vec::new(),
        assurance_files: direct_child_file_names(&artifact_root.join("release"), |name| {
            !name.ends_with(".redaction.json")
                && name.ends_with(".json")
                && (name.contains("eval") || name.contains("bench") || name.contains("cert"))
        }),
    };

    let manifest_path = artifact_root.join("artifact-manifest.json");
    if let Ok(body) = fs::read_to_string(&manifest_path)
        && let Ok(manifest) = serde_json::from_str::<ArtifactManifest>(&body)
    {
        summary.artifact_ids = manifest
            .artifacts
            .into_iter()
            .map(|entry| entry.artifact_id)
            .collect();
        summary.artifact_ids.sort();
    }

    summary
}

fn direct_child_file_names(dir: &Path, include: fn(&str) -> bool) -> Vec<String> {
    let mut names = fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            include(&name).then_some(name)
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn render_nav() -> String {
    let items = [
        ("dashboard", "Dashboard"),
        ("agent-boundary", "Agent Boundary"),
        ("provider-registry", "Provider Registry"),
        ("approval-queue", "Approval Queue"),
        ("trace", "Trace Explorer"),
        ("accountability", "Accountability"),
        ("reports", "Reports"),
        ("artifacts", "Artifacts"),
        ("assurance", "Assurance"),
        ("settings", "Settings"),
    ]
    .into_iter()
    .map(|(id, label)| format!(r##"<a href="#{}">{}</a>"##, id, escape_html_text(label)))
    .collect::<Vec<_>>()
    .join("");
    format!(
        r#"<nav class="left-nav" aria-label="Runwarden sections"><div class="nav-brand"><span class="brand-mark" aria-hidden="true">RW</span><strong>Runwarden</strong><small>review console</small></div>{items}</nav>"#
    )
}

fn render_command_bar() -> &'static str {
    r#"<header class="command-bar"><div><p class="eyebrow">Assurance Operations</p><h1>Reviewer Console</h1></div><div class="command-meter"><span>Trusted side effects</span><strong>approval-gated by kernel evidence</strong></div></header>"#
}

fn render_status_pill(label: &str, value: &str, tone: &str) -> String {
    format!(
        r#"<div class="status-pill tone-{}"><span class="status-label">{}</span><strong>{}</strong></div>"#,
        escape_attr(tone),
        escape_html_text(label),
        escape_html_text(value)
    )
}

fn render_assurance_map(
    pending_count: usize,
    risk_state: &str,
    trace_state: &str,
    report_state: &str,
    artifact_state: &str,
    assurance_state: &str,
) -> String {
    let review_body = if pending_count == 0 {
        "No pending high-risk actions.".to_string()
    } else {
        format!(
            "{pending_count} high-risk {} require visible context, reviewer identity, and reason.",
            plural(pending_count, "action", "actions")
        )
    };
    format!(
        r#"<section class="assurance-map" id="assurance-map" aria-label="Assurance evidence map"><div class="module-head"><h2>Assurance Map</h2><span class="state-badge">{pending_count} pending review</span></div><div class="assurance-nodes"><button type="button" class="assurance-node tone-info" data-detail-type="Kernel" data-detail-title="Kernel decision boundary" data-detail-body="Provider calls remain mediated by Runwarden kernel decisions before side effects."><span>Kernel</span><strong>{}</strong></button><button type="button" class="assurance-node tone-review" data-detail-type="Review" data-detail-title="Reviewer approval binding" data-detail-body="{}"><span>Review</span><strong>{pending_count} pending</strong></button><button type="button" class="assurance-node tone-success" data-detail-type="Trace" data-detail-title="Trace integrity" data-detail-body="Trace status is {}; report and approval claims must cite obs refs."><span>Trace</span><strong>{}</strong></button><button type="button" class="assurance-node tone-info" data-detail-type="Artifacts" data-detail-title="Artifacts and reports" data-detail-body="Reports are {}; artifacts are {}; assurance is {}."><span>Evidence</span><strong>{}</strong></button></div></section>"#,
        escape_html_text(risk_state),
        escape_attr(&review_body),
        escape_attr(trace_state),
        escape_html_text(trace_state),
        escape_attr(report_state),
        escape_attr(artifact_state),
        escape_attr(assurance_state),
        escape_html_text(assurance_state),
    )
}

fn render_evidence_timeline(
    session_label: &str,
    risk_state: &str,
    trace_state: &str,
    approval_label: &str,
    artifact_message: &str,
    assurance_message: &str,
) -> String {
    let items = [
        ("session", session_label),
        ("kernel", risk_state),
        ("trace", trace_state),
        ("approval", approval_label),
        ("artifact", artifact_message),
        ("assurance", assurance_message),
    ]
    .into_iter()
    .map(|(label, value)| {
        format!(
            r#"<li><span class="timeline-dot" aria-hidden="true"></span><strong>{}</strong><code>{}</code></li>"#,
            escape_html_text(label),
            escape_html_text(value)
        )
    })
    .collect::<Vec<_>>()
    .join("");
    format!(
        r#"<section class="evidence-timeline" id="evidence-timeline" aria-label="Evidence timeline"><div class="module-head"><h2>Evidence Timeline</h2><span class="state-badge">obs chain</span></div><ol>{items}</ol></section>"#
    )
}

fn render_queue_toolbar() -> &'static str {
    r#"<div class="queue-toolbar" role="search"><label class="queue-search">Search approvals<input type="search" data-approval-search placeholder="Provider, action, obs, hash"></label><div class="queue-filters" aria-label="Approval filters"><button type="button" data-approval-filter="all" aria-pressed="true">All</button><button type="button" data-approval-filter="requires_review">Review</button><button type="button" data-approval-filter="network">Network</button><button type="button" data-approval-filter="artifact">Artifact</button></div></div>"#
}

fn render_approval_summary(pending_count: usize) -> String {
    let message = if pending_count == 0 {
        "No reviewer action is currently required."
    } else {
        "Pending actions require visible context, reviewer identity, and reason before approval is consumed."
    };
    format!(
        r#"<article class="module module-{}" id="approval-summary"><div class="module-head"><h2>Approval Summary</h2><span class="state-badge">{pending_count} pending</span></div><p>{}</p></article>"#,
        if pending_count == 0 {
            "empty"
        } else {
            "partial"
        },
        escape_html_text(message)
    )
}

fn render_module(
    id: &str,
    title: &str,
    message: &str,
    state: &str,
    count: Option<usize>,
) -> String {
    let count_badge = count
        .map(|value| format!(r#"<span class="module-count">{value}</span>"#))
        .unwrap_or_default();
    format!(
        r#"<article class="module module-{}" id="{}"><div class="module-head"><h2>{}</h2><span class="state-badge">{}</span>{}</div><p>{}</p></article>"#,
        escape_attr(state),
        escape_attr(id),
        escape_html_text(title),
        escape_html_text(state),
        count_badge,
        escape_html_text(message)
    )
}

fn module_state(has_content: bool) -> &'static str {
    if has_content { "success" } else { "empty" }
}

fn optional_count(count: usize) -> Option<usize> {
    (count > 0).then_some(count)
}

fn render_approval_row(approval: &ApprovalRecord, selected: bool) -> String {
    let search_text = [
        approval.approval_id.as_str(),
        approval.binding.provider.as_str(),
        approval.binding.action.as_str(),
        "requires_review",
        approval.binding.actor_id.as_deref().unwrap_or("unknown"),
        approval.binding.authz_id.as_deref().unwrap_or("none"),
        approval.binding.argument_hash.as_str(),
        "pending provider side effect",
    ]
    .join(" ");
    format!(
        r#"<article class="approval-row{}" role="listitem" tabindex="0" aria-current="{}" aria-controls="approval-details" aria-label="Review approval for {}" data-approval-id="{}" data-provider="{}" data-action="{}" data-risk="requires_review" data-target="{}" data-side-effects="pending provider side effect" data-actor="{}" data-authz="{}" data-argument-hash="{}" data-obs-refs="" data-search-text="{}"><div><span class="risk-chip">requires_review</span><h3>{}</h3><p>{}</p></div><dl>{}{}{}{}{}{}</dl>{}</article>"#,
        if selected { " is-selected" } else { "" },
        if selected { "true" } else { "false" },
        escape_attr(&approval.binding.provider),
        escape_attr(&approval.approval_id),
        escape_attr(&approval.binding.provider),
        escape_attr(&approval.binding.action),
        escape_attr(&approval.binding.action),
        escape_attr(approval.binding.actor_id.as_deref().unwrap_or("unknown")),
        escape_attr(approval.binding.authz_id.as_deref().unwrap_or("none")),
        escape_attr(&approval.binding.argument_hash),
        escape_attr(&search_text),
        escape_html_text(&approval.binding.provider),
        escape_html_text(&approval.binding.action),
        render_field("Approval", &approval.approval_id),
        render_field("Risk", "requires_review"),
        render_field(
            "Actor",
            approval.binding.actor_id.as_deref().unwrap_or("unknown")
        ),
        render_field(
            "Authz",
            approval.binding.authz_id.as_deref().unwrap_or("none")
        ),
        render_field("Argument", &approval.binding.argument_hash),
        render_field("Action", &approval.binding.action),
        render_approval_decision_form(&approval.approval_id),
    )
}

fn render_approval_details(approval: &ApprovalRecord) -> String {
    format!(
        r#"<aside class="details-drawer" id="approval-details" data-approval-details aria-label="Approval details"><h2 data-detail-title>{}</h2><dl data-detail-fields>{}{}{}{}{}{}{}{}{}</dl>{}</aside>"#,
        escape_html_text(&approval.binding.provider),
        render_field("Approval", &approval.approval_id),
        render_field("Provider", &approval.binding.provider),
        render_field("Action", &approval.binding.action),
        render_field("Risk", "requires_review"),
        render_field("Target", &approval.binding.action),
        render_field("Side effects", "pending provider side effect"),
        render_field(
            "Actor",
            approval.binding.actor_id.as_deref().unwrap_or("unknown")
        ),
        render_field(
            "Authz",
            approval.binding.authz_id.as_deref().unwrap_or("none")
        ),
        render_field("Argument hash", &approval.binding.argument_hash),
        render_approval_decision_form(&approval.approval_id),
    )
}

fn render_empty_approval_details() -> String {
    "<aside class=\"details-drawer\" id=\"approval-details\" data-approval-details aria-label=\"Approval details\"><h2 data-detail-title>Approval Details</h2><p>Select an approval to inspect provider, risk, target, side effects, actor, authz, argument hash, and obs refs before a reviewer decision.</p></aside>".to_string()
}

fn render_field(label: &str, value: &str) -> String {
    format!(
        r#"<div><dt>{}</dt><dd>{}</dd></div>"#,
        escape_html_text(label),
        escape_html_text(value)
    )
}

fn render_approval_decision_form(approval_id: &str) -> String {
    format!(
        r#"<form class="approval-decision-form" data-approval-id="{}" novalidate><label>Reviewer<input name="reviewer" autocomplete="off" required></label><label>Reason<textarea name="reason" required></textarea></label><div class="decision-actions"><button type="submit" name="decision" value="approve" data-action="approve">Approve</button><button type="submit" name="decision" value="deny" data-action="deny">Deny</button></div><p class="decision-status" role="status" data-decision-status></p></form>"#,
        escape_attr(approval_id)
    )
}

fn render_settings_module() -> String {
    r#"<article class="module module-empty" id="settings"><div class="module-head"><h2>Settings</h2><span class="state-badge">local</span></div><p>Local API token not loaded.</p><label>Local API Token<input id="local-api-token" name="local_api_token" type="password" autocomplete="off" spellcheck="false"></label></article>"#.to_string()
}

fn reviewer_console_css() -> &'static str {
    r#"
    :root {
      color-scheme: light;
      font-family: "IBM Plex Sans", "Aptos", sans-serif;
      --ink: #20241f;
      --muted: #626b61;
      --paper: #f7f8f4;
      --panel: #fffffb;
      --line: #cdd5c8;
      --rail: #151813;
      --rail-soft: #262d24;
      --green: #2f6f4e;
      --amber: #a76716;
      --red: #b42318;
      --blue: #2866a8;
      --shadow: 0 18px 48px rgba(32, 36, 31, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        linear-gradient(90deg, rgba(21, 24, 19, 0.045) 1px, transparent 1px),
        linear-gradient(0deg, rgba(21, 24, 19, 0.035) 1px, transparent 1px),
        repeating-linear-gradient(135deg, rgba(47, 111, 78, 0.055) 0 1px, transparent 1px 18px),
        #f7f8f4;
      background-size: 28px 28px, 28px 28px, auto, auto;
      color: #20241f;
      font-size: 14px;
    }
    [hidden] { display: none !important; }
    section[id], article[id], aside[id] { scroll-margin-top: 86px; }
    .runwarden-workbench { min-height: 100vh; display: grid; grid-template-columns: 248px minmax(0, 1fr) minmax(320px, 360px); }
    .left-nav {
      position: sticky;
      top: 0;
      height: 100vh;
      background: #151813;
      color: #f3faf5;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      border-right: 1px solid rgba(255, 255, 255, 0.08);
    }
    .nav-brand {
      display: grid;
      grid-template-columns: 44px minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      padding: 4px 0 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.12);
      margin-bottom: 10px;
    }
    .brand-mark {
      width: 44px;
      height: 44px;
      display: grid;
      place-items: center;
      border: 1px solid rgba(255, 255, 255, 0.28);
      border-radius: 8px;
      background: linear-gradient(145deg, rgba(47, 111, 78, 0.82), rgba(21, 24, 19, 0.55));
      font-family: "JetBrains Mono", ui-monospace, monospace;
      font-size: 13px;
    }
    .nav-brand strong, .nav-brand small { display: block; overflow-wrap: anywhere; }
    .nav-brand small { color: #b9c6b8; font-size: 12px; }
    .left-nav a { color: inherit; text-decoration: none; padding: 10px 12px; border-radius: 6px; min-height: 44px; display: flex; align-items: center; border: 1px solid transparent; }
    .left-nav a:hover { background: #262d24; border-color: rgba(255, 255, 255, 0.14); }
    .workbench-main { padding: 22px; min-width: 0; }
    .command-bar {
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: end;
      margin-bottom: 16px;
      padding: 20px;
      border: 1px solid rgba(205, 213, 200, 0.9);
      border-radius: 8px;
      background: rgba(255, 255, 251, 0.86);
      box-shadow: var(--shadow);
    }
    .eyebrow { margin: 0 0 4px; color: #626b61; font-size: 12px; text-transform: uppercase; }
    h1 { margin: 0; font-size: 40px; line-height: 1; }
    .command-meter { min-width: 220px; border-left: 4px solid #2f6f4e; padding: 10px 12px; background: #f7f8f4; border-radius: 6px; }
    .command-meter span { display: block; color: #626b61; font-size: 12px; }
    .command-meter strong { display: block; font-size: 15px; overflow-wrap: anywhere; }
    .top-status-strip { display: grid; grid-template-columns: repeat(6, minmax(116px, 1fr)); gap: 10px; margin-bottom: 14px; }
    .status-pill {
      border: 1px solid #cdd5c8;
      border-top-width: 3px;
      background: #fffffb;
      border-radius: 8px;
      padding: 11px 12px;
      min-width: 0;
      box-shadow: 0 1px 0 rgba(32, 36, 31, 0.05);
    }
    .status-label { display: block; font-size: 12px; color: #626b61; }
    .status-pill strong { display: block; overflow-wrap: anywhere; font-size: 14px; }
    .tone-success { border-top-color: #1f7a4d; }
    .tone-review { border-top-color: #a76716; }
    .tone-danger { border-top-color: #b42318; }
    .tone-info { border-top-color: #2866a8; }
    .assurance-ops-layout { display: grid; grid-template-columns: minmax(240px, 0.8fr) minmax(320px, 1.1fr); gap: 14px; align-items: start; }
    .workspace-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
    .supporting-modules { grid-column: 1 / -1; }
    .module { background: rgba(255, 255, 251, 0.94); border: 1px solid #cdd5c8; border-radius: 8px; padding: 15px; min-width: 0; box-shadow: 0 10px 30px rgba(32, 36, 31, 0.07); }
    .module-head { display: flex; align-items: center; gap: 8px; justify-content: space-between; margin-bottom: 10px; }
    .module h2, .details-drawer h2 { font-size: 16px; margin: 0; }
    .module p, .details-drawer p { margin: 0; color: #626b61; overflow-wrap: anywhere; }
    .state-badge, .module-count, .risk-chip { border: 1px solid #cdd5c8; border-radius: 999px; padding: 4px 8px; color: #626b61; background: #f7f8f4; font-size: 12px; white-space: nowrap; }
    .module-success .state-badge { color: #1f7a4d; border-color: #1f7a4d; }
    .module-error .state-badge { color: #b42318; border-color: #b42318; }
    .module-partial .state-badge { color: #a76716; border-color: #a76716; }
    .assurance-map, .evidence-timeline { background: rgba(255, 255, 251, 0.94); border: 1px solid #cdd5c8; border-radius: 8px; padding: 15px; min-width: 0; box-shadow: 0 10px 30px rgba(32, 36, 31, 0.07); }
    .assurance-nodes { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    .assurance-node { display: grid; gap: 4px; align-content: start; text-align: left; background: #f7f8f4; border-radius: 8px; min-height: 86px; padding: 12px; border-top-width: 3px; }
    .assurance-node span { color: #626b61; font-size: 12px; text-transform: uppercase; }
    .assurance-node strong { overflow-wrap: anywhere; }
    .evidence-timeline ol { list-style: none; padding: 0; margin: 0; display: grid; }
    .evidence-timeline li { display: grid; grid-template-columns: 16px 82px minmax(0, 1fr); gap: 8px; align-items: start; min-height: 38px; padding: 6px 0; border-bottom: 1px solid #e3e8df; }
    .evidence-timeline li:last-child { border-bottom: 0; }
    .timeline-dot { width: 9px; height: 9px; border-radius: 999px; background: #2f6f4e; margin-top: 4px; box-shadow: 0 0 0 3px rgba(47, 111, 78, 0.14); }
    .evidence-timeline strong { color: #626b61; font-size: 12px; text-transform: uppercase; }
    .evidence-timeline code { font-family: "JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .approval-module { grid-column: 1 / -1; }
    .review-queue-panel { grid-column: 1 / -1; }
    .queue-toolbar { display: grid; grid-template-columns: minmax(220px, 1fr) auto; gap: 12px; align-items: end; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #e3e8df; }
    .queue-search { margin: 0; }
    .queue-search input { min-height: 44px; }
    .queue-filters { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
    .queue-filters button[aria-pressed="true"] { background: #2f6f4e; color: #f3faf5; border-color: #2f6f4e; }
    .queue-empty { margin-top: 10px; }
    .approval-row { border: 1px solid #cdd5c8; border-radius: 8px; padding: 13px; display: grid; grid-template-columns: minmax(180px, 1fr) minmax(260px, 2fr) minmax(220px, auto); gap: 14px; align-items: start; background: #fffffb; cursor: pointer; transition: border-color 120ms ease, box-shadow 120ms ease, background-color 120ms ease; }
    .approval-row:hover { border-color: rgba(47, 111, 78, 0.55); }
    .approval-row.is-selected { border-color: #2f6f4e; background: #fbfdf9; box-shadow: inset 4px 0 0 #2f6f4e, 0 10px 24px rgba(32, 36, 31, 0.08); }
    .approval-row + .approval-row { margin-top: 10px; }
    .approval-row h3 { margin: 8px 0 4px; font-size: 15px; overflow-wrap: anywhere; }
    .approval-row p { margin: 0; color: #626b61; overflow-wrap: anywhere; }
    dl { display: grid; gap: 7px; margin: 0; }
    dl div { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: 8px; }
    dt { color: #626b61; font-size: 12px; }
    dd { margin: 0; font-family: "JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .row-actions, .decision-actions { display: flex; flex-wrap: wrap; gap: 6px; }
    .approval-decision-form { display: grid; gap: 8px; }
    button { border: 1px solid #cdd5c8; background: #fffffb; border-radius: 6px; min-height: 44px; padding: 8px 12px; color: #20241f; }
    button:hover { border-color: #2f6f4e; background: #eef1ea; }
    button:focus-visible, input:focus-visible, textarea:focus-visible, .left-nav a:focus-visible, .approval-row:focus-visible { outline: 2px solid #2f6f4e; outline-offset: 2px; }
    .details-drawer { border-left: 1px solid #cdd5c8; background: #fffffb; padding: 22px 18px; min-width: 0; box-shadow: -12px 0 34px rgba(32, 36, 31, 0.06); position: sticky; top: 0; height: 100vh; overflow: auto; }
    label { display: block; margin: 12px 0 6px; font-size: 12px; color: #626b61; }
    input, textarea { width: 100%; min-height: 38px; margin-top: 8px; box-sizing: border-box; border: 1px solid #cdd5c8; border-radius: 6px; padding: 8px; background: #fffffb; color: #20241f; }
    textarea { min-height: 82px; resize: vertical; }
    .decision-status { min-height: 20px; color: #20241f; overflow-wrap: anywhere; }
    .decision-status[data-state="error"] { color: #b42318; }
    .decision-status[data-state="success"] { color: #1f7a4d; }
    .decision-complete { opacity: 0.78; }
    @media (max-width: 1199px) {
      .runwarden-workbench { grid-template-columns: 86px minmax(0, 1fr); }
      .nav-brand { grid-template-columns: 1fr; }
      .nav-brand strong, .nav-brand small { display: none; }
      .left-nav a { font-size: 12px; padding-inline: 8px; }
      .details-drawer { grid-column: 1 / -1; border-left: 0; border-top: 1px solid #cdd5c8; position: static; height: auto; overflow: visible; }
      .top-status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .assurance-ops-layout { grid-template-columns: 1fr; }
    }
    @media (max-width: 768px) {
      .runwarden-workbench { display: block; }
      .left-nav { position: sticky; top: 0; height: auto; z-index: 10; flex-direction: row; overflow-x: auto; padding: 8px 10px; border-right: 0; border-bottom: 1px solid #cdd5c8; box-shadow: 0 10px 22px rgba(32, 36, 31, 0.18); scrollbar-width: thin; }
      .nav-brand { display: none; }
      .left-nav a { white-space: nowrap; }
      h1 { font-size: 30px; }
      .command-bar { display: block; padding: 16px; }
      .command-meter { min-width: 0; margin-top: 12px; }
      .top-status-strip, .workspace-grid, .assurance-nodes, .queue-toolbar { grid-template-columns: 1fr; }
      .queue-filters { justify-content: flex-start; }
      .approval-row { grid-template-columns: 1fr; }
      .details-drawer { min-height: 0; border-left: 0; border-top: 1px solid #cdd5c8; }
    }
  "#
}

fn reviewer_console_js() -> &'static str {
    r##""use strict";
(() => {
  const root = document.querySelector(".runwarden-workbench");
  const apiRoot = root?.dataset.localApiUrl?.replace(/\/$/, "");
  const tokenInput = document.querySelector("#local-api-token");
  const details = document.querySelector("[data-approval-details]");
  const detailTitle = details?.querySelector("[data-detail-title]");
  const detailFields = details?.querySelector("[data-detail-fields]");
  const detailForm = details?.querySelector("form.approval-decision-form");
  const queue = document.querySelector(".review-queue-panel");
  const queueSearch = document.querySelector("[data-approval-search]");
  const queueEmpty = document.querySelector("[data-queue-empty]");

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#39;"
    })[char]);
  }

  function fieldHtml(label, value) {
    return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value || "none")}</dd></div>`;
  }

  function statusFor(form) {
    return form.querySelector("[data-decision-status]");
  }

  function setStatus(form, text, state) {
    const status = statusFor(form);
    if (!status) {
      return;
    }
    status.textContent = text;
    if (state) {
      status.dataset.state = state;
    } else {
      delete status.dataset.state;
    }
  }

  function disableForm(form) {
    for (const control of form.querySelectorAll("input, textarea, button")) {
      control.disabled = true;
    }
    form.classList.add("decision-complete");
  }

  function enableForm(form) {
    for (const control of form.querySelectorAll("input, textarea, button")) {
      control.disabled = false;
    }
    form.classList.remove("decision-complete");
  }

  function matchingForms(approvalId) {
    return Array.from(document.querySelectorAll("form.approval-decision-form")).filter((form) => form.dataset.approvalId === approvalId);
  }

  function markApprovalComplete(approvalId, message) {
    for (const row of document.querySelectorAll(".approval-row")) {
      if (row.dataset.approvalId === approvalId) {
        row.dataset.decisionComplete = "true";
      }
    }
    for (const form of matchingForms(approvalId)) {
      setStatus(form, message, "success");
      disableForm(form);
    }
  }

  function syncDetails(row) {
    if (!details || !detailTitle || !detailFields || !detailForm) {
      return;
    }
    const approvalId = row.dataset.approvalId ?? "";
    detailTitle.textContent = row.dataset.provider || "Approval Details";
    detailFields.innerHTML = [
      fieldHtml("Approval", approvalId),
      fieldHtml("Provider", row.dataset.provider),
      fieldHtml("Action", row.dataset.action),
      fieldHtml("Risk", row.dataset.risk),
      fieldHtml("Target", row.dataset.target),
      fieldHtml("Side effects", row.dataset.sideEffects),
      fieldHtml("Actor", row.dataset.actor),
      fieldHtml("Authz", row.dataset.authz),
      fieldHtml("Argument hash", row.dataset.argumentHash),
      fieldHtml("Obs refs", row.dataset.obsRefs)
    ].join("");
    detailForm.dataset.approvalId = approvalId;
    detailForm.reset();
    enableForm(detailForm);
    setStatus(detailForm, "", "");
    if (row.dataset.decisionComplete === "true") {
      setStatus(detailForm, "Decision already recorded.", "success");
      disableForm(detailForm);
    }
  }

  function selectApproval(row) {
    for (const item of document.querySelectorAll(".approval-row")) {
      const selected = item === row;
      item.classList.toggle("is-selected", selected);
      item.setAttribute("aria-current", selected ? "true" : "false");
    }
    syncDetails(row);
  }

  function filterApprovals() {
    if (!queue) {
      return;
    }
    const term = (queueSearch?.value ?? "").trim().toLowerCase();
    const filter = queue.dataset.filterStatus ?? "all";
    let visible = 0;
    for (const row of queue.querySelectorAll(".approval-row")) {
      const haystack = (row.dataset.searchText ?? "").toLowerCase();
      const sideEffects = (row.dataset.sideEffects ?? "").toLowerCase();
      const risk = (row.dataset.risk ?? "").toLowerCase();
      const matchesTerm = !term || haystack.includes(term);
      const matchesFilter =
        filter === "all" ||
        risk.includes(filter) ||
        sideEffects.includes(filter);
      const show = matchesTerm && matchesFilter;
      row.hidden = !show;
      if (show) {
        visible += 1;
      }
    }
    if (queueEmpty) {
      queueEmpty.hidden = visible !== 0;
    }
  }

  function interactiveTarget(target) {
    return target instanceof Element && Boolean(target.closest("input, textarea, button, a, label"));
  }

  async function submitDecision(form, decision) {
    const approvalId = form.dataset.approvalId;
    const reviewer = form.elements.reviewer?.value?.trim() ?? "";
    const reason = form.elements.reason?.value?.trim() ?? "";
    const token = tokenInput?.value?.trim() ?? "";
    if (!apiRoot || !approvalId) {
      setStatus(form, "Local API endpoint is unavailable.", "error");
      return;
    }
    if (!token) {
      setStatus(form, "Local API token is required.", "error");
      tokenInput?.focus();
      return;
    }
    if (!reviewer || !reason) {
      setStatus(form, "Reviewer and reason are required.", "error");
      return;
    }
    setStatus(form, "Submitting decision...", "");
    const response = await fetch(`${apiRoot}/approvals/${encodeURIComponent(approvalId)}/${decision}`, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({ reviewer, reason })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setStatus(form, body.error ?? "Approval decision failed.", "error");
      return;
    }
    markApprovalComplete(approvalId, `${decision === "approve" ? "Approval" : "Denial"} recorded.`);
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.classList.contains("approval-decision-form")) {
      return;
    }
    event.preventDefault();
    const submitter = event.submitter;
    const decision = submitter instanceof HTMLButtonElement ? submitter.value : "";
    if (decision !== "approve" && decision !== "deny") {
      setStatus(form, "Choose approve or deny.", "error");
      return;
    }
    submitDecision(form, decision).catch((error) => {
      setStatus(form, error instanceof Error ? error.message : "Approval decision failed.", "error");
    });
  });

  document.addEventListener("click", (event) => {
    const filterButton = event.target instanceof Element ? event.target.closest("[data-approval-filter]") : null;
    if (filterButton instanceof HTMLButtonElement && queue) {
      queue.dataset.filterStatus = filterButton.dataset.approvalFilter ?? "all";
      for (const button of queue.querySelectorAll("[data-approval-filter]")) {
        button.setAttribute("aria-pressed", button === filterButton ? "true" : "false");
      }
      filterApprovals();
      return;
    }
    const node = event.target instanceof Element ? event.target.closest(".assurance-node") : null;
    if (node instanceof HTMLElement && detailTitle && detailFields) {
      detailTitle.textContent = node.dataset.detailTitle || node.dataset.detailType || "Assurance detail";
      detailFields.innerHTML = fieldHtml(node.dataset.detailType || "Type", node.dataset.detailBody || "No detail available.");
      return;
    }
    if (interactiveTarget(event.target)) {
      return;
    }
    const row = event.target instanceof Element ? event.target.closest(".approval-row") : null;
    if (row instanceof HTMLElement) {
      selectApproval(row);
    }
  });

  document.addEventListener("keydown", (event) => {
    const row = event.target instanceof HTMLElement && event.target.classList.contains("approval-row") ? event.target : null;
    if (!row || (event.key !== "Enter" && event.key !== " ")) {
      return;
    }
    event.preventDefault();
    selectApproval(row);
  });

  queueSearch?.addEventListener("input", filterApprovals);

  const initialRow = document.querySelector(".approval-row.is-selected") ?? document.querySelector(".approval-row");
  if (initialRow instanceof HTMLElement) {
    syncDetails(initialRow);
  }
  filterApprovals();
})();
"##
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn join_preview(values: &[String], limit: usize) -> String {
    let mut preview = values.iter().take(limit).cloned().collect::<Vec<_>>();
    if values.len() > limit {
        preview.push(format!("+{} more", values.len() - limit));
    }
    preview.join(", ")
}

fn file_url_for_path(path: &Path) -> String {
    format!(
        "file://{}",
        percent_encode_path(&normalize_file_url_path(&path.to_string_lossy()))
    )
}

fn normalize_file_url_path(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");

    if let Some(stripped) = normalized.strip_prefix("//?/UNC/") {
        return stripped.to_string();
    }
    if let Some(stripped) = normalized.strip_prefix("//?/") {
        normalized = stripped.to_string();
    }

    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return format!("/{normalized}");
    }

    normalized
}

fn percent_encode_path(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(path.len());
    for byte in path.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                encoded.push(*byte as char);
            }
            other => {
                encoded.push('%');
                encoded.push(HEX[(other >> 4) as usize] as char);
                encoded.push(HEX[(other & 0x0f) as usize] as char);
            }
        }
    }
    encoded
}

fn escape_html_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn escape_attr(value: &str) -> String {
    escape_html_text(value)
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

pub fn serve_one_request(
    listener: TcpListener,
    config: LocalApiServerConfig,
) -> std::io::Result<()> {
    let mut router = LocalApiRouter::from_config(config);
    serve_next_request(&listener, &mut router)
}

pub fn serve_next_request(
    listener: &TcpListener,
    router: &mut LocalApiRouter,
) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let bytes = read_http_request_bytes(&mut stream)?;
    let request_text = String::from_utf8_lossy(&bytes);
    let (request, body) = parse_http_request(&request_text);
    let response = router.handle(request, body);
    let body = serde_json::to_string(&response.body).expect("local API body serializes");
    let status_text = status_text(response.status);
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        status_text,
        body.len()
    )?;
    for (name, value) in response.headers {
        write!(stream, "{}: {}\r\n", name, value)?;
    }
    write!(stream, "\r\n{body}")?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}

fn read_http_request_bytes(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some((header_end, content_length)) = http_request_lengths(&bytes)? {
            if content_length > MAX_LOCAL_API_REQUEST_BODY_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "local API request body exceeds limit",
                ));
            }
            let expected_len = header_end + content_length;
            if bytes.len() >= expected_len {
                break;
            }
        } else if bytes.len() > MAX_LOCAL_API_REQUEST_HEADER_BYTES {
            break;
        }
    }
    Ok(bytes)
}

fn http_request_lengths(bytes: &[u8]) -> std::io::Result<Option<(usize, usize)>> {
    let Some(header_end) = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
    else {
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    Ok(Some((header_end, content_length.unwrap_or(0))))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecisionInput {
    pub decision: ApprovalDecision,
    pub reviewer: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct LocalApiSecurity {
    launch_token: String,
    allowed_hosts: BTreeSet<String>,
    allowed_origins: BTreeSet<String>,
    artifact_tokens: BTreeMap<String, ArtifactDownloadToken>,
    approvals: BTreeMap<String, ApprovalRecord>,
    sessions: BTreeMap<String, SessionManifest>,
}

#[derive(Debug, Clone)]
struct ArtifactDownloadToken {
    artifact_id: String,
    expires_at: Instant,
}

impl LocalApiSecurity {
    pub fn new<H, O>(launch_token: impl Into<String>, allowed_hosts: H, allowed_origins: O) -> Self
    where
        H: IntoIterator,
        H::Item: Into<String>,
        O: IntoIterator,
        O::Item: Into<String>,
    {
        Self {
            launch_token: launch_token.into(),
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(Into::into)
                .map(normalize_host)
                .collect(),
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
            artifact_tokens: BTreeMap::new(),
            approvals: BTreeMap::new(),
            sessions: BTreeMap::new(),
        }
    }

    pub fn authorize_control_plane(&self, request: &LocalApiRequest) -> LocalApiResponse {
        if !self.has_valid_launch_token(request) {
            return denied(
                401,
                "missing or invalid Runwarden launch token",
                "local_api_token",
            );
        }

        let Some(host) = request.header_value("host").map(normalize_host) else {
            return denied(403, "missing Host header", "host");
        };
        if !self.allowed_hosts.contains(&host) {
            return denied(403, "Host is not allowed for Runwarden Local API", "host");
        }

        let Some(origin) = request.header_value("origin") else {
            return denied(403, "missing Origin header", "origin");
        };
        if !self.origin_is_allowed(origin) {
            return denied(
                403,
                "Origin is not allowed for Runwarden Local API",
                "origin",
            );
        }

        let headers = self.cors_headers(origin);

        LocalApiResponse {
            status: 200,
            headers,
            body: json!({
                "authorized": true,
                "path": request.path,
                "method": request.method,
                "side_effect_executed": false
            }),
        }
    }

    pub fn authorize_preflight(&self, request: &LocalApiRequest) -> LocalApiResponse {
        let Some(host) = request.header_value("host").map(normalize_host) else {
            return denied(403, "missing Host header", "host");
        };
        if !self.allowed_hosts.contains(&host) {
            return denied(403, "Host is not allowed for Runwarden Local API", "host");
        }

        let Some(origin) = request.header_value("origin") else {
            return denied(403, "missing Origin header", "origin");
        };
        if !self.origin_is_allowed(origin) {
            return denied(
                403,
                "Origin is not allowed for Runwarden Local API",
                "origin",
            );
        }

        response_with_headers(
            200,
            self.cors_headers(origin),
            json!({
                "preflight": true,
                "side_effect_executed": false
            }),
        )
    }

    pub fn insert_approval(&mut self, approval: ApprovalRecord) {
        self.approvals
            .insert(approval.approval_id.clone(), approval);
    }

    pub fn pending_approval_count(&self) -> usize {
        self.approvals
            .values()
            .filter(|approval| approval.state == ApprovalState::Pending)
            .count()
    }

    pub fn approval_state(&self, approval_id: &str) -> Option<ApprovalState> {
        self.approvals
            .get(approval_id)
            .map(|approval| approval.state.clone())
    }

    fn persist_consumed_approval(&mut self, call: &ProviderCall, binding: &ApprovalBinding) {
        let Some(approval_id) = call.approval_id.as_deref() else {
            return;
        };
        if let Some(approval) = self.approvals.get_mut(approval_id)
            && approval.state == ApprovalState::Approved
        {
            let _ = approval.consume_once(binding);
        }
    }

    pub fn approval_queue(&self, request: &LocalApiRequest) -> LocalApiResponse {
        let authorization = self.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }

        let mut approvals: Vec<_> = self
            .approvals
            .values()
            .filter(|approval| approval.state == ApprovalState::Pending)
            .cloned()
            .collect();
        approvals.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));

        LocalApiResponse {
            status: 200,
            headers: authorization.headers,
            body: json!({
                "approvals": approvals,
                "side_effect_executed": false
            }),
        }
    }

    pub fn decide_approval(
        &mut self,
        request: &LocalApiRequest,
        approval_id: &str,
        input: ApprovalDecisionInput,
    ) -> LocalApiResponse {
        let authorization = self.authorize_control_plane(request);
        if authorization.status != 200 {
            return authorization;
        }

        if input.reviewer.trim().is_empty() || input.reason.trim().is_empty() {
            return response_with_headers(
                400,
                authorization.headers,
                json!({
                    "error": "reviewer and reason are required",
                    "gate": "approval_review",
                    "side_effect_executed": false
                }),
            );
        }

        let Some(approval) = self.approvals.get_mut(approval_id) else {
            return response_with_headers(
                404,
                authorization.headers,
                json!({
                    "error": "approval id was not found",
                    "gate": "approval_review",
                    "side_effect_executed": false
                }),
            );
        };

        let transition = match input.decision {
            ApprovalDecision::Approve => approval.approve(input.reviewer, input.reason),
            ApprovalDecision::Deny => approval.deny(input.reviewer, input.reason),
        };

        match transition {
            Ok(()) => response_with_headers(
                200,
                authorization.headers,
                json!({
                    "approval": approval,
                    "side_effect_executed": true
                }),
            ),
            Err(err) => response_with_headers(
                409,
                authorization.headers,
                json!({
                    "error": err.to_string(),
                    "gate": "approval_review",
                    "side_effect_executed": false
                }),
            ),
        }
    }

    pub fn issue_artifact_download_token(&mut self, artifact_id: impl Into<String>) -> String {
        let token = format!("rw_artifact_dl_{}", uuid::Uuid::now_v7());
        self.artifact_tokens.insert(
            token.clone(),
            ArtifactDownloadToken {
                artifact_id: artifact_id.into(),
                expires_at: Instant::now() + Duration::from_secs(300),
            },
        );
        token
    }

    pub fn consume_artifact_download_token(&mut self, token: &str) -> LocalApiResponse {
        match self.artifact_tokens.remove(token) {
            Some(entry) if Instant::now() <= entry.expires_at => LocalApiResponse {
                status: 200,
                headers: BTreeMap::new(),
                body: json!({
                    "artifact_id": entry.artifact_id,
                    "token_consumed": true
                }),
            },
            Some(_) => denied(403, "artifact token is expired", "artifact_token"),
            None => denied(
                403,
                "artifact token is invalid or already used",
                "artifact_token",
            ),
        }
    }

    fn has_valid_launch_token(&self, request: &LocalApiRequest) -> bool {
        request
            .header_value("authorization")
            .and_then(|header| header.strip_prefix("Bearer "))
            .is_some_and(|token| token == self.launch_token)
            || request
                .header_value("x-runwarden-token")
                .is_some_and(|token| token == self.launch_token)
    }

    fn cors_headers(&self, origin: &str) -> BTreeMap<String, String> {
        let mut headers = BTreeMap::new();
        headers.insert(
            "access-control-allow-origin".to_string(),
            origin.to_string(),
        );
        headers.insert(
            "access-control-allow-methods".to_string(),
            "GET, POST, OPTIONS".to_string(),
        );
        headers.insert(
            "access-control-allow-headers".to_string(),
            "authorization, content-type, x-runwarden-token".to_string(),
        );
        headers.insert("vary".to_string(), "Origin".to_string());
        headers
    }

    fn optional_cors_headers(&self, request: &LocalApiRequest) -> BTreeMap<String, String> {
        let host_allowed = request
            .header_value("host")
            .map(normalize_host)
            .is_some_and(|host| self.allowed_hosts.contains(&host));
        let Some(origin) = request.header_value("origin") else {
            return BTreeMap::new();
        };
        if host_allowed && self.origin_is_allowed(origin) {
            self.cors_headers(origin)
        } else {
            BTreeMap::new()
        }
    }

    fn origin_is_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.contains(origin) || origin == "null"
    }
}

fn denied(status: u16, error: &str, gate: &str) -> LocalApiResponse {
    LocalApiResponse {
        status,
        headers: BTreeMap::new(),
        body: json!({
            "error": error,
            "gate": gate,
            "side_effect_executed": false
        }),
    }
}

fn response_with_headers(
    status: u16,
    headers: BTreeMap<String, String>,
    body: Value,
) -> LocalApiResponse {
    LocalApiResponse {
        status,
        headers,
        body,
    }
}

fn parse_http_request(raw: &str) -> (LocalApiRequest, Option<Value>) {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let mut request = LocalApiRequest::new(method, path);

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            request = request.header(name.trim(), value.trim());
        }
    }

    let body = if body.trim().is_empty() {
        None
    } else {
        serde_json::from_str(body.trim()).ok()
    };
    (request, body)
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "Runwarden",
    }
}

fn normalize_header_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn normalize_host(host: impl Into<String>) -> String {
    host.into()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}
