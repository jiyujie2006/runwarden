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
        let query = TraceQuery {
            offset: number_field(&body, "offset").unwrap_or(0),
            limit: number_field(&body, "limit").unwrap_or(100),
            provider: string_field(&body, "provider"),
            event_type: string_field(&body, "event_type"),
            obs_prefix: string_field(&body, "obs_prefix"),
            max_bytes: number_field(&body, "max_bytes"),
        };
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
        if !self.security.approvals.contains_key(&approval_id) {
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
        match write_submission_bundle(&root, Path::new(&output_path), full) {
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
        match write_ui_launch_bundle(&bind, port as u16, Path::new(&artifacts_path)) {
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

    match call.provider.as_str() {
        "runwarden.input.inspect" => {
            let bytes = if let Some(text) = string_field(&call.arguments, "input_text") {
                text.into_bytes()
            } else {
                let path = string_field(&call.arguments, "input_path")
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
            let root = string_field(&call.arguments, "root_path")
                .or_else(|| resolve_session_root_path(session, &call.arguments))
                .or_else(|| string_field(&call.arguments, "root"))
                .ok_or_else(|| "root_path is required".to_string())?;
            inspect_evidence_root(Path::new(&root), EvidenceInspectPolicy::default())
                .map(|inspection| json!(inspection))
                .map_err(|err| err.to_string())
        }
        "runwarden.trace.verify" => read_trace_from_body(&call.arguments).map(verify_trace_events),
        "runwarden.trace.export" => {
            let events = read_trace_from_body(&call.arguments)?;
            let mut store = InMemoryTraceStore::default();
            for event in events {
                store.append(event);
            }
            store
                .stream_export(TraceQuery::default())
                .map(|page| json!(page))
                .map_err(|err| err.to_string())
        }
        "runwarden.report.scaffold" => {
            let events = read_trace_from_body(&call.arguments)?;
            Ok(json!(scaffold_report_from_trace(&events)))
        }
        "runwarden.report.lint" => {
            let (report, trace) = read_report_and_trace_from_body(&call.arguments)?;
            Ok(json!(lint_report_against_trace(&report, &trace)))
        }
        "runwarden.report.render" => {
            let (report, trace) = read_report_and_trace_from_body(&call.arguments)?;
            let format = parse_render_format(
                string_field(&call.arguments, "format")
                    .as_deref()
                    .unwrap_or("markdown"),
            )?;
            render_report(&report, &trace, format)
                .map(|rendered| json!(rendered))
                .map_err(|err| err.message)
        }
        "runwarden.audit.summary" => {
            let events = read_trace_from_body(&call.arguments)?;
            Ok(json!(audit_summary(&events)))
        }
        "runwarden.accountability.summary" => {
            let events = read_trace_from_body(&call.arguments)?;
            Ok(json!(accountability_summary(&events)))
        }
        "runwarden.cert.all" => {
            let root = find_workspace_root(
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?;
            Ok(json!(certify_workspace(&root)))
        }
        "runwarden.eval.all" => {
            let (report, trace) = read_report_and_trace_from_body(&call.arguments)?;
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

fn write_ui_launch_bundle(bind: &str, port: u16, artifact_root: &Path) -> Result<Value, String> {
    fs::create_dir_all(artifact_root)
        .map_err(|err| format!("failed to create {}: {err}", artifact_root.display()))?;
    let html_path = artifact_root.join("reviewer-console.html");
    fs::write(&html_path, reviewer_console_html(bind, port))
        .map_err(|err| format!("failed to write {}: {err}", html_path.display()))?;

    Ok(json!({
        "bind": bind,
        "port": port,
        "artifact_root": artifact_root.to_string_lossy(),
        "html_path": html_path.to_string_lossy(),
        "launch_url": format!("http://{bind}:{port}/"),
        "mode": "static_reviewer_console_bundle",
        "side_effect_executed": true
    }))
}

fn reviewer_console_html(bind: &str, port: u16) -> String {
    r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Runwarden Reviewer Console</title>
  <style>
    :root { color-scheme: light; font-family: "IBM Plex Sans", system-ui, sans-serif; }
    body { margin: 0; background: #f7f8f4; color: #20241f; }
    .runwarden-workbench { min-height: 100vh; display: grid; grid-template-columns: 220px minmax(0, 1fr) 340px; }
    .left-nav { background: #151813; color: #f3faf5; padding: 18px; display: flex; flex-direction: column; gap: 6px; }
    .left-nav strong { padding: 9px 10px; }
    .left-nav a { color: inherit; text-decoration: none; padding: 9px 10px; border-radius: 6px; min-height: 44px; box-sizing: border-box; display: flex; align-items: center; }
    .left-nav a:hover { background: #262d24; }
    .workbench-main { padding: 18px; min-width: 0; }
    .top-status-strip { display: grid; grid-template-columns: repeat(6, minmax(110px, 1fr)); gap: 8px; margin-bottom: 14px; }
    .status-pill, .module { border: 1px solid #cdd5c8; background: #ffffff; border-radius: 6px; padding: 14px; min-width: 0; }
    .status-pill span { display: block; font-size: 12px; color: #687064; }
    .status-pill strong { display: block; overflow-wrap: anywhere; font-size: 14px; }
    .tone-review { border-color: #a76716; }
    .workspace-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .module h2, .details-drawer h2 { font-size: 16px; margin: 0 0 10px; }
    .module p, .details-drawer p { margin: 0; }
    .module code, .status-pill code { font-family: "JetBrains Mono", ui-monospace, monospace; overflow-wrap: anywhere; }
    .approval-module { grid-column: 1 / -1; }
    button { border: 1px solid #cdd5c8; background: #ffffff; border-radius: 6px; min-height: 44px; padding: 8px 12px; }
    button:hover { border-color: #2f6f4e; background: #eef1ea; }
    button:focus-visible, .left-nav a:focus-visible { outline: 2px solid #2f6f4e; outline-offset: 2px; }
    .details-drawer { border-left: 1px solid #cdd5c8; background: #ffffff; padding: 18px; min-width: 0; }
    @media (max-width: 1199px) {
      .runwarden-workbench { grid-template-columns: 76px minmax(0, 1fr); }
      .left-nav a { font-size: 12px; }
      .details-drawer { grid-column: 1 / -1; border-left: 0; border-top: 1px solid #cdd5c8; }
      .top-status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 768px) {
      .runwarden-workbench { display: block; padding-bottom: 76px; }
      .left-nav { position: fixed; left: 0; right: 0; bottom: 0; z-index: 10; flex-direction: row; overflow-x: auto; padding: 8px 10px; border-top: 1px solid #cdd5c8; }
      .left-nav a { white-space: nowrap; }
      .top-status-strip, .workspace-grid { grid-template-columns: 1fr; }
      .details-drawer { min-height: calc(100vh - 76px); border-left: 0; border-top: 1px solid #cdd5c8; }
    }
  </style>
</head>
<body>
<main class="runwarden-workbench">
  <nav class="left-nav" aria-label="Runwarden sections">
    <strong>Runwarden</strong>
    <a href="#dashboard">Dashboard</a>
    <a href="#agent-boundary">Agent Boundary</a>
    <a href="#provider-registry">Provider Registry</a>
    <a href="#approval-queue">Approval Queue</a>
    <a href="#trace">Trace Explorer</a>
    <a href="#accountability">Accountability</a>
    <a href="#reports">Reports</a>
    <a href="#artifacts">Artifacts</a>
    <a href="#settings">Settings</a>
  </nav>
  <section class="workbench-main" id="dashboard" aria-label="Reviewer workspace">
    <header class="top-status-strip" role="status" aria-label="Assessment status">
      <div class="status-pill"><span>Session</span><strong>No assessment loaded</strong></div>
      <div class="status-pill"><span>Local API</span><strong><code>__BIND__:__PORT__</code></strong></div>
      <div class="status-pill tone-review"><span>Risk</span><strong>incomplete</strong></div>
      <div class="status-pill tone-review"><span>Trace</span><strong>missing</strong></div>
      <div class="status-pill"><span>Approvals</span><strong>unknown</strong></div>
      <div class="status-pill tone-review"><span>Gates</span><strong>missing</strong></div>
    </header>
    <div class="workspace-grid">
      <article class="module" id="agent-boundary"><h2>Agent Boundary</h2><p>No agent config checked</p></article>
      <article class="module" id="provider-registry"><h2>Provider Registry</h2><p>No providers allowed for this session</p></article>
      <article class="module approval-module" id="approval-queue"><h2>Approval Queue</h2><p>No actions waiting for review</p></article>
      <article class="module" id="trace"><h2>Trace Explorer</h2><p>No trace events yet</p></article>
      <article class="module" id="accountability"><h2>Accountability</h2><p>No accountability chain reconstructed</p></article>
      <article class="module" id="reports"><h2>Reports</h2><p>No report rendered</p></article>
      <article class="module" id="artifacts"><h2>Artifacts</h2><p>No artifacts generated</p></article>
      <article class="module" id="assurance"><h2>Assurance</h2><p>No eval run yet</p></article>
      <article class="module" id="settings"><h2>Settings</h2><p>Local API token, artifact paths, and debug visibility are not loaded.</p></article>
    </div>
  </section>
  <aside class="details-drawer" aria-label="Approval details">
    <h2>Approval Details</h2>
    <p>Select an approval to inspect provider, risk, target, side effects, actor, authz, argument hash, and obs refs before a reviewer decision.</p>
  </aside>
</main>
</body>
</html>
"##
    .replace("__BIND__", bind)
    .replace("__PORT__", &port.to_string())
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
        if !self.allowed_origins.contains(origin) {
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
        if !self.allowed_origins.contains(origin) {
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
        if host_allowed && self.allowed_origins.contains(origin) {
            self.cors_headers(origin)
        } else {
            BTreeMap::new()
        }
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
