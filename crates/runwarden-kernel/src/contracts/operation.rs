use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Ok,
    Denied,
    RequiresReview,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    ManifestInvalid,
    ProviderUnknown,
    ProviderNotAllowed,
    ArgumentSchemaInvalid,
    ScopeViolation,
    RootEscape,
    EgressDenied,
    BudgetExceeded,
    ActiveAssessmentRequired,
    AuthzInvalid,
    ApprovalInvalid,
    ApprovalConsumed,
    ApprovalExpired,
    TraceTampered,
    TraceWriteFailed,
    RedactionFailed,
    ArtifactInvalid,
    ReportCitationInvalid,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorCode(pub String);

impl ErrorCode {
    pub fn new(kind: &ErrorKind) -> Self {
        let suffix = match kind {
            ErrorKind::ManifestInvalid => "manifest_invalid",
            ErrorKind::ProviderUnknown => "provider_unknown",
            ErrorKind::ProviderNotAllowed => "provider_not_allowed",
            ErrorKind::ArgumentSchemaInvalid => "argument_schema_invalid",
            ErrorKind::ScopeViolation => "scope_violation",
            ErrorKind::RootEscape => "root_escape",
            ErrorKind::EgressDenied => "egress_denied",
            ErrorKind::BudgetExceeded => "budget_exceeded",
            ErrorKind::ActiveAssessmentRequired => "active_assessment_required",
            ErrorKind::AuthzInvalid => "authz_invalid",
            ErrorKind::ApprovalInvalid => "approval_invalid",
            ErrorKind::ApprovalConsumed => "approval_consumed",
            ErrorKind::ApprovalExpired => "approval_expired",
            ErrorKind::TraceTampered => "trace_tampered",
            ErrorKind::TraceWriteFailed => "trace_write_failed",
            ErrorKind::RedactionFailed => "redaction_failed",
            ErrorKind::ArtifactInvalid => "artifact_invalid",
            ErrorKind::ReportCitationInvalid => "report_citation_invalid",
            ErrorKind::Internal => "internal",
        };
        Self(format!("RW_{suffix}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationError {
    pub kind: ErrorKind,
    pub code: ErrorCode,
    pub user_message: String,
    pub developer_message: String,
    pub obs_refs: Vec<String>,
    pub retryable: bool,
    pub side_effect_executed: bool,
}

impl OperationError {
    pub fn fail_closed(kind: ErrorKind, user_message: impl Into<String>) -> Self {
        let code = ErrorCode::new(&kind);
        Self {
            kind,
            code,
            user_message: user_message.into(),
            developer_message:
                "Runwarden rejected or failed the operation before treating it as trusted."
                    .to_string(),
            obs_refs: Vec::new(),
            retryable: false,
            side_effect_executed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationResult<T>
where
    T: JsonSchema,
{
    pub ok: bool,
    pub status: OperationStatus,
    pub data: Option<T>,
    pub error: Option<OperationError>,
    pub obs_refs: Vec<String>,
    pub artifacts: Vec<super::ArtifactRef>,
    pub next_actions: Vec<String>,
}

impl<T> OperationResult<T>
where
    T: JsonSchema,
{
    pub fn ok(data: T) -> Self {
        Self {
            ok: true,
            status: OperationStatus::Ok,
            data: Some(data),
            error: None,
            obs_refs: Vec::new(),
            artifacts: Vec::new(),
            next_actions: Vec::new(),
        }
    }

    pub fn denied(error: OperationError) -> Self {
        Self {
            ok: false,
            status: OperationStatus::Denied,
            data: None,
            error: Some(error),
            obs_refs: Vec::new(),
            artifacts: Vec::new(),
            next_actions: Vec::new(),
        }
    }
}
