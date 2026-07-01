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
