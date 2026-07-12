use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequestParts, Json, Path, Query, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::request::Parts;
use axum::http::{StatusCode, header::HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::operation::{OperationState, SecurityOperation, SideEffectState};
use runwarden_kernel::story::{
    ApprovalId, EvidenceStatus, OperationId, SecurityStory, StoryClaim, StoryEvidenceView, StoryId,
    StoryProvenance,
};
use runwarden_kernel::trace::StoryEvent;
use runwarden_state::{ApprovalDecisionInput, JournalError, ReviewerDecision, StateStore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::{REVIEWER_NONCE_HEADER_LOWER, ReviewerApiState};

const EVENT_PAGE_LIMIT: u64 = 256;
const CACHE_CONTROL_VALUE: &str = "no-store, no-cache, must-revalidate, private";

pub(super) fn routes() -> Router<ReviewerApiState> {
    Router::new()
        .route("/api/bootstrap", get(bootstrap))
        .route("/api/stories", get(stories))
        .route("/api/stories/{story_id}", get(story))
        .route("/api/stories/{story_id}/events", get(story_events))
        .route(
            "/api/stories/{story_id}/operations/{operation_id}",
            get(story_operation),
        )
        .route("/api/stories/{story_id}/report", get(story_report))
        .route(
            "/api/stories/{story_id}/evidence/verify",
            get(verify_story_evidence),
        )
        .route(
            "/api/approvals/{approval_id}/decision",
            post(decide_approval).options(reject_preflight),
        )
}

#[derive(Serialize)]
struct ReviewerBootstrap {
    schema_version: String,
    mode: String,
    active_story_id: StoryId,
    reviewer_nonce: String,
    accepted_origin: String,
    evidence: StoryEvidenceView,
}

async fn bootstrap(State(state): State<ReviewerApiState>) -> Result<Response, ApiError> {
    let active_story_id = require_active_story_id(&state.store, StatusCode::CONFLICT)?;
    let evidence = state
        .store
        .story_evidence(active_story_id)
        .map_err(ApiError::read_journal)?;
    require_live_story(&evidence.story)?;
    let bootstrap = ReviewerBootstrap {
        schema_version: evidence.story.schema_version.as_str().to_owned(),
        mode: "live".to_owned(),
        active_story_id,
        reviewer_nonce: state.nonce.encoded(),
        accepted_origin: state.accepted_origin.clone(),
        evidence,
    };
    let mut response = Json(bootstrap).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL_VALUE),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    Ok(response)
}

async fn stories(
    State(state): State<ReviewerApiState>,
) -> Result<Json<Vec<SecurityStory>>, ApiError> {
    let Some(active) = state.store.active_demo().map_err(ApiError::read_journal)? else {
        return Ok(Json(Vec::new()));
    };
    let story = state
        .store
        .story_snapshot(active.story_id)
        .map_err(ApiError::read_journal)?;
    if !is_live_story(&story) {
        return Ok(Json(Vec::new()));
    }
    Ok(Json(vec![story]))
}

async fn story(
    State(state): State<ReviewerApiState>,
    Path(story_id): Path<String>,
) -> Result<Json<SecurityStory>, ApiError> {
    let story_id = parse_path_id(&story_id, "story")?;
    Ok(Json(active_story_snapshot(&state.store, story_id)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoryEventsQuery {
    #[serde(default)]
    after_seq: u64,
}

async fn story_events(
    State(state): State<ReviewerApiState>,
    Path(story_id): Path<String>,
    query: Result<Query<StoryEventsQuery>, QueryRejection>,
) -> Result<Json<Vec<StoryEvent>>, ApiError> {
    let story_id = parse_path_id(&story_id, "story")?;
    active_story_snapshot(&state.store, story_id)?;
    let Query(query) = query.map_err(|_| ApiError::unprocessable("invalid_query"))?;
    let events = state
        .store
        .events_after(story_id, query.after_seq, EVENT_PAGE_LIMIT)
        .map_err(ApiError::read_journal)?;
    Ok(Json(events))
}

#[derive(Serialize)]
struct ReviewerOperation {
    operation: SecurityOperation,
    approval_version: Option<u64>,
}

async fn story_operation(
    State(state): State<ReviewerApiState>,
    Path((story_id, operation_id)): Path<(String, String)>,
) -> Result<Json<ReviewerOperation>, ApiError> {
    let story_id = parse_path_id(&story_id, "story")?;
    let operation_id = parse_path_id(&operation_id, "operation")?;
    active_story_snapshot(&state.store, story_id)?;
    let snapshot = state
        .store
        .reviewer_operation_snapshot(story_id, operation_id)
        .map_err(ApiError::read_journal)?;
    Ok(Json(ReviewerOperation {
        operation: snapshot.operation,
        approval_version: snapshot.approval_version,
    }))
}

async fn story_report(
    State(state): State<ReviewerApiState>,
    Path(story_id): Path<String>,
) -> Result<Json<Vec<StoryClaim>>, ApiError> {
    let story_id = parse_path_id(&story_id, "story")?;
    let story = active_story_snapshot(&state.store, story_id)?;
    Ok(Json(story.report_claims))
}

#[derive(Serialize)]
struct StructuralVerification {
    verification_scope: &'static str,
    structural_valid: bool,
    evidence_status: EvidenceStatus,
}

async fn verify_story_evidence(
    State(state): State<ReviewerApiState>,
    Path(story_id): Path<String>,
) -> Result<Json<StructuralVerification>, ApiError> {
    let story_id = parse_path_id(&story_id, "story")?;
    require_active_story(&state.store, story_id)?;
    let evidence = state
        .store
        .story_evidence(story_id)
        .map_err(ApiError::read_journal)?;
    require_live_story(&evidence.story)?;
    let evidence_status = evidence.story.evidence_status;
    evidence
        .verify_structure()
        .map_err(|_| ApiError::internal("story_structure_invalid"))?;
    Ok(Json(StructuralVerification {
        verification_scope: "structural",
        structural_valid: true,
        evidence_status,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionBody {
    decision: ReviewerDecision,
    reviewer: String,
    reason: String,
    expected_approval_version: u64,
    expected_operation_version: u64,
}

#[derive(Serialize)]
struct ApprovalDecisionResponse {
    approval_id: ApprovalId,
    operation_id: OperationId,
    approval_state: ApprovalState,
    approval_version: u64,
    operation_state: OperationState,
    operation_version: u64,
    side_effect_state: SideEffectState,
}

async fn decide_approval(
    State(state): State<ReviewerApiState>,
    Path(approval_id): Path<String>,
    _guard: ReviewerWriteGuard,
    body: Result<Json<ApprovalDecisionBody>, JsonRejection>,
) -> Result<Json<ApprovalDecisionResponse>, ApiError> {
    let approval_id = parse_path_id(&approval_id, "approval")?;
    let Json(body) = body.map_err(|_| ApiError::unprocessable("invalid_body"))?;
    validate_reviewer_body(&body)?;

    let outcome = state
        .store
        .decide_active_approval(ApprovalDecisionInput {
            approval_id,
            expected_version: body.expected_approval_version,
            expected_operation_version: body.expected_operation_version,
            reviewer: body.reviewer,
            reason: body.reason,
            decision: body.decision,
            now: OffsetDateTime::now_utc(),
        })
        .map_err(ApiError::decision_journal)?;
    let approval = outcome.approval;
    let operation = outcome.operation;
    Ok(Json(ApprovalDecisionResponse {
        approval_id: approval.approval_id,
        operation_id: approval.operation_id,
        approval_state: approval.state,
        approval_version: approval.version,
        operation_state: operation.state,
        operation_version: operation.version,
        side_effect_state: operation.side_effect_state,
    }))
}

fn validate_reviewer_body(body: &ApprovalDecisionBody) -> Result<(), ApiError> {
    if body.reviewer.trim().is_empty()
        || body.reviewer.len() > 256
        || body.reason.trim().is_empty()
        || body.reason.len() > 4_096
    {
        return Err(ApiError::unprocessable("invalid_reviewer_decision"));
    }
    Ok(())
}

async fn reject_preflight() -> ApiError {
    ApiError::forbidden("cross_origin_preflight_forbidden")
}

struct ReviewerWriteGuard;

impl FromRequestParts<ReviewerApiState> for ReviewerWriteGuard {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ReviewerApiState,
    ) -> Result<Self, Self::Rejection> {
        let origin = exactly_one_header(&parts.headers, header::ORIGIN)
            .ok_or_else(|| ApiError::forbidden("reviewer_origin_forbidden"))?;
        if origin.as_bytes() != state.accepted_origin.as_bytes() {
            return Err(ApiError::forbidden("reviewer_origin_forbidden"));
        }
        let nonce_header = HeaderName::from_static(REVIEWER_NONCE_HEADER_LOWER);
        let nonce = exactly_one_header(&parts.headers, nonce_header)
            .ok_or_else(|| ApiError::forbidden("reviewer_nonce_forbidden"))?;
        if !state.nonce.matches(nonce) {
            return Err(ApiError::forbidden("reviewer_nonce_forbidden"));
        }
        Ok(Self)
    }
}

pub(super) fn exactly_one_header(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

pub(super) fn active_story_snapshot(
    store: &StateStore,
    requested_story_id: StoryId,
) -> Result<SecurityStory, ApiError> {
    require_active_story(store, requested_story_id)?;
    let story = store
        .story_snapshot(requested_story_id)
        .map_err(ApiError::read_journal)?;
    require_live_story(&story)?;
    Ok(story)
}

fn require_active_story(store: &StateStore, requested_story_id: StoryId) -> Result<(), ApiError> {
    let active_story_id = require_active_story_id(store, StatusCode::NOT_FOUND)?;
    if active_story_id != requested_story_id {
        return Err(ApiError::not_found("story_not_found"));
    }
    Ok(())
}

fn require_active_story_id(
    store: &StateStore,
    missing_status: StatusCode,
) -> Result<StoryId, ApiError> {
    let active = store.active_demo().map_err(ApiError::read_journal)?;
    active.map(|active| active.story_id).ok_or_else(|| {
        if missing_status == StatusCode::NOT_FOUND {
            ApiError::not_found("active_story_not_found")
        } else {
            ApiError::conflict("reviewer_context_inactive")
        }
    })
}

fn require_live_story(story: &SecurityStory) -> Result<(), ApiError> {
    if is_live_story(story) {
        Ok(())
    } else {
        Err(ApiError::conflict("reviewer_context_inactive"))
    }
}

fn is_live_story(story: &SecurityStory) -> bool {
    story.provenance == StoryProvenance::Native
        && story.authority.authz_state == "active"
        && OffsetDateTime::now_utc() < story.authority.expires_at
}

pub(super) fn parse_path_id<T: DeserializeOwned>(
    raw: &str,
    entity: &'static str,
) -> Result<T, ApiError> {
    serde_json::from_value(Value::String(raw.to_owned())).map_err(|_| {
        ApiError::not_found(match entity {
            "story" => "story_not_found",
            "operation" => "operation_not_found",
            "approval" => "approval_not_found",
            _ => "entity_not_found",
        })
    })
}

#[derive(Serialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
}

pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn not_found(code: &'static str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            code,
            "requested reviewer entity was not found",
        )
    }

    fn forbidden(code: &'static str) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            code,
            "reviewer request was forbidden",
        )
    }

    fn conflict(code: &'static str) -> Self {
        Self::new(
            StatusCode::CONFLICT,
            code,
            "reviewer state changed or is not active",
        )
    }

    pub(super) fn unprocessable(code: &'static str) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            code,
            "reviewer request body was invalid",
        )
    }

    fn internal(code: &'static str) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            code,
            "reviewer state could not be read safely",
        )
    }

    fn unavailable(code: &'static str) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            code,
            "reviewer state storage is unavailable",
        )
    }

    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    pub(super) fn read_journal(error: JournalError) -> Self {
        match error {
            JournalError::NotFound { .. } => Self::not_found("reviewer_entity_not_found"),
            JournalError::Conflict { .. }
            | JournalError::InvocationConflict { .. }
            | JournalError::InvalidTransition { .. } => Self::conflict("reviewer_state_conflict"),
            JournalError::Permission(_) | JournalError::Sqlite(_) => {
                Self::unavailable("reviewer_storage_unavailable")
            }
            JournalError::Integrity(_) | JournalError::Json(_) => {
                Self::internal("reviewer_state_integrity_failure")
            }
        }
    }

    fn decision_journal(error: JournalError) -> Self {
        match error {
            JournalError::NotFound { .. } => Self::not_found("approval_not_found"),
            JournalError::Integrity(_)
            | JournalError::Json(_)
            | JournalError::Conflict { .. }
            | JournalError::InvocationConflict { .. }
            | JournalError::InvalidTransition { .. } => Self::conflict("approval_state_conflict"),
            JournalError::Permission(_) | JournalError::Sqlite(_) => {
                Self::unavailable("reviewer_storage_unavailable")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorEnvelope {
                error: ApiErrorBody {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelopes_never_include_journal_details() {
        let response = ApiError::read_journal(JournalError::Integrity(
            "private database detail".to_owned(),
        ));
        let value = serde_json::json!({
            "code": response.code,
            "message": response.message,
        });
        assert!(!value.to_string().contains("private database detail"));
    }
}
