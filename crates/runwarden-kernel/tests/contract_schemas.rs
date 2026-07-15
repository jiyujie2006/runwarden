use std::fs;
use std::path::{Path, PathBuf};

use runwarden_kernel::artifact::ArtifactManifest;
use runwarden_kernel::authority::ApprovalRecord;
use runwarden_kernel::evidence::TraceEvent;
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_kernel::{
    OperationResult, ProviderCall, ProviderContract, ProviderManifest, ProviderOutcome,
};
use schemars::schema_for;
use serde_json::Value;

#[test]
fn rust_contracts_generate_json_schemas() {
    let provider_call = schema_for!(ProviderCall);
    let provider_outcome = schema_for!(ProviderOutcome);
    let approval_record = schema_for!(ApprovalRecord);
    let operation_result = schema_for!(OperationResult<ProviderOutcome>);

    assert_schema_title(provider_call, "ProviderCall");
    assert_schema_title(provider_outcome, "ProviderOutcome");
    assert_schema_title(approval_record, "ApprovalRecord");
    assert_schema_title(operation_result, "OperationResult_for_ProviderOutcome");
}

#[test]
fn checked_in_schema_artifacts_match_rust_contracts() {
    let root = workspace_root();

    assert_schema_file_matches(
        &root,
        "provider-call.schema.json",
        serde_json::to_value(schema_for!(ProviderCall)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "provider-outcome.schema.json",
        serde_json::to_value(schema_for!(ProviderOutcome)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "operation-result.schema.json",
        serde_json::to_value(schema_for!(OperationResult<ProviderOutcome>)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "approval-record.schema.json",
        serde_json::to_value(schema_for!(ApprovalRecord)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "trace-event.schema.json",
        serde_json::to_value(schema_for!(TraceEvent)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "assessment-manifest.schema.json",
        serde_json::to_value(schema_for!(AssessmentManifest)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "session-manifest.schema.json",
        serde_json::to_value(schema_for!(SessionManifest)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "artifact-manifest.schema.json",
        serde_json::to_value(schema_for!(ArtifactManifest)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "provider-manifest.schema.json",
        serde_json::to_value(schema_for!(ProviderManifest)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "provider-contract.schema.json",
        serde_json::to_value(schema_for!(ProviderContract)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "report.schema.json",
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "ReportDraft",
            "type": "object",
            "additionalProperties": false,
            "required": ["claims"],
            "properties": {
                "claims": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["id", "text", "obs_refs", "support"],
                        "properties": {
                            "id": {"type": "string"},
                            "text": {"type": "string"},
                            "obs_refs": {
                                "type": "array",
                                "minItems": 1,
                                "items": {"type": "string", "pattern": "^obs_"}
                            },
                            "support": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["provider", "event_type", "decision", "execution_status", "side_effect_executed"],
                                "properties": {
                                    "provider": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]*$"},
                                    "event_type": {"type": "string", "enum": ["provider_completed", "provider_policy_evaluated", "provider_denied", "provider_approval_pending", "provider_requires_review", "provider_simulated_replay", "provider_failed"]},
                                    "decision": {"type": "string", "enum": ["allowed", "denied", "requires_review"]},
                                    "execution_status": {"type": "string", "enum": ["not_executed", "running", "completed", "failed", "incomplete", "simulated"]},
                                    "side_effect_executed": {"type": "boolean"},
                                    "simulated": {"type": "boolean"}
                                }
                            }
                        }
                    }
                }
            }
        }),
    );
}

#[test]
fn active_typescript_webui_surface_is_removed() {
    let root = workspace_root();
    assert!(!root.join("pnpm-workspace.yaml").exists());
    assert!(!root.join("packages/webui").exists());
}

#[test]
fn artifact_paths_are_schema_restricted_to_relative_workspace_paths() {
    let root = workspace_root();
    let artifact = read_schema(&root, "artifact-manifest.schema.json");
    let entry = artifact["definitions"]["ArtifactManifestEntry"]["properties"]
        .as_object()
        .expect("artifact entry properties");

    for field in ["relative_path", "redaction_sidecar_path"] {
        assert_string_or_nullable_string(&entry[field]["type"], field);
        assert_eq!(entry[field]["minLength"], 1, "{field}");
        assert!(
            entry[field]["pattern"]
                .as_str()
                .is_some_and(|pattern| pattern.contains(r"\.\.")),
            "{field} must reject parent traversal"
        );
    }

    let provider_outcome = read_schema(&root, "provider-outcome.schema.json");
    let artifact_ref = provider_outcome["definitions"]["ArtifactRef"]["properties"]
        .as_object()
        .expect("artifact ref properties");
    assert_string_or_nullable_string(&artifact_ref["path"]["type"], "path");
    assert_eq!(artifact_ref["path"]["minLength"], 1);
    assert!(
        artifact_ref["path"]["pattern"]
            .as_str()
            .is_some_and(|pattern| pattern.contains(r"\.\."))
    );
}

#[test]
fn workspace_output_path_rejects_absolute_parent_and_empty_paths() {
    let root = tempfile::tempdir().expect("root");

    assert!(
        runwarden_kernel::artifact::resolve_workspace_relative_path(root.path(), Path::new(""))
            .is_err()
    );
    assert!(
        runwarden_kernel::artifact::resolve_workspace_relative_path(
            root.path(),
            Path::new("/tmp/x")
        )
        .is_err()
    );
    assert!(
        runwarden_kernel::artifact::resolve_workspace_relative_path(root.path(), Path::new("../x"))
            .is_err()
    );
    assert!(
        runwarden_kernel::artifact::resolve_workspace_relative_path(
            root.path(),
            Path::new("a/../x")
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn workspace_output_path_allows_in_root_symlink_but_rejects_escape() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("root");
    let outside = tempfile::tempdir().expect("outside");
    let inside = root.path().join("inside");
    fs::create_dir(&inside).expect("inside dir");
    symlink(&inside, root.path().join("inside-link")).expect("inside symlink");
    symlink(outside.path(), root.path().join("outside-link")).expect("outside symlink");

    assert!(
        runwarden_kernel::artifact::resolve_workspace_relative_path(
            root.path(),
            Path::new("inside-link/out.txt"),
        )
        .is_ok()
    );
    assert!(
        runwarden_kernel::artifact::resolve_workspace_relative_path(
            root.path(),
            Path::new("outside-link/out.txt"),
        )
        .is_err()
    );
}

fn assert_string_or_nullable_string(value: &Value, field: &str) {
    if value == "string" {
        return;
    }
    assert!(
        value
            .as_array()
            .is_some_and(|types| types.iter().any(|kind| kind == "string")),
        "{field} must include string type"
    );
}

fn assert_schema_title(schema: schemars::schema::RootSchema, expected: &str) {
    let value = serde_json::to_value(schema).expect("schema serializes");
    assert_eq!(
        value.get("title").and_then(Value::as_str),
        Some(expected),
        "schema title should stay stable for generated artifacts"
    );
}

fn assert_schema_file_matches(root: &Path, file_name: &str, generated: Value) {
    let checked_in = read_schema(root, file_name);
    assert_eq!(
        checked_in, generated,
        "schema artifact {file_name} is stale; refresh it from the Rust contract type"
    );
}

fn read_schema(root: &Path, file_name: &str) -> Value {
    let body =
        fs::read_to_string(root.join("schemas").join(file_name)).expect("read schema artifact");
    serde_json::from_str(&body).expect("schema JSON")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}
