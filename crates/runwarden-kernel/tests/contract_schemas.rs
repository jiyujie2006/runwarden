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
            "required": ["claims"],
            "properties": {
                "claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["id", "text", "obs_refs"],
                        "properties": {
                            "id": {"type": "string"},
                            "text": {"type": "string"},
                            "obs_refs": {
                                "type": "array",
                                "items": {"type": "string", "pattern": "^obs_"}
                            },
                            "support": {
                                "type": "object",
                                "minProperties": 1,
                                "properties": {
                                    "provider": {"type": "string"},
                                    "event_type": {"type": "string"},
                                    "decision": {"type": "string"},
                                    "execution_status": {"type": "string"},
                                    "side_effect_executed": {"type": "boolean"}
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
fn active_typescript_surface_is_static_webui_only() {
    let root = workspace_root();
    let workspace =
        fs::read_to_string(root.join("pnpm-workspace.yaml")).expect("read pnpm workspace");
    let package_entries: Vec<_> = workspace
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .map(|entry| entry.trim_matches('"'))
        .collect();
    assert_eq!(package_entries, ["packages/webui"]);
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
