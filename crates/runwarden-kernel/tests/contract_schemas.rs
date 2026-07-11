use std::fs;
use std::path::{Path, PathBuf};

use runwarden_kernel::artifact::ArtifactManifest;
use runwarden_kernel::authority::ApprovalRecord;
use runwarden_kernel::bundle::StoryBundleManifest;
use runwarden_kernel::evidence::TraceEvent;
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_kernel::operation::SecurityOperation;
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::session::AuthoritySnapshot;
use runwarden_kernel::story::{SecurityStory, StoryEvidenceView, StoryReplayFrame};
use runwarden_kernel::trace::StoryEvent;
use runwarden_kernel::{
    OperationResult, ProviderCall, ProviderContract, ProviderManifest, ProviderOutcome,
};
use schemars::schema_for;
use serde_json::Value;

const EXPECTED_SCHEMA_FILES: [&str; 19] = [
    "approval-record.schema.json",
    "artifact-manifest.schema.json",
    "assessment-manifest.schema.json",
    "authority-snapshot.schema.json",
    "operation-result.schema.json",
    "provider-call.schema.json",
    "provider-contract.schema.json",
    "provider-manifest.schema.json",
    "provider-outcome.schema.json",
    "report.schema.json",
    "resource-claim.schema.json",
    "security-operation.schema.json",
    "security-story.schema.json",
    "session-manifest.schema.json",
    "story-bundle-manifest.schema.json",
    "story-event.schema.json",
    "story-evidence-view.schema.json",
    "story-replay-frame.schema.json",
    "trace-event.schema.json",
];

const U64_DECIMAL_SCHEMA_COMPONENT: &str = concat!(
    "(?:0|[1-9][0-9]{0,18}",
    "|1[0-7][0-9]{18}",
    "|18[0-3][0-9]{17}",
    "|184[0-3][0-9]{16}",
    "|1844[0-5][0-9]{15}",
    "|18446[0-6][0-9]{14}",
    "|184467[0-3][0-9]{13}",
    "|1844674[0-3][0-9]{12}",
    "|184467440[0-6][0-9]{10}",
    "|1844674407[0-2][0-9]{9}",
    "|18446744073[0-6][0-9]{8}",
    "|1844674407370[0-8][0-9]{6}",
    "|18446744073709[0-4][0-9]{5}",
    "|184467440737095[0-4][0-9]{4}",
    "|18446744073709550[0-9]{3}",
    "|18446744073709551[0-5][0-9]{2}",
    "|1844674407370955160[0-9]",
    "|1844674407370955161[0-5])",
);
const UUID_V7_SCHEMA_PATTERN: &str =
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])";
const OBSERVATION_ID_SCHEMA_PATTERN: &str =
    r"^obs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\s\S])";
const EVENT_CODE_SCHEMA_PATTERN: &str = r"^[A-Za-z0-9.:/@_-]+(?![\s\S])";
const WORKSPACE_RELATIVE_PATH_SCHEMA_PATTERN: &str = r"^(?!\.{1,2}(?:/|(?![\s\S])))[^/\\:\x00\r\n\u2028\u2029]+(?:/(?!\.{1,2}(?:/|(?![\s\S])))[^/\\:\x00\r\n\u2028\u2029]+)*(?![\s\S])";

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
        "security-story.schema.json",
        serde_json::to_value(schema_for!(SecurityStory)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "security-operation.schema.json",
        serde_json::to_value(schema_for!(SecurityOperation)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "story-event.schema.json",
        serde_json::to_value(schema_for!(StoryEvent)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "resource-claim.schema.json",
        serde_json::to_value(schema_for!(ResourceClaim)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "authority-snapshot.schema.json",
        serde_json::to_value(schema_for!(AuthoritySnapshot)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "story-bundle-manifest.schema.json",
        serde_json::to_value(schema_for!(StoryBundleManifest)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "story-replay-frame.schema.json",
        serde_json::to_value(schema_for!(StoryReplayFrame)).expect("schema value"),
    );
    assert_schema_file_matches(
        &root,
        "story-evidence-view.schema.json",
        serde_json::to_value(schema_for!(StoryEvidenceView)).expect("schema value"),
    );
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
                                "minItems": 1,
                                "items": {"type": "string", "pattern": "^obs_"}
                            },
                            "support": {
                                "type": "object",
                                "properties": {
                                    "provider": {"type": "string"},
                                    "event_type": {"type": "string"},
                                    "decision": {"type": "string"},
                                    "execution_status": {"type": "string"},
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
fn checked_in_schema_inventory_is_frozen() {
    let mut actual = fs::read_dir(workspace_root().join("schemas"))
        .expect("read schemas directory")
        .map(|entry| {
            entry
                .expect("read schema directory entry")
                .file_name()
                .into_string()
                .expect("schema file name must be UTF-8")
        })
        .filter(|file_name| file_name.ends_with(".schema.json"))
        .collect::<Vec<_>>();
    actual.sort();

    assert_eq!(actual, EXPECTED_SCHEMA_FILES.map(str::to_string));
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
fn story_bundle_schema_exposes_validated_wire_boundaries() {
    let root = workspace_root();
    let manifest = read_schema(&root, "story-bundle-manifest.schema.json");

    assert_eq!(manifest["additionalProperties"], false);
    assert!(manifest["properties"].get("signature").is_none());
    for definition in ["BundleFileDigest", "BundleVerificationSummary"] {
        assert_eq!(
            manifest["definitions"][definition]["additionalProperties"], false,
            "{definition} must reject unknown fields"
        );
    }

    assert_eq!(
        manifest["definitions"]["BundleFileDigest"]["properties"]["relative_path"]["$ref"],
        "#/definitions/WorkspaceRelativePath"
    );
    let relative_path = &manifest["definitions"]["WorkspaceRelativePath"];
    assert_eq!(relative_path["minLength"], 1);
    assert_eq!(
        relative_path["pattern"],
        WORKSPACE_RELATIVE_PATH_SCHEMA_PATTERN
    );

    let schema_version = &manifest["definitions"]["SchemaVersion"];
    assert_eq!(schema_version["minLength"], 5);
    assert_eq!(schema_version["maxLength"], 43);
    assert_eq!(
        schema_version["pattern"],
        format!(r"^1\.{U64_DECIMAL_SCHEMA_COMPONENT}\.{U64_DECIMAL_SCHEMA_COMPONENT}(?![\s\S])")
    );

    let digest = &manifest["definitions"]["Sha256Digest"];
    assert_eq!(digest["minLength"], 71);
    assert_eq!(digest["maxLength"], 71);
    assert_eq!(digest["pattern"], r"^sha256:[0-9a-f]{64}(?![\s\S])");
}

#[test]
fn story_schemas_expose_validated_identifier_code_and_claim_boundaries() {
    let root = workspace_root();
    let evidence = read_schema(&root, "story-evidence-view.schema.json");
    let definitions = evidence["definitions"]
        .as_object()
        .expect("story evidence definitions");

    for identifier in [
        "StoryId",
        "SessionId",
        "OperationId",
        "EventId",
        "ApprovalId",
        "ExecutionLeaseId",
    ] {
        let schema = &definitions[identifier];
        assert_eq!(schema["type"], "string", "{identifier}");
        assert_eq!(schema["format"], "uuid", "{identifier}");
        assert_eq!(schema["minLength"], 36, "{identifier}");
        assert_eq!(schema["maxLength"], 36, "{identifier}");
        assert_eq!(schema["pattern"], UUID_V7_SCHEMA_PATTERN, "{identifier}");
    }

    let observation = &definitions["ObservationId"];
    assert_eq!(observation["type"], "string");
    assert!(observation.get("format").is_none());
    assert_eq!(observation["minLength"], 40);
    assert_eq!(observation["maxLength"], 40);
    assert_eq!(observation["pattern"], OBSERVATION_ID_SCHEMA_PATTERN);

    let event_code = &definitions["EventCode"];
    assert_eq!(event_code["type"], "string");
    assert_eq!(event_code["minLength"], 1);
    assert_eq!(event_code["maxLength"], 128);
    assert_eq!(event_code["pattern"], EVENT_CODE_SCHEMA_PATTERN);

    let claim_support = &definitions["ReportClaimSupport"];
    assert_eq!(claim_support["type"], "object");
    assert_eq!(claim_support["additionalProperties"], false);
    let requirements = claim_support["anyOf"]
        .as_array()
        .expect("non-null claim support requirements");
    assert_eq!(requirements.len(), 6);

    let mut required_fields = requirements
        .iter()
        .map(|requirement| {
            let fields = requirement["required"]
                .as_array()
                .expect("claim support required fields");
            assert_eq!(fields.len(), 1);
            let field = fields[0].as_str().expect("required field name");
            let property = &requirement["properties"][field];
            assert!(!schema_explicitly_allows_null(property), "{field}");
            field
        })
        .collect::<Vec<_>>();
    required_fields.sort_unstable();
    assert_eq!(
        required_fields,
        [
            "event_kind",
            "operation_state",
            "policy_decision",
            "provider",
            "side_effect_state",
            "simulated",
        ]
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

fn schema_explicitly_allows_null(schema: &Value) -> bool {
    schema["type"] == "null"
        || schema["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|kind| kind == "null"))
        || schema["anyOf"]
            .as_array()
            .is_some_and(|variants| variants.iter().any(schema_explicitly_allows_null))
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
    let body = fs::read_to_string(root.join("schemas").join(file_name))
        .unwrap_or_else(|error| panic!("read schema artifact {file_name}: {error}"));
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
