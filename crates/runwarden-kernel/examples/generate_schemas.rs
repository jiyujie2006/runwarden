use std::{fs, path::Path};

use runwarden_kernel::artifact::ArtifactManifest;
use runwarden_kernel::authority::ApprovalRecord;
use runwarden_kernel::evidence::TraceEvent;
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_kernel::{
    OperationResult, ProviderCall, ProviderContract, ProviderManifest, ProviderOutcome,
};
use schemars::{schema::RootSchema, schema_for};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("schemas");
    fs::create_dir_all(out_dir)?;

    write_schema(
        out_dir.join("provider-call.schema.json"),
        schema_for!(ProviderCall),
    )?;
    write_schema(
        out_dir.join("provider-outcome.schema.json"),
        schema_for!(ProviderOutcome),
    )?;
    write_schema(
        out_dir.join("operation-result.schema.json"),
        schema_for!(OperationResult<ProviderOutcome>),
    )?;
    write_schema(
        out_dir.join("approval-record.schema.json"),
        schema_for!(ApprovalRecord),
    )?;
    write_schema(
        out_dir.join("trace-event.schema.json"),
        schema_for!(TraceEvent),
    )?;
    write_schema(
        out_dir.join("assessment-manifest.schema.json"),
        schema_for!(AssessmentManifest),
    )?;
    write_schema(
        out_dir.join("session-manifest.schema.json"),
        schema_for!(SessionManifest),
    )?;
    write_schema(
        out_dir.join("artifact-manifest.schema.json"),
        schema_for!(ArtifactManifest),
    )?;
    write_schema(
        out_dir.join("provider-manifest.schema.json"),
        schema_for!(ProviderManifest),
    )?;
    write_schema(
        out_dir.join("provider-contract.schema.json"),
        schema_for!(ProviderContract),
    )?;
    write_report_schema(out_dir.join("report.schema.json"))?;

    Ok(())
}

fn write_schema(
    path: impl AsRef<Path>,
    schema: RootSchema,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_string_pretty(&schema)?;
    fs::write(path, format!("{body}\n"))?;
    Ok(())
}

fn write_report_schema(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let schema = serde_json::json!({
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
    });
    let body = serde_json::to_string_pretty(&schema)?;
    fs::write(path, format!("{body}\n"))?;
    Ok(())
}
