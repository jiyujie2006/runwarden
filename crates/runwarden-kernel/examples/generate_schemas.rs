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
    });
    let body = serde_json::to_string_pretty(&schema)?;
    fs::write(path, format!("{body}\n"))?;
    Ok(())
}
