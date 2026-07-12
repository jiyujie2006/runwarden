use runwarden_kernel::operation::SafeProviderOutput;
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::trace::Sha256Digest;
use serde_json::Value;

use crate::demo_tools::{ToolError, ToolExecution};
use crate::input::{InputInspectPolicy, InputSource, inspect_input};

pub(crate) fn inspect_bounded_input(
    arguments: &Value,
    claim: &ResourceClaim,
) -> Result<ToolExecution, ToolError> {
    let input = arguments
        .as_object()
        .and_then(|object| object.get("input_text"))
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    let ResourceClaim::InputInspection {
        source,
        content_hash,
        ..
    } = claim
    else {
        return Err(ToolError::ClaimMismatch);
    };
    if source != "tool_input" || &Sha256Digest::from_bytes(input.as_bytes()) != content_hash {
        return Err(ToolError::ClaimMismatch);
    }
    let inspection = inspect_input(
        InputSource::ToolInput,
        input.as_bytes(),
        InputInspectPolicy::default(),
    );
    let risk_codes = inspection
        .risks
        .iter()
        .filter_map(|risk| serde_json::to_value(&risk.kind).ok())
        .filter_map(|value| value.as_str().map(camel_to_snake))
        .collect();
    Ok(ToolExecution::completed(
        SafeProviderOutput::Input {
            content_hash: content_hash.clone(),
            risk_codes,
        },
        BudgetCharge {
            calls: 1,
            file_bytes: 0,
            network_bytes: 0,
        },
    ))
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index != 0 {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}
