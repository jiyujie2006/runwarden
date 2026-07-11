use runwarden_kernel::KernelProvider;
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::trace::Sha256Digest;
use serde_json::Value;

use super::{
    ResourceExtractionContext, ResourceExtractionError, ResourceExtractor, required_string,
    validated_object,
};

pub(super) struct InputExtractor;

impl ResourceExtractor for InputExtractor {
    fn extract(
        &self,
        _provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError> {
        if action != "inspect" {
            return Err(ResourceExtractionError::UnsupportedAction);
        }
        let object = validated_object(arguments, &["input_text"], &["input_text"])?;
        let input = required_string(object, "input_text")?;
        Ok(ResourceClaim::InputInspection {
            source: "tool_input".to_owned(),
            content_hash: Sha256Digest::from_bytes(input.as_bytes()),
            classification: context.default_classification,
        })
    }
}
