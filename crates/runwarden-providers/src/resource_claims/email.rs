use runwarden_kernel::KernelProvider;
use runwarden_kernel::resource::ResourceClaim;
use serde_json::Value;

use super::{
    ResourceExtractionContext, ResourceExtractionError, ResourceExtractor,
    validate_optional_string, validated_object,
};

pub(super) struct EmailExtractor;

impl ResourceExtractor for EmailExtractor {
    fn extract(
        &self,
        _provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError> {
        if action != "send" {
            return Err(ResourceExtractionError::UnsupportedAction);
        }
        let object = validated_object(arguments, &["to", "subject", "body"], &["to"])?;
        validate_optional_string(object, "subject")?;
        validate_optional_string(object, "body")?;
        let recipients = canonicalize_recipients(
            object
                .get("to")
                .ok_or(ResourceExtractionError::MissingField { field: "to" })?,
        )?;
        Ok(ResourceClaim::Email {
            recipients,
            classification: context.default_classification,
        })
    }
}

pub fn canonicalize_recipients(value: &Value) -> Result<Vec<String>, ResourceExtractionError> {
    let recipients = value
        .as_array()
        .ok_or(ResourceExtractionError::InvalidFieldType { field: "to" })?;
    if recipients.is_empty() {
        return Err(ResourceExtractionError::EmptyRecipients);
    }
    let mut canonical = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let mailbox = recipient
            .as_str()
            .ok_or(ResourceExtractionError::InvalidMailbox)?;
        if mailbox.is_empty()
            || !mailbox.is_ascii()
            || mailbox.trim() != mailbox
            || mailbox
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ResourceExtractionError::InvalidMailbox);
        }
        let mut parts = mailbox.split('@');
        let local = parts.next().unwrap_or_default();
        let domain = parts.next().unwrap_or_default();
        if local.is_empty() || domain.is_empty() || parts.next().is_some() {
            return Err(ResourceExtractionError::InvalidMailbox);
        }
        canonical.push(format!("{local}@{}", domain.to_ascii_lowercase()));
    }
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}
