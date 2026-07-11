mod email;
mod file;
mod input;
mod network;
mod store;

use std::collections::BTreeMap;

use runwarden_kernel::KernelProvider;
use runwarden_kernel::resource::{DataClass, ResourceClaim};
use runwarden_kernel::trace::Sha256Digest;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::executor::canonical_provider_contract_hash;
use email::EmailExtractor;
use file::FileExtractor;
use input::InputExtractor;
use network::NetworkExtractor;
use store::StoreExtractor;

pub use email::canonicalize_recipients as canonicalize_email_recipients;
pub use file::canonicalize_path as canonicalize_file_path;
pub use network::{
    canonicalize_method as canonicalize_http_method,
    canonicalize_origin as canonicalize_http_origin,
};

const RESERVED_FIELDS: &[&str] = &[
    "active_assessment",
    "active_instance_id",
    "allowed_origins",
    "approval_id",
    "approval_required",
    "args",
    "authz_grants",
    "authz_id",
    "authority",
    "budget",
    "budget_charge",
    "budget_usage",
    "budgets",
    "classification",
    "command",
    "cwd",
    "default_classification",
    "egress",
    "env",
    "environment",
    "execution_permit",
    "execution_started_version",
    "filesystem_root",
    "instance_token",
    "knowledge_namespace",
    "lease_id",
    "memory_namespace",
    "namespace",
    "operation_id",
    "permit",
    "permissions",
    "policy",
    "policy_snapshot",
    "policy_snapshot_hash",
    "provider",
    "requires_approval",
    "resource_claim",
    "resource_claim_hash",
    "root",
    "root_path",
    "runtime",
    "sandbox_root",
    "session_allowed_providers",
    "session_id",
    "session_roots",
    "simulated_approval",
    "story_id",
    "timeout",
    "timeout_ms",
    "transport",
    "wall_time_ms",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceExtractionContext {
    pub filesystem_root: String,
    pub memory_namespace: String,
    pub knowledge_namespace: String,
    pub default_classification: DataClass,
}

pub trait ResourceExtractor: Send + Sync {
    fn extract(
        &self,
        provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResourceExtractionError {
    #[error("provider arguments must be a JSON object")]
    ArgumentsNotObject,
    #[error("resource extractor is not registered for this provider")]
    ExtractorNotRegistered,
    #[error("provider contract does not match the canonical catalog entry")]
    ProviderContractMismatch,
    #[error("action is not supported by this provider")]
    UnsupportedAction,
    #[error("reserved field is not allowed: {field}")]
    ReservedField { field: String },
    #[error("unknown field is not allowed: {field}")]
    UnknownField { field: String },
    #[error("required field is missing: {field}")]
    MissingField { field: &'static str },
    #[error("field has an invalid JSON type: {field}")]
    InvalidFieldType { field: &'static str },
    #[error("filesystem path is invalid")]
    InvalidPath,
    #[error("email recipient is invalid")]
    InvalidMailbox,
    #[error("email recipient set must not be empty")]
    EmptyRecipients,
    #[error("network URL is invalid")]
    InvalidUrl,
    #[error("HTTP method is invalid")]
    InvalidHttpMethod,
    #[error("store key is invalid")]
    InvalidStoreKey,
    #[error("trusted extraction context field is invalid: {field}")]
    InvalidContext { field: &'static str },
}

impl ResourceExtractionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ArgumentsNotObject => "arguments_not_object",
            Self::ExtractorNotRegistered => "extractor_not_registered",
            Self::ProviderContractMismatch => "provider_contract_mismatch",
            Self::UnsupportedAction => "unsupported_action",
            Self::ReservedField { .. } => "reserved_field",
            Self::UnknownField { .. } => "unknown_field",
            Self::MissingField { .. } => "missing_field",
            Self::InvalidFieldType { .. } => "invalid_field_type",
            Self::InvalidPath => "invalid_path",
            Self::InvalidMailbox => "invalid_mailbox",
            Self::EmptyRecipients => "empty_recipients",
            Self::InvalidUrl => "invalid_url",
            Self::InvalidHttpMethod => "invalid_http_method",
            Self::InvalidStoreKey => "invalid_store_key",
            Self::InvalidContext { .. } => "invalid_context",
        }
    }
}

pub struct ResourceExtractorRegistry {
    extractors: BTreeMap<String, Box<dyn ResourceExtractor>>,
    canonical_provider_digests: BTreeMap<String, Sha256Digest>,
}

impl ResourceExtractorRegistry {
    pub fn contest_default() -> Self {
        let mut extractors: BTreeMap<String, Box<dyn ResourceExtractor>> = BTreeMap::new();
        register(
            &mut extractors,
            "external.mcp.filesystem.read_file",
            FileExtractor::read(),
        );
        register(
            &mut extractors,
            "external.mcp.filesystem.write_file",
            FileExtractor::write(),
        );
        register(&mut extractors, "external.email.send", EmailExtractor);
        register(
            &mut extractors,
            "external.api.request",
            NetworkExtractor::api(),
        );
        register(
            &mut extractors,
            "external.mcp.browser.open_page",
            NetworkExtractor::browser(),
        );
        register(
            &mut extractors,
            "external.memory.read",
            StoreExtractor::memory_read(),
        );
        register(
            &mut extractors,
            "external.memory.write",
            StoreExtractor::memory_write(),
        );
        register(
            &mut extractors,
            "external.knowledge.read",
            StoreExtractor::knowledge_read(),
        );
        register(
            &mut extractors,
            "external.knowledge.write",
            StoreExtractor::knowledge_write(),
        );
        register(&mut extractors, "runwarden.input.inspect", InputExtractor);

        let provider_registry = crate::catalog::full_provider_registry();
        let canonical_provider_digests = extractors
            .keys()
            .map(|provider_id| {
                let provider = provider_registry
                    .get(provider_id)
                    .expect("every contest extractor has a canonical provider");
                (
                    provider_id.clone(),
                    canonical_provider_contract_hash(provider)
                        .expect("built-in provider contract serializes"),
                )
            })
            .collect();

        Self {
            extractors,
            canonical_provider_digests,
        }
    }

    pub fn extract(
        &self,
        provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError> {
        object_without_reserved_fields(arguments)?;
        let extractor = self
            .extractors
            .get(&provider.id)
            .ok_or(ResourceExtractionError::ExtractorNotRegistered)?;
        let canonical_digest = self
            .canonical_provider_digests
            .get(&provider.id)
            .ok_or(ResourceExtractionError::ExtractorNotRegistered)?;
        if canonical_provider_contract_hash(provider)
            .map_err(|_| ResourceExtractionError::ProviderContractMismatch)?
            != *canonical_digest
        {
            return Err(ResourceExtractionError::ProviderContractMismatch);
        }
        extractor.extract(provider, action, arguments, context)
    }
}

impl Default for ResourceExtractorRegistry {
    fn default() -> Self {
        Self::contest_default()
    }
}

fn register<E>(
    extractors: &mut BTreeMap<String, Box<dyn ResourceExtractor>>,
    provider_id: &str,
    extractor: E,
) where
    E: ResourceExtractor + 'static,
{
    let previous = extractors.insert(provider_id.to_owned(), Box::new(extractor));
    assert!(previous.is_none(), "duplicate built-in resource extractor");
}

pub(super) fn validated_object<'a>(
    arguments: &'a Value,
    allowed: &[&str],
    required: &[&'static str],
) -> Result<&'a Map<String, Value>, ResourceExtractionError> {
    let object = object_without_reserved_fields(arguments)?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(ResourceExtractionError::UnknownField {
            field: safe_field_label(field),
        });
    }
    if let Some(field) = required.iter().find(|field| !object.contains_key(**field)) {
        return Err(ResourceExtractionError::MissingField { field });
    }
    Ok(object)
}

fn object_without_reserved_fields(
    arguments: &Value,
) -> Result<&Map<String, Value>, ResourceExtractionError> {
    let object = arguments
        .as_object()
        .ok_or(ResourceExtractionError::ArgumentsNotObject)?;
    if let Some(field) = object
        .keys()
        .find(|field| RESERVED_FIELDS.contains(&field.as_str()))
    {
        return Err(ResourceExtractionError::ReservedField {
            field: safe_field_label(field),
        });
    }
    Ok(object)
}

pub(super) fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ResourceExtractionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ResourceExtractionError::InvalidFieldType { field })
}

pub(super) fn validate_optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<(), ResourceExtractionError> {
    if object.get(field).is_some_and(|value| !value.is_string()) {
        return Err(ResourceExtractionError::InvalidFieldType { field });
    }
    Ok(())
}

pub(super) fn validate_context_value(
    value: &str,
    field: &'static str,
) -> Result<(), ResourceExtractionError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.len() > 256
    {
        return Err(ResourceExtractionError::InvalidContext { field });
    }
    Ok(())
}

fn safe_field_label(field: &str) -> String {
    if !field.is_empty()
        && field.len() <= 64
        && field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        field.to_owned()
    } else {
        "unrecognized".to_owned()
    }
}
