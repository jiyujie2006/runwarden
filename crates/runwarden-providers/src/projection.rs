use runwarden_kernel::operation::SafeArgumentView;
use runwarden_kernel::resource::{FileAccess, MemoryAccess, ResourceClaim};
use runwarden_kernel::trace::Sha256Digest;
use serde_json::{Map, Value};

use crate::resource_claims::{
    canonicalize_email_recipients, canonicalize_file_path, canonicalize_http_method,
    canonicalize_http_origin,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SafeArgumentProjectionError {
    #[error("provider arguments must be an object")]
    ArgumentsNotObject,
    #[error("provider arguments are inconsistent with the typed resource claim")]
    ClaimArgumentMismatch,
    #[error("opaque legacy claims have no native safe argument projection")]
    OpaqueLegacy,
}

/// Construct the one display-safe argument projection from an already
/// validated typed claim. Private content is represented only by SHA-256.
pub fn project_safe_arguments(
    arguments: &Value,
    claim: &ResourceClaim,
) -> Result<SafeArgumentView, SafeArgumentProjectionError> {
    let object = arguments
        .as_object()
        .ok_or(SafeArgumentProjectionError::ArgumentsNotObject)?;
    match claim {
        ResourceClaim::File { path, access, .. } => {
            let submitted_path = canonicalize_file_path(required_string(object, "path")?)
                .map_err(|_| SafeArgumentProjectionError::ClaimArgumentMismatch)?;
            if &submitted_path != path {
                return Err(SafeArgumentProjectionError::ClaimArgumentMismatch);
            }
            let content_hash = match access {
                FileAccess::Read => None,
                FileAccess::Write => Some(hash_required_string(object, "content")?),
            };
            Ok(SafeArgumentView::File {
                path: path.clone(),
                content_hash,
            })
        }
        ResourceClaim::Email { recipients, .. } => {
            let submitted = object
                .get("to")
                .ok_or(SafeArgumentProjectionError::ClaimArgumentMismatch)
                .and_then(|value| {
                    canonicalize_email_recipients(value)
                        .map_err(|_| SafeArgumentProjectionError::ClaimArgumentMismatch)
                })?;
            if &submitted != recipients {
                return Err(SafeArgumentProjectionError::ClaimArgumentMismatch);
            }
            Ok(SafeArgumentView::Email {
                recipients: recipients.clone(),
                subject_hash: hash_optional_string(object, "subject")?,
                body_hash: hash_optional_string(object, "body")?,
            })
        }
        ResourceClaim::Network { method, origin, .. } => {
            let submitted_origin = canonicalize_http_origin(required_string(object, "url")?)
                .map_err(|_| SafeArgumentProjectionError::ClaimArgumentMismatch)?;
            let submitted_method = match object.get("method") {
                Some(Value::String(value)) => canonicalize_http_method(value)
                    .map_err(|_| SafeArgumentProjectionError::ClaimArgumentMismatch)?,
                None if method == "GET" => "GET".to_owned(),
                _ => return Err(SafeArgumentProjectionError::ClaimArgumentMismatch),
            };
            if &submitted_origin != origin || &submitted_method != method {
                return Err(SafeArgumentProjectionError::ClaimArgumentMismatch);
            }
            Ok(SafeArgumentView::Network {
                method: method.clone(),
                origin: origin.clone(),
                body_hash: optional_string_hash(object, "body")?,
            })
        }
        ResourceClaim::Memory {
            namespace,
            key,
            access,
        } => {
            let submitted_key = required_string(object, "key")?;
            if submitted_key != key {
                return Err(SafeArgumentProjectionError::ClaimArgumentMismatch);
            }
            let value_hash = match access {
                MemoryAccess::Read => None,
                MemoryAccess::Write => Some(hash_required_string(object, "value")?),
            };
            Ok(SafeArgumentView::Store {
                namespace: namespace.clone(),
                key_hash: Sha256Digest::from_bytes(key.as_bytes()),
                value_hash,
            })
        }
        ResourceClaim::InputInspection {
            source,
            content_hash,
            ..
        } => {
            let submitted_hash = hash_required_string(object, "input_text")?;
            if &submitted_hash != content_hash || source != "tool_input" {
                return Err(SafeArgumentProjectionError::ClaimArgumentMismatch);
            }
            Ok(SafeArgumentView::Input {
                source: source.clone(),
                content_hash: content_hash.clone(),
            })
        }
        ResourceClaim::CodeExecution { runtime, .. } => {
            let script_hash = hash_required_string(object, "source")?;
            Ok(SafeArgumentView::Code {
                runtime: runtime.clone(),
                script_hash,
            })
        }
        ResourceClaim::Evidence {
            story_id,
            operation_id,
        } => Ok(SafeArgumentView::Evidence {
            story_id: *story_id,
            operation_id: *operation_id,
        }),
        ResourceClaim::Artifact {
            relative_path,
            format,
        } => Ok(SafeArgumentView::Artifact {
            relative_path: relative_path.clone(),
            format: format.clone(),
        }),
        ResourceClaim::OpaqueLegacy { .. } => Err(SafeArgumentProjectionError::OpaqueLegacy),
    }
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, SafeArgumentProjectionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(SafeArgumentProjectionError::ClaimArgumentMismatch)
}

fn hash_required_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Sha256Digest, SafeArgumentProjectionError> {
    Ok(Sha256Digest::from_bytes(
        required_string(object, field)?.as_bytes(),
    ))
}

fn hash_optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Sha256Digest, SafeArgumentProjectionError> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(Sha256Digest::from_bytes(value.as_bytes())),
        None => Ok(Sha256Digest::from_bytes(b"")),
        Some(_) => Err(SafeArgumentProjectionError::ClaimArgumentMismatch),
    }
}

fn optional_string_hash(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<Sha256Digest>, SafeArgumentProjectionError> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(Some(Sha256Digest::from_bytes(value.as_bytes()))),
        None => Ok(None),
        Some(_) => Err(SafeArgumentProjectionError::ClaimArgumentMismatch),
    }
}
