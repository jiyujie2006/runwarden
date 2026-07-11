use runwarden_kernel::KernelProvider;
use runwarden_kernel::resource::ResourceClaim;
use serde_json::Value;
use url::Url;

use super::{
    ResourceExtractionContext, ResourceExtractionError, ResourceExtractor, required_string,
    validated_object,
};

enum NetworkKind {
    Api,
    Browser,
}

pub(super) struct NetworkExtractor {
    kind: NetworkKind,
}

impl NetworkExtractor {
    pub(super) fn api() -> Self {
        Self {
            kind: NetworkKind::Api,
        }
    }

    pub(super) fn browser() -> Self {
        Self {
            kind: NetworkKind::Browser,
        }
    }
}

impl ResourceExtractor for NetworkExtractor {
    fn extract(
        &self,
        _provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError> {
        let (method, object) = match self.kind {
            NetworkKind::Api => {
                if action != "request" {
                    return Err(ResourceExtractionError::UnsupportedAction);
                }
                let object =
                    validated_object(arguments, &["method", "url", "body"], &["method", "url"])?;
                (
                    canonicalize_method(required_string(object, "method")?)?,
                    object,
                )
            }
            NetworkKind::Browser => {
                if action != "open_page" {
                    return Err(ResourceExtractionError::UnsupportedAction);
                }
                (
                    "GET".to_owned(),
                    validated_object(arguments, &["url"], &["url"])?,
                )
            }
        };
        let origin = canonicalize_origin(required_string(object, "url")?)?;
        Ok(ResourceClaim::Network {
            method,
            origin,
            classification: context.default_classification,
        })
    }
}

pub fn canonicalize_method(value: &str) -> Result<String, ResourceExtractionError> {
    if value.is_empty()
        || value.len() > 32
        || !value.is_ascii()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(ResourceExtractionError::InvalidHttpMethod);
    }
    Ok(value.to_ascii_uppercase())
}

pub fn canonicalize_origin(value: &str) -> Result<String, ResourceExtractionError> {
    let url = Url::parse(value).map_err(|_| ResourceExtractionError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ResourceExtractionError::InvalidUrl);
    }
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(ResourceExtractionError::InvalidUrl);
    }
    Ok(origin)
}
