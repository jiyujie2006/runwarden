use runwarden_kernel::KernelProvider;
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::resource::{FileAccess, ResourceClaim};
use serde_json::Value;

use super::{
    ResourceExtractionContext, ResourceExtractionError, ResourceExtractor, required_string,
    validate_context_value, validated_object,
};

pub(super) struct FileExtractor {
    action: &'static str,
    access: FileAccess,
    write: bool,
}

impl FileExtractor {
    pub(super) fn read() -> Self {
        Self {
            action: "read_file",
            access: FileAccess::Read,
            write: false,
        }
    }

    pub(super) fn write() -> Self {
        Self {
            action: "write_file",
            access: FileAccess::Write,
            write: true,
        }
    }
}

impl ResourceExtractor for FileExtractor {
    fn extract(
        &self,
        _provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError> {
        if action != self.action {
            return Err(ResourceExtractionError::UnsupportedAction);
        }
        validate_context_value(&context.filesystem_root, "filesystem_root")?;
        let object = if self.write {
            validated_object(arguments, &["path", "content"], &["path", "content"])?
        } else {
            validated_object(arguments, &["path"], &["path"])?
        };
        if self.write {
            required_string(object, "content")?;
        }
        let path = canonicalize_path(required_string(object, "path")?)?;
        Ok(ResourceClaim::File {
            root: context.filesystem_root.clone(),
            path,
            access: self.access,
            classification: context.default_classification,
        })
    }
}

pub fn canonicalize_path(value: &str) -> Result<WorkspaceRelativePath, ResourceExtractionError> {
    if value.is_empty() || value.starts_with('/') || value.ends_with('/') {
        return Err(ResourceExtractionError::InvalidPath);
    }
    let mut components = Vec::new();
    for component in value.split('/') {
        match component {
            "" | ".." => return Err(ResourceExtractionError::InvalidPath),
            "." => {}
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Err(ResourceExtractionError::InvalidPath);
    }
    WorkspaceRelativePath::try_from(components.join("/"))
        .map_err(|_| ResourceExtractionError::InvalidPath)
}
