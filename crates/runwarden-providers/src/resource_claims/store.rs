use runwarden_kernel::KernelProvider;
use runwarden_kernel::resource::{MemoryAccess, ResourceClaim};
use serde_json::Value;

use super::{
    ResourceExtractionContext, ResourceExtractionError, ResourceExtractor, required_string,
    validate_context_value, validated_object,
};

enum StoreKind {
    Memory,
    Knowledge,
}

pub(super) struct StoreExtractor {
    kind: StoreKind,
    action: &'static str,
    access: MemoryAccess,
}

impl StoreExtractor {
    pub(super) fn memory_read() -> Self {
        Self::new(StoreKind::Memory, "read", MemoryAccess::Read)
    }

    pub(super) fn memory_write() -> Self {
        Self::new(StoreKind::Memory, "write", MemoryAccess::Write)
    }

    pub(super) fn knowledge_read() -> Self {
        Self::new(StoreKind::Knowledge, "read", MemoryAccess::Read)
    }

    pub(super) fn knowledge_write() -> Self {
        Self::new(StoreKind::Knowledge, "write", MemoryAccess::Write)
    }

    fn new(kind: StoreKind, action: &'static str, access: MemoryAccess) -> Self {
        Self {
            kind,
            action,
            access,
        }
    }
}

impl ResourceExtractor for StoreExtractor {
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
        let object = if self.access == MemoryAccess::Write {
            validated_object(arguments, &["key", "value"], &["key", "value"])?
        } else {
            validated_object(arguments, &["key"], &["key"])?
        };
        let key = required_string(object, "key")?;
        if key.is_empty() || key.trim() != key || key.chars().any(char::is_control) {
            return Err(ResourceExtractionError::InvalidStoreKey);
        }
        let namespace = match self.kind {
            StoreKind::Memory => &context.memory_namespace,
            StoreKind::Knowledge => &context.knowledge_namespace,
        };
        validate_context_value(namespace, "namespace")?;
        Ok(ResourceClaim::Memory {
            namespace: namespace.clone(),
            key: key.to_owned(),
            access: self.access,
        })
    }
}
