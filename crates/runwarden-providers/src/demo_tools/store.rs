use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::SafeProviderOutput;
use runwarden_kernel::resource::{MemoryAccess, ResourceClaim};
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ToolError, ToolExecution, canonical_sandbox_root, ensure_private_directory, one_call_charge,
    random_suffix, sync_directory, validate_regular_file,
};

const STORE_SCHEMA_VERSION: &str = "1";
static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreClass {
    Memory,
    Knowledge,
}

impl StoreClass {
    fn directory(self) -> &'static str {
        match self {
            Self::Memory => "stores/memory",
            Self::Knowledge => "stores/knowledge",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreRecord {
    schema_version: String,
    namespace_hash: Sha256Digest,
    version: u64,
    entries: BTreeMap<String, Value>,
}

pub(crate) fn read_store(
    sandbox_root: &Path,
    class: StoreClass,
    arguments: &Value,
    claim: &ResourceClaim,
    max_store_bytes: u64,
) -> Result<ToolExecution, ToolError> {
    let (namespace, key) = store_claim(claim, MemoryAccess::Read, arguments)?;
    if max_store_bytes == 0 {
        return Err(ToolError::LimitExceeded);
    }
    let _guard = STORE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| ToolError::LockUnavailable)?;
    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let directory = ensure_private_directory(&canonical_root, &relative(class.directory())?)?;
    let namespace_hash = Sha256Digest::from_bytes(namespace.as_bytes());
    let store_path = store_path(&directory, &namespace_hash);
    let (record, bytes_read) = load_store(
        &canonical_root,
        &store_path,
        &namespace_hash,
        max_store_bytes,
    )?;
    let _value = record.entries.get(key);

    Ok(ToolExecution::completed(
        SafeProviderOutput::Store {
            key_hash: Sha256Digest::from_bytes(key.as_bytes()),
            version: record.version,
        },
        one_call_charge(bytes_read, 0),
    ))
}

pub(crate) fn write_store(
    sandbox_root: &Path,
    class: StoreClass,
    arguments: &Value,
    claim: &ResourceClaim,
    max_store_bytes: u64,
) -> Result<ToolExecution, ToolError> {
    let (namespace, key) = store_claim(claim, MemoryAccess::Write, arguments)?;
    let value = arguments
        .get("value")
        .cloned()
        .ok_or(ToolError::InvalidRequest)?;
    if max_store_bytes == 0 {
        return Err(ToolError::LimitExceeded);
    }
    let _guard = STORE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| ToolError::LockUnavailable)?;
    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let directory = ensure_private_directory(&canonical_root, &relative(class.directory())?)?;
    let namespace_hash = Sha256Digest::from_bytes(namespace.as_bytes());
    let store_path = store_path(&directory, &namespace_hash);
    let (mut record, _) = load_store(
        &canonical_root,
        &store_path,
        &namespace_hash,
        max_store_bytes,
    )?;
    record.entries.insert(key.to_owned(), value);
    record.version = record
        .version
        .checked_add(1)
        .ok_or(ToolError::LimitExceeded)?;
    let encoded = serde_json::to_value(&record)
        .map(|value| canonical_json_v1(&value))
        .map_err(|_| ToolError::Integrity)?;
    let encoded_length = u64::try_from(encoded.len()).map_err(|_| ToolError::LimitExceeded)?;
    if encoded_length > max_store_bytes {
        return Err(ToolError::LimitExceeded);
    }

    let temp = directory.join(format!(".store-{}.tmp", random_suffix()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|_| ToolError::IoBeforeSideEffect)?;
    if file
        .write_all(&encoded)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&temp);
        return Err(ToolError::IoBeforeSideEffect);
    }
    drop(file);
    if fs::symlink_metadata(&store_path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        let _ = fs::remove_file(&temp);
        return Err(ToolError::SymlinkDenied);
    }
    if fs::rename(&temp, &store_path).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(ToolError::IoBeforeSideEffect);
    }
    if validate_regular_file(&canonical_root, &store_path, true).is_err() {
        return Err(ToolError::OutcomeUnknown);
    }
    sync_directory(&directory)?;

    Ok(ToolExecution::completed(
        SafeProviderOutput::Store {
            key_hash: Sha256Digest::from_bytes(key.as_bytes()),
            version: record.version,
        },
        one_call_charge(encoded_length, 0),
    ))
}

fn store_claim<'a>(
    claim: &'a ResourceClaim,
    expected_access: MemoryAccess,
    arguments: &'a Value,
) -> Result<(&'a str, &'a str), ToolError> {
    let ResourceClaim::Memory {
        namespace,
        key,
        access,
    } = claim
    else {
        return Err(ToolError::ClaimMismatch);
    };
    let argument_key = arguments
        .get("key")
        .and_then(Value::as_str)
        .ok_or(ToolError::InvalidRequest)?;
    if namespace.is_empty() || key.is_empty() || *access != expected_access || argument_key != key {
        return Err(ToolError::ClaimMismatch);
    }
    Ok((namespace, key))
}

fn load_store(
    root: &Path,
    path: &Path,
    namespace_hash: &Sha256Digest,
    max_bytes: u64,
) -> Result<(StoreRecord, u64), ToolError> {
    if validate_regular_file(root, path, false)?.is_none() {
        return Ok((
            StoreRecord {
                schema_version: STORE_SCHEMA_VERSION.to_owned(),
                namespace_hash: namespace_hash.clone(),
                version: 0,
                entries: BTreeMap::new(),
            },
            0,
        ));
    }
    let mut file = fs::File::open(path).map_err(|_| ToolError::IoBeforeSideEffect)?;
    let limit = max_bytes.checked_add(1).ok_or(ToolError::LimitExceeded)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ToolError::ExecutedWithError)?;
    if bytes.len() as u128 > max_bytes as u128 {
        return Err(ToolError::LimitExceeded);
    }
    let record: StoreRecord = serde_json::from_slice(&bytes).map_err(|_| ToolError::Integrity)?;
    let canonical = serde_json::to_value(&record)
        .map(|value| canonical_json_v1(&value))
        .map_err(|_| ToolError::Integrity)?;
    if bytes != canonical
        || record.schema_version != STORE_SCHEMA_VERSION
        || record.namespace_hash != *namespace_hash
    {
        return Err(ToolError::Integrity);
    }
    let bytes_read = u64::try_from(bytes.len()).map_err(|_| ToolError::LimitExceeded)?;
    Ok((record, bytes_read))
}

fn store_path(directory: &Path, namespace_hash: &Sha256Digest) -> PathBuf {
    let digest = namespace_hash
        .as_str()
        .strip_prefix("sha256:")
        .expect("typed SHA-256 digest always has its prefix");
    directory.join(format!("{digest}.json"))
}

fn relative(value: &str) -> Result<WorkspaceRelativePath, ToolError> {
    WorkspaceRelativePath::try_from(value.to_owned()).map_err(|_| ToolError::InvalidRequest)
}
