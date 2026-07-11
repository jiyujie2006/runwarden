use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::SafeProviderOutput;
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::story::OperationId;
use runwarden_kernel::trace::{Sha256Digest, canonical_json_v1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::{
    ToolCleanup, ToolError, ToolExecution, ToolReceipt, canonical_sandbox_root,
    ensure_private_directory, one_call_charge, random_suffix, sync_directory,
    validate_regular_file,
};
use crate::resource_claims::canonicalize_email_recipients;

const RECEIPT_SCHEMA_VERSION: &str = "1";
const MAILBOX_READ_LIMIT: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailReceiptRecord {
    schema_version: String,
    operation_id: OperationId,
    argument_hash: Sha256Digest,
    recipients: Vec<String>,
    subject_hash: Sha256Digest,
    body_hash: Sha256Digest,
    #[serde(with = "time::serde::rfc3339")]
    recorded_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImmutableEmailBinding {
    operation_id: OperationId,
    argument_hash: Sha256Digest,
    recipients: Vec<String>,
    subject_hash: Sha256Digest,
    body_hash: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum EmailReconciliation {
    Completed(Box<ToolExecution>),
    NotFound,
}

pub(crate) fn send_email(
    sandbox_root: &Path,
    operation_id: OperationId,
    argument_hash: &Sha256Digest,
    arguments: &Value,
    claim: &ResourceClaim,
    recorded_at: OffsetDateTime,
    max_receipt_bytes: usize,
) -> Result<ToolExecution, ToolError> {
    if max_receipt_bytes == 0 {
        return Err(ToolError::InvalidRequest);
    }
    let binding = email_binding(operation_id, argument_hash, arguments, claim)?;

    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let receipts_relative = relative("mail/receipts")?;
    let temp_relative = relative("mail/tmp")?;
    let receipts_directory = ensure_private_directory(&canonical_root, &receipts_relative)?;
    let temp_directory = ensure_private_directory(&canonical_root, &temp_relative)?;
    let final_relative = relative(&format!("mail/receipts/{}.json", binding.operation_id))?;
    let final_path = receipts_directory.join(format!("{}.json", binding.operation_id));

    if final_path.exists() {
        let (stored, bytes) = read_receipt(
            &canonical_root,
            &final_path,
            binding.operation_id,
            max_receipt_bytes,
        )?;
        verify_immutable_binding(&stored, &binding)?;
        return Ok(completed_email(
            binding.operation_id,
            final_relative,
            &bytes,
            None,
        ));
    }

    let record = EmailReceiptRecord {
        schema_version: RECEIPT_SCHEMA_VERSION.to_owned(),
        operation_id: binding.operation_id,
        argument_hash: binding.argument_hash.clone(),
        recipients: binding.recipients.clone(),
        subject_hash: binding.subject_hash.clone(),
        body_hash: binding.body_hash.clone(),
        recorded_at,
    };
    let value = serde_json::to_value(&record).map_err(|_| ToolError::InvalidRequest)?;
    let bytes = canonical_json_v1(&value);
    if bytes.len() > max_receipt_bytes {
        return Err(ToolError::LimitExceeded);
    }

    let temp_name = format!("{}-{}.json.tmp", binding.operation_id, random_suffix()?);
    let temp_relative_path = relative(&format!("mail/tmp/{temp_name}"))?;
    let temp_path = temp_directory.join(&temp_name);
    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|_| ToolError::IoBeforeSideEffect)?;
    if let Err(error) = temp_file
        .write_all(&bytes)
        .and_then(|()| temp_file.sync_all())
    {
        let _ = fs::remove_file(&temp_path);
        let _ = error;
        return Err(ToolError::IoBeforeSideEffect);
    }
    drop(temp_file);

    let temp_hash = Sha256Digest::from_bytes(&bytes);
    let cleanup = ToolCleanup {
        relative_path: temp_relative_path,
        sha256: temp_hash.clone(),
    };
    match fs::hard_link(&temp_path, &final_path) {
        Ok(()) => {
            if sync_directory(&receipts_directory).is_err()
                || sync_directory(&temp_directory).is_err()
            {
                let _ = fs::remove_file(&temp_path);
                let _ = sync_directory(&temp_directory);
                return Err(ToolError::OutcomeUnknown);
            }
            Ok(completed_email(
                binding.operation_id,
                final_relative,
                &bytes,
                Some(cleanup),
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let stored = read_receipt(
                &canonical_root,
                &final_path,
                binding.operation_id,
                max_receipt_bytes,
            );
            let (stored, stored_bytes) = match stored {
                Ok(stored) => stored,
                Err(error) => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(error);
                }
            };
            if let Err(error) = verify_immutable_binding(&stored, &binding) {
                let _ = fs::remove_file(&temp_path);
                return Err(error);
            }
            Ok(completed_email(
                binding.operation_id,
                final_relative,
                &stored_bytes,
                Some(cleanup),
            ))
        }
        Err(_) => {
            let _ = fs::remove_file(&temp_path);
            Err(ToolError::IoBeforeSideEffect)
        }
    }
}

fn email_binding(
    operation_id: OperationId,
    argument_hash: &Sha256Digest,
    arguments: &Value,
    claim: &ResourceClaim,
) -> Result<ImmutableEmailBinding, ToolError> {
    if *argument_hash != Sha256Digest::from_bytes(&canonical_json_v1(arguments)) {
        return Err(ToolError::InvalidRequest);
    }
    let ResourceClaim::Email {
        recipients: claim_recipients,
        ..
    } = claim
    else {
        return Err(ToolError::ClaimMismatch);
    };
    let recipients =
        canonicalize_email_recipients(arguments.get("to").ok_or(ToolError::InvalidRequest)?)
            .map_err(|_| ToolError::InvalidRequest)?;
    if recipients != *claim_recipients {
        return Err(ToolError::ClaimMismatch);
    }
    let subject = optional_string(arguments, "subject")?;
    let body = optional_string(arguments, "body")?;
    Ok(ImmutableEmailBinding {
        operation_id,
        argument_hash: argument_hash.clone(),
        recipients,
        subject_hash: Sha256Digest::from_bytes(subject.as_bytes()),
        body_hash: Sha256Digest::from_bytes(body.as_bytes()),
    })
}

pub(crate) fn reconcile_email(
    sandbox_root: &Path,
    operation_id: OperationId,
    max_receipt_bytes: usize,
) -> Result<EmailReconciliation, ToolError> {
    if max_receipt_bytes == 0 {
        return Err(ToolError::LimitExceeded);
    }
    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let relative_path = relative(&format!("mail/receipts/{operation_id}.json"))?;
    let receipt_path = canonical_root.join(relative_path.as_str());
    match fs::symlink_metadata(&receipt_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(EmailReconciliation::NotFound);
        }
        Err(_) => return Err(ToolError::ReceiptIntegrity),
        Ok(_) => {}
    }
    let (_, bytes) = read_receipt(
        &canonical_root,
        &receipt_path,
        operation_id,
        max_receipt_bytes,
    )?;
    Ok(EmailReconciliation::Completed(Box::new(completed_email(
        operation_id,
        relative_path,
        &bytes,
        None,
    ))))
}

pub(crate) fn verify_email(
    sandbox_root: &Path,
    operation_id: OperationId,
    argument_hash: &Sha256Digest,
    arguments: &Value,
    claim: &ResourceClaim,
    max_receipt_bytes: usize,
) -> Result<EmailReconciliation, ToolError> {
    if max_receipt_bytes == 0 {
        return Err(ToolError::LimitExceeded);
    }
    let binding = email_binding(operation_id, argument_hash, arguments, claim)?;
    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let relative_path = relative(&format!("mail/receipts/{operation_id}.json"))?;
    let receipt_path = canonical_root.join(relative_path.as_str());
    match fs::symlink_metadata(&receipt_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(EmailReconciliation::NotFound);
        }
        Err(_) => return Err(ToolError::ReceiptIntegrity),
        Ok(_) => {}
    }
    let (stored, bytes) = read_receipt(
        &canonical_root,
        &receipt_path,
        operation_id,
        max_receipt_bytes,
    )?;
    verify_immutable_binding(&stored, &binding)?;
    Ok(EmailReconciliation::Completed(Box::new(completed_email(
        operation_id,
        relative_path,
        &bytes,
        None,
    ))))
}

pub(crate) fn finalize_email_cleanup(
    sandbox_root: &Path,
    operation_id: OperationId,
    relative_path: &WorkspaceRelativePath,
    expected_hash: &Sha256Digest,
    max_receipt_bytes: usize,
) -> Result<(), ToolError> {
    let prefix = format!("mail/tmp/{operation_id}-");
    let path = relative_path.as_str();
    let Some(random) = path
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(".json.tmp"))
    else {
        return Err(ToolError::Integrity);
    };
    if random.len() != 32
        || !random
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ToolError::Integrity);
    }

    let canonical_root = canonical_sandbox_root(sandbox_root)?;
    let cleanup_path = canonical_root.join(path);
    validate_regular_file(&canonical_root, &cleanup_path, true)
        .map_err(|_| ToolError::Integrity)?;
    let bytes = read_bounded(&cleanup_path, max_receipt_bytes).map_err(|_| ToolError::Integrity)?;
    if Sha256Digest::from_bytes(&bytes) != *expected_hash {
        return Err(ToolError::Integrity);
    }
    let receipt_path = canonical_root.join(format!("mail/receipts/{operation_id}.json"));
    validate_regular_file(&canonical_root, &receipt_path, true)
        .map_err(|_| ToolError::Integrity)?;
    let receipt_bytes =
        read_bounded(&receipt_path, max_receipt_bytes).map_err(|_| ToolError::Integrity)?;
    if Sha256Digest::from_bytes(&receipt_bytes) != *expected_hash {
        return Err(ToolError::Integrity);
    }
    fs::remove_file(&cleanup_path).map_err(|_| ToolError::Integrity)?;
    let temp_directory = cleanup_path.parent().ok_or(ToolError::Integrity)?;
    sync_directory(temp_directory)
}

/// Safe read-only test view derived solely from immutable receipt files.
/// Subject and body plaintext are never stored or rendered.
pub fn mailbox_view_for_test(sandbox_root: &Path) -> io::Result<String> {
    let canonical_root = sandbox_root.canonicalize()?;
    let receipts = canonical_root.join("mail/receipts");
    if !receipts.exists() {
        return Ok(String::new());
    }
    let metadata = fs::symlink_metadata(&receipts)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_mailbox());
    }
    let canonical_receipts = receipts.canonicalize()?;
    if !canonical_receipts.starts_with(&canonical_root) {
        return Err(invalid_mailbox());
    }

    let mut entries = fs::read_dir(&canonical_receipts)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let mut rendered = String::new();
    for entry in entries {
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_mailbox())?;
        let expected_operation = file_name
            .strip_suffix(".json")
            .ok_or_else(invalid_mailbox)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAILBOX_READ_LIMIT as u64
        {
            return Err(invalid_mailbox());
        }
        let bytes = read_bounded(&entry.path(), MAILBOX_READ_LIMIT)?;
        let record: EmailReceiptRecord =
            serde_json::from_slice(&bytes).map_err(|_| invalid_mailbox())?;
        let canonical = serde_json::to_value(&record)
            .map(|value| canonical_json_v1(&value))
            .map_err(|_| invalid_mailbox())?;
        if bytes != canonical
            || record.schema_version != RECEIPT_SCHEMA_VERSION
            || record.operation_id.to_string() != expected_operation
        {
            return Err(invalid_mailbox());
        }
        let recipients_value =
            serde_json::to_value(&record.recipients).map_err(|_| invalid_mailbox())?;
        let recipients =
            canonicalize_email_recipients(&recipients_value).map_err(|_| invalid_mailbox())?;
        if recipients != record.recipients {
            return Err(invalid_mailbox());
        }
        let view = serde_json::json!({
            "operation_id": record.operation_id,
            "argument_hash": record.argument_hash,
            "recipients": record.recipients,
            "subject_hash": record.subject_hash,
            "body_hash": record.body_hash,
            "recorded_at": record.recorded_at,
        });
        let line = serde_json::to_string(&view).map_err(|_| invalid_mailbox())?;
        rendered.push_str(&line);
        rendered.push('\n');
    }
    Ok(rendered)
}

fn completed_email(
    operation_id: OperationId,
    relative_path: WorkspaceRelativePath,
    bytes: &[u8],
    cleanup: Option<ToolCleanup>,
) -> ToolExecution {
    let receipt_hash = Sha256Digest::from_bytes(bytes);
    let receipt = ToolReceipt {
        operation_id,
        kind: "email_receipt".to_owned(),
        relative_path,
        sha256: receipt_hash.clone(),
    };
    let execution = ToolExecution::completed(
        SafeProviderOutput::Email { receipt_hash },
        one_call_charge(0, 0),
    )
    .with_receipt(receipt);
    match cleanup {
        Some(cleanup) => execution.with_cleanup(cleanup),
        None => execution,
    }
}

fn verify_immutable_binding(
    stored: &EmailReceiptRecord,
    expected: &ImmutableEmailBinding,
) -> Result<(), ToolError> {
    if stored.argument_hash != expected.argument_hash {
        return Err(ToolError::BindingConflict);
    }
    if stored.operation_id != expected.operation_id
        || stored.recipients != expected.recipients
        || stored.subject_hash != expected.subject_hash
        || stored.body_hash != expected.body_hash
    {
        return Err(ToolError::ReceiptIntegrity);
    }
    Ok(())
}

fn read_receipt(
    root: &Path,
    path: &Path,
    expected_operation_id: OperationId,
    max_bytes: usize,
) -> Result<(EmailReceiptRecord, Vec<u8>), ToolError> {
    validate_regular_file(root, path, true).map_err(|_| ToolError::ReceiptIntegrity)?;
    let bytes = read_bounded(path, max_bytes).map_err(|_| ToolError::ReceiptIntegrity)?;
    let record: EmailReceiptRecord =
        serde_json::from_slice(&bytes).map_err(|_| ToolError::ReceiptIntegrity)?;
    let canonical = serde_json::to_value(&record)
        .map(|value| canonical_json_v1(&value))
        .map_err(|_| ToolError::ReceiptIntegrity)?;
    if bytes != canonical
        || record.schema_version != RECEIPT_SCHEMA_VERSION
        || record.operation_id != expected_operation_id
    {
        return Err(ToolError::ReceiptIntegrity);
    }
    let recipients_value =
        serde_json::to_value(&record.recipients).map_err(|_| ToolError::ReceiptIntegrity)?;
    let canonical_recipients = canonicalize_email_recipients(&recipients_value)
        .map_err(|_| ToolError::ReceiptIntegrity)?;
    if canonical_recipients != record.recipients {
        return Err(ToolError::ReceiptIntegrity);
    }
    Ok((record, bytes))
}

fn read_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)
        .map_err(|_| invalid_mailbox())?
        .checked_add(1)
        .ok_or_else(invalid_mailbox)?;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(invalid_mailbox());
    }
    Ok(bytes)
}

fn optional_string<'a>(arguments: &'a Value, field: &str) -> Result<&'a str, ToolError> {
    match arguments.get(field) {
        Some(value) => value.as_str().ok_or(ToolError::InvalidRequest),
        None => Ok(""),
    }
}

fn relative(value: &str) -> Result<WorkspaceRelativePath, ToolError> {
    WorkspaceRelativePath::try_from(value.to_owned()).map_err(|_| ToolError::InvalidRequest)
}

fn invalid_mailbox() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "mailbox receipt is invalid")
}
