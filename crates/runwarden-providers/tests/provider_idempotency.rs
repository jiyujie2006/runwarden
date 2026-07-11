use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration as StdDuration;

use runwarden_kernel::KernelProvider;
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::{ProviderExecutionStatus, SafeProviderOutput, SideEffectState};
use runwarden_kernel::resource::{DataClass, FileAccess, ResourceClaim};
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ExecutionLeaseId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::catalog::full_provider_registry;
use runwarden_providers::executor::{
    CleanupDisposition, CleanupError, DefaultProviderExecutor, ExecutionPermit, ExecutorConfig,
    PermitAuthority, PermitClaims, PermitIssuer, PermitVerifier, ProviderExecutionRequest,
    ProviderExecutor, ReconciliationResult, canonical_argument_hash,
    canonical_provider_contract_hash,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

const RECIPIENT: &str = "finance@example.test";
const SUBJECT: &str = "Q2 confidential subject";
const BODY: &str = "Quarterly confidential body";

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
}

fn email_provider() -> KernelProvider {
    full_provider_registry()
        .get("external.email.send")
        .expect("email provider is registered")
        .clone()
}

fn email_arguments(subject: &str, body: &str) -> Value {
    json!({
        "to": [RECIPIENT],
        "subject": subject,
        "body": body,
    })
}

fn email_request(operation_id: OperationId, arguments: Value) -> ProviderExecutionRequest {
    let provider = email_provider();
    let resource_claim = ResourceClaim::Email {
        recipients: vec![RECIPIENT.to_owned()],
        classification: DataClass::Internal,
    };
    ProviderExecutionRequest {
        operation_id,
        story_id: StoryId::new(),
        session_id: SessionId::new(),
        provider: provider.id.clone(),
        action: "send".to_owned(),
        argument_hash: canonical_argument_hash(&arguments),
        arguments,
        resource_claim_hash: resource_claim.digest(),
        resource_claim,
        policy_snapshot_hash: Sha256Digest::from_bytes(b"idempotency-policy"),
        provider_contract_hash: canonical_provider_contract_hash(&provider).unwrap(),
        budget_charge: BudgetCharge {
            calls: 1,
            file_bytes: 0,
            network_bytes: 256 * 1_024,
        },
    }
}

fn file_write_request(operation_id: OperationId) -> ProviderExecutionRequest {
    let provider = full_provider_registry()
        .get("external.mcp.filesystem.write_file")
        .expect("filesystem provider is registered")
        .clone();
    let arguments = json!({
        "path": "reconcile-must-not-write.txt",
        "content": "must never be written by reconciliation",
    });
    let resource_claim = ResourceClaim::File {
        root: "contest-workspace".to_owned(),
        path: WorkspaceRelativePath::try_from("reconcile-must-not-write.txt".to_owned()).unwrap(),
        access: FileAccess::Write,
        classification: DataClass::Internal,
    };
    ProviderExecutionRequest {
        operation_id,
        story_id: StoryId::new(),
        session_id: SessionId::new(),
        provider: provider.id.clone(),
        action: "write_file".to_owned(),
        argument_hash: canonical_argument_hash(&arguments),
        arguments,
        resource_claim_hash: resource_claim.digest(),
        resource_claim,
        policy_snapshot_hash: Sha256Digest::from_bytes(b"file-reconciliation-policy"),
        provider_contract_hash: canonical_provider_contract_hash(&provider).unwrap(),
        budget_charge: BudgetCharge {
            calls: 1,
            file_bytes: 64 * 1_024,
            network_bytes: 0,
        },
    }
}

fn permit_claims(request: &ProviderExecutionRequest) -> PermitClaims {
    PermitClaims {
        lease_id: ExecutionLeaseId::new(),
        operation_id: request.operation_id,
        story_id: request.story_id,
        session_id: request.session_id,
        provider: request.provider.clone(),
        action: request.action.clone(),
        argument_hash: request.argument_hash.clone(),
        resource_claim_hash: request.resource_claim_hash.clone(),
        policy_snapshot_hash: request.policy_snapshot_hash.clone(),
        provider_contract_hash: request.provider_contract_hash.clone(),
        budget_charge: request.budget_charge,
        expires_at: fixed_now() + Duration::minutes(5),
        execution_started_version: 9,
    }
}

fn seal(issuer: &PermitIssuer, request: &ProviderExecutionRequest) -> ExecutionPermit {
    issuer.seal(permit_claims(request)).unwrap()
}

struct Harness {
    _root: tempfile::TempDir,
    sandbox: PathBuf,
    runtime: PathBuf,
    issuer: PermitIssuer,
    verifier: PermitVerifier,
    executor: DefaultProviderExecutor,
}

impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("executor root");
        let sandbox = root.path().join("sandbox");
        let runtime = root.path().join("runtime");
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        let (issuer, verifier) = PermitAuthority::generate().unwrap();
        let executor = executor(&sandbox, &runtime, verifier.clone());
        Self {
            _root: root,
            sandbox,
            runtime,
            issuer,
            verifier,
            executor,
        }
    }
}

fn executor(sandbox: &Path, runtime: &Path, verifier: PermitVerifier) -> DefaultProviderExecutor {
    let config = ExecutorConfig::new(
        sandbox.to_path_buf(),
        runtime.to_path_buf(),
        64 * 1_024,
        StdDuration::from_secs(2),
        verifier,
    )
    .unwrap();
    DefaultProviderExecutor::new(config)
}

fn receipt_paths(sandbox: &Path) -> Vec<PathBuf> {
    let directory = sandbox.join("mail/receipts");
    let mut paths = fs::read_dir(directory)
        .expect("receipt directory exists after email execution")
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn temp_receipt_paths(sandbox: &Path) -> Vec<PathBuf> {
    let directory = sandbox.join("mail/tmp");
    let mut paths = fs::read_dir(directory)
        .expect("temporary receipt directory exists after email execution")
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn mailbox_view(sandbox: &Path) -> String {
    runwarden_providers::demo_tools::mailbox_view_for_test(sandbox)
        .expect("immutable receipts render a mailbox view")
}

fn assert_email_completed(
    outcome: &runwarden_providers::executor::ProviderExecutionOutcome,
    reserved: BudgetCharge,
) {
    assert_eq!(
        outcome.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert_eq!(
        outcome.result.side_effect_state(),
        SideEffectState::Completed
    );
    assert!(matches!(
        outcome.result.output(),
        SafeProviderOutput::Email { .. }
    ));
    assert!(outcome.result.output_hash().is_some());
    assert!(outcome.result.receipt().is_some());
    outcome.result.validate_against(reserved).unwrap();
}

#[test]
fn same_email_permit_and_operation_returns_one_immutable_receipt() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);

    let first = harness.executor.execute(&permit, &request, fixed_now());
    let second = harness.executor.execute(&permit, &request, fixed_now());

    assert_email_completed(&first, request.budget_charge);
    assert_email_completed(&second, request.budget_charge);
    assert_eq!(first.result.receipt(), second.result.receipt());
    assert_eq!(receipt_paths(&harness.sandbox).len(), 1);
    let mailbox = mailbox_view(&harness.sandbox);
    assert_eq!(mailbox.matches(RECIPIENT).count(), 1);
    assert!(!mailbox.contains(SUBJECT));
    assert!(!mailbox.contains(BODY));
}

#[test]
fn same_operation_with_new_valid_permit_and_changed_arguments_is_an_integrity_conflict() {
    let harness = Harness::new();
    let operation_id = OperationId::new();
    let request = email_request(operation_id, email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let first = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&first, request.budget_charge);
    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let receipt_before = fs::read(&receipt_path).unwrap();

    let changed = ProviderExecutionRequest {
        arguments: email_arguments("changed subject", "changed body"),
        ..request.clone()
    };
    let changed = ProviderExecutionRequest {
        argument_hash: canonical_argument_hash(&changed.arguments),
        ..changed
    };
    let changed_permit = seal(&harness.issuer, &changed);
    let conflict = harness
        .executor
        .execute(&changed_permit, &changed, fixed_now());

    assert_eq!(
        conflict.result.execution_status(),
        ProviderExecutionStatus::NotExecuted
    );
    assert_eq!(
        conflict.result.side_effect_state(),
        SideEffectState::BlockedBeforeExecution
    );
    assert_eq!(conflict.result.error_kind(), Some("integrity_error"));
    assert_eq!(
        conflict.result.reason_code(),
        Some("operation_binding_mismatch")
    );
    assert!(matches!(conflict.result.output(), SafeProviderOutput::None));
    assert!(conflict.result.receipt().is_none());
    assert_eq!(
        conflict.result.actual_budget_charge(),
        BudgetCharge {
            calls: 0,
            file_bytes: 0,
            network_bytes: 0,
        }
    );
    assert_eq!(receipt_paths(&harness.sandbox).len(), 1);
    assert_eq!(fs::read(receipt_path).unwrap(), receipt_before);
    assert_eq!(mailbox_view(&harness.sandbox).matches(RECIPIENT).count(), 1);
}

#[test]
fn sixteen_threads_across_independent_executors_still_create_one_receipt() {
    const THREADS: usize = 16;

    let harness = Harness::new();
    let request = Arc::new(email_request(
        OperationId::new(),
        email_arguments(SUBJECT, BODY),
    ));
    let permit = Arc::new(seal(&harness.issuer, &request));
    let barrier = Arc::new(Barrier::new(THREADS));
    let executors = (0..THREADS)
        .map(|_| {
            Arc::new(executor(
                &harness.sandbox,
                &harness.runtime,
                harness.verifier.clone(),
            ))
        })
        .collect::<Vec<_>>();

    let workers = executors
        .into_iter()
        .map(|executor| {
            let request = Arc::clone(&request);
            let permit = Arc::clone(&permit);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                executor.execute(&permit, &request, fixed_now())
            })
        })
        .collect::<Vec<_>>();

    let mut receipts = Vec::with_capacity(THREADS);
    for worker in workers {
        let outcome = worker.join().expect("email worker does not panic");
        assert_email_completed(&outcome, request.budget_charge);
        receipts.push(outcome.result.receipt().cloned().unwrap());
    }
    assert!(receipts.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(receipt_paths(&harness.sandbox).len(), 1);
    assert_eq!(mailbox_view(&harness.sandbox).matches(RECIPIENT).count(), 1);
}

#[test]
fn tampered_structurally_valid_receipt_fails_closed_as_outcome_unknown() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let first = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&first, request.budget_charge);

    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    let object = receipt
        .as_object_mut()
        .expect("receipt is a canonical JSON object");
    assert!(object.contains_key("subject_hash"));
    object.insert(
        "subject_hash".to_owned(),
        Value::String(
            Sha256Digest::from_bytes(b"tampered subject")
                .as_str()
                .to_owned(),
        ),
    );
    let tampered = serde_json::to_vec(&receipt).unwrap();
    fs::write(&receipt_path, &tampered).unwrap();

    let reconciled = harness.executor.execute(&permit, &request, fixed_now());
    assert_eq!(
        reconciled.result.execution_status(),
        ProviderExecutionStatus::OutcomeUnknown
    );
    assert_eq!(
        reconciled.result.side_effect_state(),
        SideEffectState::OutcomeUnknown
    );
    assert_eq!(
        reconciled.result.error_kind(),
        Some("receipt_integrity_error")
    );
    assert_eq!(
        reconciled.result.reason_code(),
        Some("receipt_integrity_mismatch")
    );
    assert!(matches!(
        reconciled.result.output(),
        SafeProviderOutput::None
    ));
    assert!(reconciled.result.output_hash().is_none());
    assert!(reconciled.result.receipt().is_none());
    assert_eq!(
        reconciled.result.actual_budget_charge(),
        request.budget_charge
    );
    reconciled
        .result
        .validate_against(request.budget_charge)
        .unwrap();
    assert_eq!(receipt_paths(&harness.sandbox).len(), 1);
    assert_eq!(fs::read(receipt_path).unwrap(), tampered);
}

#[test]
fn changing_only_the_receipt_timestamp_still_fails_immutable_verification() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let first = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&first, request.budget_charge);

    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let original_receipt = first.result.receipt().cloned().unwrap();
    let mut receipt: Value = serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt
        .as_object_mut()
        .expect("receipt is a canonical JSON object")
        .insert(
            "recorded_at".to_owned(),
            Value::String("2100-01-01T00:00:00Z".to_owned()),
        );
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    let replayed = harness.executor.execute(&permit, &request, fixed_now());

    assert_eq!(
        replayed.result.execution_status(),
        ProviderExecutionStatus::OutcomeUnknown
    );
    assert_eq!(
        replayed.result.side_effect_state(),
        SideEffectState::OutcomeUnknown
    );
    assert_eq!(
        replayed.result.error_kind(),
        Some("receipt_integrity_error")
    );
    assert_eq!(
        replayed.result.reason_code(),
        Some("receipt_integrity_mismatch")
    );
    assert!(replayed.result.receipt().is_none());
    assert_ne!(replayed.result.receipt(), Some(&original_receipt));
    assert_eq!(
        replayed.result.actual_budget_charge(),
        request.budget_charge
    );
}

#[test]
fn committed_cleanup_removes_only_the_hash_matched_temp_and_preserves_receipt() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let mut outcome = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&outcome, request.budget_charge);
    let receipt = outcome.result.receipt().cloned().unwrap();
    assert_eq!(receipt_paths(&harness.sandbox).len(), 1);
    assert_eq!(temp_receipt_paths(&harness.sandbox).len(), 1);
    let cleanup = outcome
        .cleanup
        .take()
        .expect("the creating execution retains a cleanup capability");

    harness
        .executor
        .finalize_cleanup(cleanup, CleanupDisposition::ResultCommitted)
        .expect("committed result permits hash-matched temp cleanup");

    assert!(temp_receipt_paths(&harness.sandbox).is_empty());
    assert_eq!(receipt_paths(&harness.sandbox).len(), 1);
    let reconciled = match harness.executor.reconcile(&request).result {
        ReconciliationResult::Completed(result) => result,
        ReconciliationResult::NotExecuted => panic!("committed email receipt disappeared"),
        ReconciliationResult::Unknown => panic!("committed email receipt became unverifiable"),
    };
    assert_eq!(reconciled.receipt(), Some(&receipt));
}

#[test]
fn cleanup_refuses_a_replaced_temp_file_and_never_deletes_the_receipt() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let mut outcome = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&outcome, request.budget_charge);
    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let receipt_before = fs::read(&receipt_path).unwrap();
    let temp_path = temp_receipt_paths(&harness.sandbox).pop().unwrap();
    fs::remove_file(&temp_path).unwrap();
    fs::write(&temp_path, &receipt_before).unwrap();
    let cleanup = outcome.cleanup.take().unwrap();

    let error = harness
        .executor
        .finalize_cleanup(cleanup, CleanupDisposition::ResultCommitted)
        .expect_err("same-content replacement is not the authorized hard link");
    assert!(matches!(error, CleanupError::Failed { .. }));
    assert!(temp_path.exists());
    assert_eq!(fs::read(receipt_path).unwrap(), receipt_before);
}

#[test]
fn cleanup_retains_the_temp_if_the_durable_receipt_has_disappeared() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let mut outcome = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&outcome, request.budget_charge);
    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let temp_path = temp_receipt_paths(&harness.sandbox).pop().unwrap();
    let cleanup = outcome.cleanup.take().unwrap();
    fs::remove_file(receipt_path).unwrap();

    let error = harness
        .executor
        .finalize_cleanup(cleanup, CleanupDisposition::ResultCommitted)
        .expect_err("cleanup must retain the last verifiable copy of a missing receipt");

    assert!(matches!(error, CleanupError::Failed { .. }));
    assert!(
        temp_path.exists(),
        "cleanup deleted the last receipt link after the durable receipt disappeared"
    );
    assert!(matches!(
        harness.executor.reconcile(&request).result,
        ReconciliationResult::Unknown
    ));
}

#[test]
fn reconcile_distinguishes_valid_missing_and_tampered_email_receipts() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let executed = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&executed, request.budget_charge);
    let expected_receipt = executed.result.receipt().cloned().unwrap();

    let reconciled = match harness.executor.reconcile(&request).result {
        ReconciliationResult::Completed(result) => result,
        ReconciliationResult::NotExecuted => panic!("valid receipt must reconcile as completed"),
        ReconciliationResult::Unknown => panic!("valid receipt must remain verifiable"),
    };
    assert_eq!(reconciled.receipt(), Some(&expected_receipt));
    assert_eq!(
        reconciled.execution_status(),
        ProviderExecutionStatus::Completed
    );
    let missing = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    assert!(matches!(
        harness.executor.reconcile(&missing).result,
        ReconciliationResult::NotExecuted
    ));

    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    fs::write(receipt_path, b"not a receipt").unwrap();
    assert!(matches!(
        harness.executor.reconcile(&request).result,
        ReconciliationResult::Unknown
    ));
}

#[test]
fn reconciliation_uses_the_frozen_email_binding_and_recovers_cleanup() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let executed = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&executed, request.budget_charge);
    let expected_receipt = executed.result.receipt().cloned().unwrap();
    drop(executed.cleanup);

    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let receipt_before = fs::read(&receipt_path).unwrap();
    let changed = ProviderExecutionRequest {
        arguments: email_arguments(SUBJECT, "substituted recovery body"),
        ..request.clone()
    };
    let changed = ProviderExecutionRequest {
        argument_hash: canonical_argument_hash(&changed.arguments),
        ..changed
    };
    let rejected = harness.executor.reconcile(&changed);
    assert!(matches!(rejected.result, ReconciliationResult::Unknown));
    assert!(rejected.cleanup.is_none());
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt_before);
    assert_eq!(temp_receipt_paths(&harness.sandbox).len(), 1);

    let mut recovered = harness.executor.reconcile(&request);
    let result = match recovered.result {
        ReconciliationResult::Completed(result) => result,
        ReconciliationResult::NotExecuted => panic!("verified receipt was lost"),
        ReconciliationResult::Unknown => panic!("verified receipt did not reconcile"),
    };
    assert_eq!(result.receipt(), Some(&expected_receipt));
    let cleanup = recovered
        .cleanup
        .take()
        .expect("reconciliation rebuilds the opaque cleanup capability");
    harness
        .executor
        .finalize_cleanup(cleanup, CleanupDisposition::ResultCommitted)
        .expect("recovered cleanup capability is hash and hard-link bound");
    assert!(temp_receipt_paths(&harness.sandbox).is_empty());
    assert_eq!(fs::read(receipt_path).unwrap(), receipt_before);
}

#[cfg(unix)]
#[test]
fn reconciliation_rejects_a_same_content_cleanup_file_without_hard_link_identity() {
    let harness = Harness::new();
    let request = email_request(OperationId::new(), email_arguments(SUBJECT, BODY));
    let permit = seal(&harness.issuer, &request);
    let executed = harness.executor.execute(&permit, &request, fixed_now());
    assert_email_completed(&executed, request.budget_charge);
    drop(executed.cleanup);

    let receipt_path = receipt_paths(&harness.sandbox).pop().unwrap();
    let receipt_bytes = fs::read(&receipt_path).unwrap();
    let temp_path = temp_receipt_paths(&harness.sandbox).pop().unwrap();
    fs::remove_file(&temp_path).unwrap();
    fs::write(&temp_path, &receipt_bytes).unwrap();

    let reconciled = harness.executor.reconcile(&request);

    assert!(matches!(reconciled.result, ReconciliationResult::Unknown));
    assert!(reconciled.cleanup.is_none());
    assert_eq!(fs::read(&receipt_path).unwrap(), receipt_bytes);
    assert_eq!(fs::read(&temp_path).unwrap(), receipt_bytes);
}

#[test]
fn non_email_reconciliation_without_durable_evidence_is_unknown_and_read_only() {
    let harness = Harness::new();
    let request = file_write_request(OperationId::new());

    let reconciled = harness.executor.reconcile(&request);

    assert!(matches!(reconciled.result, ReconciliationResult::Unknown));
    assert!(reconciled.cleanup.is_none());
    assert!(
        !harness
            .sandbox
            .join("reconcile-must-not-write.txt")
            .exists(),
        "reconciliation dispatched a filesystem business side effect"
    );
    assert_eq!(
        fs::read_dir(&harness.sandbox).unwrap().count(),
        0,
        "reconciliation must not create provider backing material"
    );
}
