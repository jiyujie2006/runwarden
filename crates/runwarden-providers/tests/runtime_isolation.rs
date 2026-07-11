use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use runwarden_kernel::KernelProvider;
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::{ProviderExecutionStatus, SafeProviderOutput, SideEffectState};
use runwarden_kernel::resource::{DataClass, FileAccess, MemoryAccess, ResourceClaim};
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ExecutionLeaseId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::catalog::full_provider_registry;
use runwarden_providers::executor::{
    DefaultProviderExecutor, ExecutionPermit, ExecutorConfig, ExecutorConfigError, PermitAuthority,
    PermitClaims, PermitIssuer, ProviderExecutionOutcome, ProviderExecutionRequest,
    ProviderExecutor, canonical_argument_hash, canonical_provider_contract_hash,
};
use runwarden_providers::resource_claims::ResourceExtractionContext;
use runwarden_providers::runtime::{
    NetworkPolicy, ProviderRuntime, ProviderRuntimeDenialKind, ProviderRuntimePolicy,
    ProviderRuntimeRequest,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

fn policy() -> ProviderRuntimePolicy {
    ProviderRuntimePolicy::locked_to_root("/srv/runwarden/providers")
}

fn request() -> ProviderRuntimeRequest {
    ProviderRuntimeRequest::new("runwarden-provider")
        .arg("--json")
        .cwd("/srv/runwarden/providers/example")
}

#[test]
fn shell_is_denied_by_default_before_process_spawn() {
    let request = request().use_shell(true);

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("shell is denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::ShellDenied);
    assert!(!denial.side_effect_executed);
}

#[test]
fn cwd_escape_is_denied_before_process_spawn() {
    let request = request().cwd("/srv/runwarden/secrets");

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("cwd escape denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::CwdEscape);
    assert!(!denial.side_effect_executed);
}

#[cfg(unix)]
#[test]
fn cwd_symlink_escape_is_denied_before_process_spawn() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("root");
    let outside = tempfile::tempdir().expect("outside");
    fs::create_dir_all(outside.path().join("provider")).expect("outside provider");
    symlink(outside.path().join("provider"), root.path().join("link")).expect("symlink");

    let policy = ProviderRuntimePolicy::locked_to_root(root.path());
    let request = ProviderRuntimeRequest::new("runwarden-provider").cwd(root.path().join("link"));

    let denial = ProviderRuntime::prepare(&policy, &request).expect_err("cwd escape denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::CwdEscape);
    assert!(!denial.side_effect_executed);
}

#[test]
fn relative_runtime_root_does_not_allow_arbitrary_absolute_cwd() {
    let policy = ProviderRuntimePolicy::locked_to_root(".");
    let request = ProviderRuntimeRequest::new("runwarden-provider").cwd("/tmp");

    let denial = ProviderRuntime::prepare(&policy, &request).expect_err("cwd escape denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::CwdEscape);
    assert!(!denial.side_effect_executed);
}

#[test]
fn parent_environment_inheritance_is_denied_when_scrubbed() {
    let request = request().inherit_parent_env(true);

    let denial =
        ProviderRuntime::prepare(&policy(), &request).expect_err("parent env inheritance denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::EnvInheritanceDenied);
    assert!(!denial.side_effect_executed);
}

#[test]
fn non_allowlisted_environment_variable_is_denied() {
    let request = request().env("AWS_SECRET_ACCESS_KEY", "secret");

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("env denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::EnvNotAllowed);
    assert!(!denial.side_effect_executed);
}

#[test]
fn network_request_is_denied_by_default() {
    let request = request().network_host("example.com");

    let denial = ProviderRuntime::prepare(&policy(), &request).expect_err("network denied");

    assert_eq!(denial.kind, ProviderRuntimeDenialKind::NetworkDenied);
    assert!(!denial.side_effect_executed);
}

#[test]
fn timeout_and_output_caps_are_enforced_before_process_spawn() {
    let timeout_request = request().timeout_ms(60_000);
    let timeout_denial =
        ProviderRuntime::prepare(&policy(), &timeout_request).expect_err("timeout denied");
    assert_eq!(
        timeout_denial.kind,
        ProviderRuntimeDenialKind::TimeoutTooLarge
    );

    let output_request = request().stdout_limit_bytes(2_000_000);
    let output_denial =
        ProviderRuntime::prepare(&policy(), &output_request).expect_err("output cap denied");
    assert_eq!(
        output_denial.kind,
        ProviderRuntimeDenialKind::OutputLimitTooLarge
    );
}

#[test]
fn safe_request_returns_sanitized_launch_plan() {
    let mut policy = policy();
    policy.allow_env("RUNWARDEN_PROVIDER_TOKEN");
    policy.network_policy = NetworkPolicy::AllowHosts(["api.example.com".into()].into());

    let request = request()
        .env("RUNWARDEN_PROVIDER_TOKEN", "redacted")
        .network_host("api.example.com")
        .timeout_ms(1_000)
        .stdout_limit_bytes(4096)
        .stderr_limit_bytes(4096);

    let plan = ProviderRuntime::prepare(&policy, &request).expect("safe request prepares");

    assert_eq!(
        plan.cwd,
        std::path::PathBuf::from("/srv/runwarden/providers/example")
    );
    assert_eq!(
        plan.env.get("RUNWARDEN_PROVIDER_TOKEN").map(String::as_str),
        Some("redacted")
    );
    assert!(plan.kill_process_tree_on_timeout);
    assert!(!plan.side_effect_executed);
}

fn execution_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
}

fn catalog_provider(provider_id: &str) -> KernelProvider {
    full_provider_registry()
        .get(provider_id)
        .unwrap_or_else(|| panic!("provider is missing from the catalog: {provider_id}"))
        .clone()
}

fn mediated_request(
    provider_id: &str,
    action: &str,
    arguments: Value,
    resource_claim: ResourceClaim,
    budget_charge: BudgetCharge,
) -> ProviderExecutionRequest {
    let provider = catalog_provider(provider_id);
    ProviderExecutionRequest {
        operation_id: OperationId::new(),
        story_id: StoryId::new(),
        session_id: SessionId::new(),
        provider: provider.id.clone(),
        action: action.to_owned(),
        argument_hash: canonical_argument_hash(&arguments),
        arguments,
        resource_claim_hash: resource_claim.digest(),
        resource_claim,
        policy_snapshot_hash: Sha256Digest::from_bytes(b"runtime-isolation-policy"),
        provider_contract_hash: canonical_provider_contract_hash(&provider).unwrap(),
        budget_charge,
    }
}

fn execution_permit(issuer: &PermitIssuer, request: &ProviderExecutionRequest) -> ExecutionPermit {
    execution_permit_expiring_at(issuer, request, execution_now() + Duration::minutes(5))
}

fn execution_permit_expiring_at(
    issuer: &PermitIssuer,
    request: &ProviderExecutionRequest,
    expires_at: OffsetDateTime,
) -> ExecutionPermit {
    issuer
        .seal(PermitClaims {
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
            expires_at,
            execution_started_version: 4,
        })
        .unwrap()
}

struct IsolationHarness {
    root: tempfile::TempDir,
    sandbox: PathBuf,
    issuer: PermitIssuer,
    executor: DefaultProviderExecutor,
}

impl IsolationHarness {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("executor root");
        let sandbox = root.path().join("sandbox");
        let runtime = root.path().join("runtime");
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        let (issuer, verifier) = PermitAuthority::generate().unwrap();
        let config = ExecutorConfig::new(
            sandbox.clone(),
            runtime,
            64 * 1_024,
            StdDuration::from_secs(2),
            verifier,
        )
        .unwrap();
        Self {
            root,
            sandbox,
            issuer,
            executor: DefaultProviderExecutor::new(config),
        }
    }
}

fn relative_path(path: &str) -> WorkspaceRelativePath {
    WorkspaceRelativePath::try_from(path.to_owned()).unwrap()
}

fn file_claim(path: &str, access: FileAccess) -> ResourceClaim {
    ResourceClaim::File {
        root: "contest-workspace".to_owned(),
        path: relative_path(path),
        access,
        classification: DataClass::Internal,
    }
}

fn file_budget() -> BudgetCharge {
    BudgetCharge {
        calls: 1,
        file_bytes: 64 * 1_024,
        network_bytes: 0,
    }
}

fn network_budget() -> BudgetCharge {
    BudgetCharge {
        calls: 1,
        file_bytes: 0,
        network_bytes: 64 * 1_024,
    }
}

fn assert_failed_before_effect(outcome: &ProviderExecutionOutcome) {
    assert!(matches!(
        outcome.result.execution_status(),
        ProviderExecutionStatus::NotExecuted | ProviderExecutionStatus::FailedBeforeSideEffect
    ));
    assert!(matches!(
        outcome.result.side_effect_state(),
        SideEffectState::BlockedBeforeExecution | SideEffectState::FailedBeforeSideEffect
    ));
    assert!(!outcome.result.side_effect_state().was_executed());
    assert!(matches!(outcome.result.output(), SafeProviderOutput::None));
    assert!(outcome.result.output_hash().is_none());
    assert!(outcome.result.receipt().is_none());
    assert_eq!(
        outcome.result.actual_budget_charge(),
        BudgetCharge {
            calls: 0,
            file_bytes: 0,
            network_bytes: 0,
        }
    );
}

#[test]
fn default_file_tools_round_trip_and_reject_absolute_or_traversing_arguments() {
    let harness = IsolationHarness::new();
    let write = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"safe/report.txt","content":"bounded report"}),
        file_claim("safe/report.txt", FileAccess::Write),
        file_budget(),
    );
    let write_permit = execution_permit(&harness.issuer, &write);
    let written = harness
        .executor
        .execute(&write_permit, &write, execution_now());
    assert_eq!(
        written.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert_eq!(
        written.result.side_effect_state(),
        SideEffectState::Completed
    );
    assert_eq!(
        fs::read_to_string(harness.sandbox.join("safe/report.txt")).unwrap(),
        "bounded report"
    );
    written
        .result
        .validate_against(write.budget_charge)
        .unwrap();

    let read = mediated_request(
        "external.mcp.filesystem.read_file",
        "read_file",
        json!({"path":"safe/report.txt"}),
        file_claim("safe/report.txt", FileAccess::Read),
        file_budget(),
    );
    let read_permit = execution_permit(&harness.issuer, &read);
    let read_result = harness
        .executor
        .execute(&read_permit, &read, execution_now());
    assert_eq!(
        read_result.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert_eq!(
        read_result.result.side_effect_state(),
        SideEffectState::Completed
    );
    assert!(matches!(
        read_result.result.output(),
        SafeProviderOutput::File { .. }
    ));
    read_result
        .result
        .validate_against(read.budget_charge)
        .unwrap();

    let traversal_target = harness.root.path().join("escaped.txt");
    let traversal = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"../escaped.txt","content":"escape"}),
        file_claim("safe/placeholder.txt", FileAccess::Write),
        file_budget(),
    );
    let traversal_permit = execution_permit(&harness.issuer, &traversal);
    let traversal_result = harness
        .executor
        .execute(&traversal_permit, &traversal, execution_now());
    assert_failed_before_effect(&traversal_result);
    assert!(!traversal_target.exists());

    let outside = tempfile::tempdir().unwrap();
    let absolute_target = outside.path().join("absolute.txt");
    let absolute = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({
            "path": absolute_target.to_string_lossy(),
            "content": "escape"
        }),
        file_claim("safe/placeholder.txt", FileAccess::Write),
        file_budget(),
    );
    let absolute_permit = execution_permit(&harness.issuer, &absolute);
    let absolute_result = harness
        .executor
        .execute(&absolute_permit, &absolute, execution_now());
    assert_failed_before_effect(&absolute_result);
    assert!(!absolute_target.exists());
}

#[test]
fn repeated_store_permit_reuses_the_operation_result_without_a_second_write() {
    let harness = IsolationHarness::new();
    let request = mediated_request(
        "external.memory.write",
        "write",
        json!({"key":"quarter","value":"Q2"}),
        ResourceClaim::Memory {
            namespace: "session-memory".to_owned(),
            key: "quarter".to_owned(),
            access: MemoryAccess::Write,
        },
        file_budget(),
    );
    let permit = execution_permit(&harness.issuer, &request);

    let first = harness.executor.execute(&permit, &request, execution_now());
    let second = harness.executor.execute(&permit, &request, execution_now());
    for outcome in [&first, &second] {
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
            SafeProviderOutput::Store { version: 1, .. }
        ));
        outcome
            .result
            .validate_against(request.budget_charge)
            .unwrap();
    }
    assert_eq!(first.result.output(), second.result.output());

    let store_directory = harness.sandbox.join("stores/memory");
    let store_paths = fs::read_dir(store_directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(store_paths.len(), 1);
    let persisted: Value = serde_json::from_slice(&fs::read(&store_paths[0]).unwrap()).unwrap();
    assert_eq!(persisted.get("version").and_then(Value::as_u64), Some(1));
}

#[test]
fn store_reads_charge_the_persisted_bytes_and_obey_the_reserved_file_cap() {
    let harness = IsolationHarness::new();
    let write = mediated_request(
        "external.memory.write",
        "write",
        json!({"key":"budgeted-key","value":"bounded backing value"}),
        ResourceClaim::Memory {
            namespace: "session-memory".to_owned(),
            key: "budgeted-key".to_owned(),
            access: MemoryAccess::Write,
        },
        file_budget(),
    );
    let write_permit = execution_permit(&harness.issuer, &write);
    let written = harness
        .executor
        .execute(&write_permit, &write, execution_now());
    assert_eq!(
        written.result.execution_status(),
        ProviderExecutionStatus::Completed
    );

    let store_path = fs::read_dir(harness.sandbox.join("stores/memory"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let persisted_length = fs::metadata(store_path).unwrap().len();
    assert!(persisted_length > 1);

    let read = mediated_request(
        "external.memory.read",
        "read",
        json!({"key":"budgeted-key"}),
        ResourceClaim::Memory {
            namespace: "session-memory".to_owned(),
            key: "budgeted-key".to_owned(),
            access: MemoryAccess::Read,
        },
        BudgetCharge {
            calls: 1,
            file_bytes: persisted_length,
            network_bytes: 0,
        },
    );
    let read_permit = execution_permit(&harness.issuer, &read);
    let read_result = harness
        .executor
        .execute(&read_permit, &read, execution_now());
    assert_eq!(
        read_result.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert_eq!(
        read_result.result.actual_budget_charge(),
        BudgetCharge {
            calls: 1,
            file_bytes: persisted_length,
            network_bytes: 0,
        }
    );
    read_result
        .result
        .validate_against(read.budget_charge)
        .unwrap();

    let capped = mediated_request(
        "external.memory.read",
        "read",
        json!({"key":"budgeted-key"}),
        ResourceClaim::Memory {
            namespace: "session-memory".to_owned(),
            key: "budgeted-key".to_owned(),
            access: MemoryAccess::Read,
        },
        BudgetCharge {
            calls: 1,
            file_bytes: persisted_length - 1,
            network_bytes: 0,
        },
    );
    let capped_permit = execution_permit(&harness.issuer, &capped);
    let capped_result = harness
        .executor
        .execute(&capped_permit, &capped, execution_now());
    assert_failed_before_effect(&capped_result);
    assert_eq!(
        capped_result.result.error_kind(),
        Some("resource_limit_exceeded")
    );
    assert_eq!(
        capped_result.result.reason_code(),
        Some("bounded_output_exceeded")
    );
}

#[test]
fn replayed_file_write_cannot_overwrite_a_later_operation() {
    let harness = IsolationHarness::new();
    let first = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"safe/current.txt","content":"first"}),
        file_claim("safe/current.txt", FileAccess::Write),
        file_budget(),
    );
    let first_permit = execution_permit(&harness.issuer, &first);
    let first_outcome = harness
        .executor
        .execute(&first_permit, &first, execution_now());
    assert_eq!(
        first_outcome.result.execution_status(),
        ProviderExecutionStatus::Completed
    );

    let later = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"safe/current.txt","content":"later"}),
        file_claim("safe/current.txt", FileAccess::Write),
        file_budget(),
    );
    let later_permit = execution_permit(&harness.issuer, &later);
    let later_outcome = harness
        .executor
        .execute(&later_permit, &later, execution_now());
    assert_eq!(
        later_outcome.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert_eq!(
        fs::read_to_string(harness.sandbox.join("safe/current.txt")).unwrap(),
        "later"
    );

    let replayed = harness
        .executor
        .execute(&first_permit, &first, execution_now());
    assert_eq!(replayed.result, first_outcome.result);
    assert_eq!(
        fs::read_to_string(harness.sandbox.join("safe/current.txt")).unwrap(),
        "later",
        "a replayed operation must return its cached result without repeating the write"
    );
}

#[test]
fn renewed_permit_cannot_replay_an_expired_file_operation() {
    let harness = IsolationHarness::new();
    let first = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"safe/renewed.txt","content":"first"}),
        file_claim("safe/renewed.txt", FileAccess::Write),
        file_budget(),
    );
    let first_permit = execution_permit_expiring_at(
        &harness.issuer,
        &first,
        execution_now() + Duration::minutes(1),
    );
    let first_outcome = harness
        .executor
        .execute(&first_permit, &first, execution_now());
    assert_eq!(
        first_outcome.result.execution_status(),
        ProviderExecutionStatus::Completed
    );

    let later = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"safe/renewed.txt","content":"later"}),
        file_claim("safe/renewed.txt", FileAccess::Write),
        file_budget(),
    );
    let later_permit = execution_permit_expiring_at(
        &harness.issuer,
        &later,
        execution_now() + Duration::minutes(10),
    );
    let later_outcome = harness
        .executor
        .execute(&later_permit, &later, execution_now());
    assert_eq!(
        later_outcome.result.execution_status(),
        ProviderExecutionStatus::Completed
    );

    let renewed = execution_permit_expiring_at(
        &harness.issuer,
        &first,
        execution_now() + Duration::minutes(10),
    );
    let replayed =
        harness
            .executor
            .execute(&renewed, &first, execution_now() + Duration::minutes(2));

    assert_eq!(replayed.result, first_outcome.result);
    assert_eq!(
        fs::read_to_string(harness.sandbox.join("safe/renewed.txt")).unwrap(),
        "later",
        "permit renewal must not erase the executor's exact-once operation binding"
    );
}

#[test]
fn file_provider_cannot_write_private_provider_backing_paths() {
    let harness = IsolationHarness::new();

    for path in [
        "mail/receipts/forged.json",
        "mail/tmp/forged.json.tmp",
        "stores/memory/forged.json",
        "stores/knowledge/forged.json",
    ] {
        let request = mediated_request(
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":path,"content":"attacker-controlled provider state"}),
            file_claim(path, FileAccess::Write),
            file_budget(),
        );
        let permit = execution_permit(&harness.issuer, &request);
        let outcome = harness.executor.execute(&permit, &request, execution_now());

        assert_failed_before_effect(&outcome);
        assert!(
            !harness.sandbox.join(path).exists(),
            "filesystem provider wrote private provider state at {path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn replacing_the_configured_sandbox_root_with_a_symlink_fails_closed() {
    use std::os::unix::fs::symlink;

    let harness = IsolationHarness::new();
    let moved_sandbox = harness.root.path().join("moved-sandbox");
    let outside = tempfile::tempdir().unwrap();
    fs::rename(&harness.sandbox, &moved_sandbox).unwrap();
    symlink(outside.path(), &harness.sandbox).unwrap();

    let request = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"escaped.txt","content":"must stay contained"}),
        file_claim("escaped.txt", FileAccess::Write),
        file_budget(),
    );
    let permit = execution_permit(&harness.issuer, &request);
    let outcome = harness.executor.execute(&permit, &request, execution_now());

    assert_failed_before_effect(&outcome);
    assert!(
        !outside.path().join("escaped.txt").exists(),
        "executor followed a replacement symlink for its configured sandbox root"
    );
}

#[test]
fn one_permit_cannot_execute_the_same_operation_in_two_sandboxes() {
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let first_sandbox = first_root.path().join("sandbox");
    let first_runtime = first_root.path().join("runtime");
    let second_sandbox = second_root.path().join("sandbox");
    let second_runtime = second_root.path().join("runtime");
    for directory in [
        &first_sandbox,
        &first_runtime,
        &second_sandbox,
        &second_runtime,
    ] {
        fs::create_dir_all(directory).unwrap();
    }
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let first_executor = DefaultProviderExecutor::new(
        ExecutorConfig::new(
            first_sandbox.clone(),
            first_runtime,
            64 * 1_024,
            StdDuration::from_secs(2),
            verifier.clone(),
        )
        .unwrap(),
    );
    let second_executor = DefaultProviderExecutor::new(
        ExecutorConfig::new(
            second_sandbox.clone(),
            second_runtime,
            64 * 1_024,
            StdDuration::from_secs(2),
            verifier,
        )
        .unwrap(),
    );
    let request = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"same-operation.txt","content":"execute once"}),
        file_claim("same-operation.txt", FileAccess::Write),
        file_budget(),
    );
    let permit = execution_permit(&issuer, &request);

    let first = first_executor.execute(&permit, &request, execution_now());
    assert_eq!(
        first.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    let second = second_executor.execute(&permit, &request, execution_now());

    assert_failed_before_effect(&second);
    assert_eq!(
        fs::read_to_string(first_sandbox.join("same-operation.txt")).unwrap(),
        "execute once"
    );
    assert!(
        !second_sandbox.join("same-operation.txt").exists(),
        "the same permit and operation executed a second physical side effect"
    );
}

#[test]
fn scoped_executor_rejects_permitted_claims_that_replace_server_owned_scope() {
    let root = tempfile::tempdir().unwrap();
    let sandbox = root.path().join("sandbox");
    let runtime = root.path().join("runtime");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&runtime).unwrap();
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let executor = DefaultProviderExecutor::new(
        ExecutorConfig::new_scoped(
            sandbox.clone(),
            runtime,
            64 * 1_024,
            StdDuration::from_secs(2),
            verifier,
            ResourceExtractionContext {
                filesystem_root: "workspace-a".to_owned(),
                memory_namespace: "memory-a".to_owned(),
                knowledge_namespace: "knowledge-a".to_owned(),
                default_classification: DataClass::Confidential,
            },
        )
        .unwrap(),
    );

    let requests = [
        mediated_request(
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":"safe/scope.txt","content":"wrong root"}),
            ResourceClaim::File {
                root: "workspace-b".to_owned(),
                path: relative_path("safe/scope.txt"),
                access: FileAccess::Write,
                classification: DataClass::Confidential,
            },
            file_budget(),
        ),
        mediated_request(
            "external.memory.write",
            "write",
            json!({"key":"scope-key","value":"poison"}),
            ResourceClaim::Memory {
                namespace: "memory-b".to_owned(),
                key: "scope-key".to_owned(),
                access: MemoryAccess::Write,
            },
            file_budget(),
        ),
        mediated_request(
            "external.email.send",
            "send",
            json!({"to":["scope@example.test"],"subject":"scope","body":"scope"}),
            ResourceClaim::Email {
                recipients: vec!["scope@example.test".to_owned()],
                classification: DataClass::Restricted,
            },
            network_budget(),
        ),
    ];

    for request in requests {
        let permit = execution_permit(&issuer, &request);
        let outcome = executor.execute(&permit, &request, execution_now());
        assert_failed_before_effect(&outcome);
        assert_eq!(outcome.result.error_kind(), Some("resource_claim_invalid"));
        assert_eq!(
            outcome.result.reason_code(),
            Some("claim_argument_mismatch")
        );
    }

    assert_eq!(
        fs::read_dir(&sandbox).unwrap().count(),
        0,
        "scope mismatch reached a business tool before being rejected"
    );
}

#[test]
fn scoped_executor_configuration_rejects_empty_or_control_character_scopes() {
    let root = tempfile::tempdir().unwrap();
    let sandbox = root.path().join("sandbox");
    let runtime = root.path().join("runtime");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&runtime).unwrap();
    let (_, verifier) = PermitAuthority::generate().unwrap();
    let contexts = [
        ResourceExtractionContext {
            filesystem_root: String::new(),
            memory_namespace: "memory-a".to_owned(),
            knowledge_namespace: "knowledge-a".to_owned(),
            default_classification: DataClass::Internal,
        },
        ResourceExtractionContext {
            filesystem_root: "workspace-a".to_owned(),
            memory_namespace: "memory\ncontrol".to_owned(),
            knowledge_namespace: "knowledge-a".to_owned(),
            default_classification: DataClass::Internal,
        },
        ResourceExtractionContext {
            filesystem_root: "workspace-a".to_owned(),
            memory_namespace: "memory-a".to_owned(),
            knowledge_namespace: "knowledge\tcontrol".to_owned(),
            default_classification: DataClass::Internal,
        },
    ];

    for context in contexts {
        let error = ExecutorConfig::new_scoped(
            sandbox.clone(),
            runtime.clone(),
            64 * 1_024,
            StdDuration::from_secs(2),
            verifier.clone(),
            context,
        )
        .expect_err("untrusted empty/control scope must be rejected");
        assert_eq!(error, ExecutorConfigError::InvalidResourceScope);
    }
}

#[cfg(unix)]
#[test]
fn default_file_tools_reject_read_and_write_through_symlink_escape() {
    use std::os::unix::fs::symlink;

    let harness = IsolationHarness::new();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), "outside secret").unwrap();
    symlink(outside.path(), harness.sandbox.join("link")).unwrap();

    let write = mediated_request(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"link/pwned.txt","content":"escape"}),
        file_claim("link/pwned.txt", FileAccess::Write),
        file_budget(),
    );
    let write_permit = execution_permit(&harness.issuer, &write);
    let write_result = harness
        .executor
        .execute(&write_permit, &write, execution_now());
    assert_failed_before_effect(&write_result);
    assert!(!outside.path().join("pwned.txt").exists());

    let read = mediated_request(
        "external.mcp.filesystem.read_file",
        "read_file",
        json!({"path":"link/secret.txt"}),
        file_claim("link/secret.txt", FileAccess::Read),
        file_budget(),
    );
    let read_permit = execution_permit(&harness.issuer, &read);
    let read_result = harness
        .executor
        .execute(&read_permit, &read, execution_now());
    assert_failed_before_effect(&read_result);
    assert!(matches!(
        read_result.result.output(),
        SafeProviderOutput::None
    ));
}

#[test]
fn api_and_browser_are_simulated_without_opening_a_socket() {
    let harness = IsolationHarness::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let url = format!("{origin}/must-not-connect");

    for (provider, action, arguments) in [
        (
            "external.api.request",
            "request",
            json!({"method":"GET","url":url}),
        ),
        (
            "external.mcp.browser.open_page",
            "open_page",
            json!({"url":url}),
        ),
    ] {
        let request = mediated_request(
            provider,
            action,
            arguments,
            ResourceClaim::Network {
                method: "GET".to_owned(),
                origin: origin.clone(),
                classification: DataClass::Internal,
            },
            network_budget(),
        );
        let permit = execution_permit(&harness.issuer, &request);
        let outcome = harness.executor.execute(&permit, &request, execution_now());
        assert_eq!(
            outcome.result.execution_status(),
            ProviderExecutionStatus::Simulated,
            "{provider}"
        );
        assert_eq!(
            outcome.result.side_effect_state(),
            SideEffectState::Simulated,
            "{provider}"
        );
        assert!(matches!(
            outcome.result.output(),
            SafeProviderOutput::Network { .. }
        ));
        assert!(outcome.result.output_hash().is_some());
        assert!(outcome.result.receipt().is_none());
        assert_eq!(
            outcome.result.actual_budget_charge(),
            BudgetCharge {
                calls: 0,
                file_bytes: 0,
                network_bytes: 0,
            }
        );
        outcome
            .result
            .validate_against(request.budget_charge)
            .unwrap();
    }

    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected listener error: {error}"),
        Ok(_) => panic!("simulated API/browser provider opened a real socket"),
    }
}

fn collect_rust_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, output);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

#[test]
fn production_crates_cannot_call_legacy_or_demo_tool_execution_bypasses() {
    let provider_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_root = provider_manifest.parent().expect("workspace crates root");
    let mut violations = Vec::new();

    for crate_entry in fs::read_dir(crates_root).unwrap() {
        let crate_path = crate_entry.unwrap().path();
        if !crate_path.is_dir() || crate_path == provider_manifest {
            continue;
        }
        let source_root = crate_path.join("src");
        if !source_root.is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        collect_rust_sources(&source_root, &mut sources);
        for source_path in sources {
            let source = fs::read_to_string(&source_path).unwrap();
            for forbidden in [
                "execute_external_tool(",
                "tools::execute_external_tool",
                "demo_tools::execute",
            ] {
                if source.contains(forbidden) {
                    violations.push(format!("{} names {forbidden}", source_path.display()));
                }
            }
        }
    }

    let provider_source = include_str!("../src/lib.rs");
    if provider_source.contains("pub fn execute_external_tool") {
        violations.push("runwarden-providers still publicly exports execute_external_tool".into());
    }
    assert!(
        violations.is_empty(),
        "legacy/direct tool execution bypasses remain:\n{}",
        violations.join("\n")
    );
}
