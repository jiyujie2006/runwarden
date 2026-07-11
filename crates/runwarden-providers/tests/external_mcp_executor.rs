#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use runwarden_kernel::KernelProvider;
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::operation::{ProviderExecutionStatus, SafeProviderOutput};
use runwarden_kernel::resource::{DataClass, FileAccess, ResourceClaim};
use runwarden_kernel::session::BudgetCharge;
use runwarden_kernel::story::{ExecutionLeaseId, OperationId, SessionId, StoryId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::catalog::{default_external_provider_manifest, full_provider_registry};
use runwarden_providers::executor::{
    DefaultProviderExecutor, ExecutionPermit, ExecutorConfig, ExternalMcpRegistrationError,
    PermitAuthority, PermitClaims, PermitIssuer, PermitVerifier, ProviderExecutionRequest,
    ProviderExecutor, canonical_argument_hash, canonical_provider_contract_hash,
};
use serde_json::json;
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};

const FILE_PROVIDER: &str = "external.mcp.filesystem.read_file";
const BROWSER_PROVIDER: &str = "external.mcp.browser.open_page";
const FILE_COMMAND: &str = "filesystem-mcp";
const BROWSER_COMMAND: &str = "browser-mcp";

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
}

fn provider(provider_id: &str) -> KernelProvider {
    full_provider_registry()
        .get(provider_id)
        .unwrap_or_else(|| panic!("provider is missing from the catalog: {provider_id}"))
        .clone()
}

fn file_claim(path: &str) -> ResourceClaim {
    ResourceClaim::File {
        root: "contest-workspace".to_owned(),
        path: WorkspaceRelativePath::try_from(path.to_owned()).unwrap(),
        access: FileAccess::Read,
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

fn valid_request() -> ProviderExecutionRequest {
    let arguments = json!({"path":"input.txt"});
    let resource_claim = file_claim("input.txt");
    let provider = provider(FILE_PROVIDER);
    ProviderExecutionRequest {
        operation_id: OperationId::new(),
        story_id: StoryId::new(),
        session_id: SessionId::new(),
        provider: provider.id.clone(),
        action: "read_file".to_owned(),
        argument_hash: canonical_argument_hash(&arguments),
        arguments,
        resource_claim_hash: resource_claim.digest(),
        resource_claim,
        policy_snapshot_hash: Sha256Digest::from_bytes(b"external-mcp-executor-policy"),
        provider_contract_hash: canonical_provider_contract_hash(&provider).unwrap(),
        budget_charge: file_budget(),
    }
}

fn claims(request: &ProviderExecutionRequest) -> PermitClaims {
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
        execution_started_version: 11,
    }
}

fn seal(issuer: &PermitIssuer, request: &ProviderExecutionRequest) -> ExecutionPermit {
    issuer.seal(claims(request)).unwrap()
}

fn config(sandbox: &Path, runtime: &Path, verifier: PermitVerifier) -> ExecutorConfig {
    ExecutorConfig::new(
        sandbox.to_path_buf(),
        runtime.to_path_buf(),
        64 * 1_024,
        StdDuration::from_secs(2),
        verifier,
    )
    .unwrap()
}

fn write_marker_adapter(runtime: &Path, command: &str, marker: &str) {
    let script = format!("#!/bin/sh\nprintf x >> {marker}\n");
    let path = runtime.join(command);
    fs::write(&path, script).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

struct Harness {
    _root: TempDir,
    sandbox: PathBuf,
    runtime: PathBuf,
    marker: PathBuf,
    issuer: PermitIssuer,
    verifier: PermitVerifier,
}

impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let sandbox = root.path().join("sandbox");
        let runtime = root.path().join("runtime");
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        write_marker_adapter(&runtime, FILE_COMMAND, "filesystem-mcp.spawned");
        write_marker_adapter(&runtime, BROWSER_COMMAND, "browser-mcp.spawned");
        let (issuer, verifier) = PermitAuthority::generate().unwrap();
        Self {
            _root: root,
            sandbox,
            marker: runtime.join("filesystem-mcp.spawned"),
            runtime,
            issuer,
            verifier,
        }
    }

    fn executor(&self) -> DefaultProviderExecutor {
        DefaultProviderExecutor::new(config(&self.sandbox, &self.runtime, self.verifier.clone()))
    }
}

#[test]
fn exact_stdio_manifest_fails_closed_until_mandatory_os_isolation_exists() {
    let harness = Harness::new();
    let manifest = default_external_provider_manifest(FILE_PROVIDER).unwrap();

    let error = harness
        .executor()
        .with_external_mcp(manifest)
        .expect_err("cwd and environment scrubbing are not an OS sandbox");

    assert_eq!(error, ExternalMcpRegistrationError::IsolationUnavailable);
    assert!(!harness.marker.exists());
}

#[test]
fn registration_rejects_every_execution_relevant_manifest_substitution() {
    let harness = Harness::new();
    let canonical = default_external_provider_manifest(FILE_PROVIDER).unwrap();
    let cases = [
        {
            let mut manifest = canonical.clone();
            manifest.transport = Some("http".to_owned());
            manifest
        },
        {
            let mut manifest = canonical.clone();
            manifest.command_allowlist = vec!["other-mcp".to_owned()];
            manifest
        },
        {
            let mut manifest = canonical.clone();
            manifest.working_root = Some("nested".to_owned());
            manifest
        },
        {
            let mut manifest = canonical;
            manifest.allowed_origins = vec!["https://example.com".to_owned()];
            manifest
        },
    ];

    for manifest in cases {
        let error = harness
            .executor()
            .with_external_mcp(manifest)
            .expect_err("a changed execution manifest must not register");
        assert_eq!(
            error,
            ExternalMcpRegistrationError::ProviderContractMismatch
        );
    }
    assert!(!harness.marker.exists());
}

#[test]
fn default_network_capable_stdio_browser_manifest_is_rejected_even_before_isolation() {
    let harness = Harness::new();
    let browser = default_external_provider_manifest(BROWSER_PROVIDER).unwrap();

    let error = harness
        .executor()
        .with_external_mcp(browser)
        .expect_err("network-capable stdio has no safe compatibility fallback");

    assert_eq!(error, ExternalMcpRegistrationError::UnsafeStdioEgress);
    assert!(!harness.runtime.join("browser-mcp.spawned").exists());
}

#[test]
fn an_unregistered_manifest_never_changes_the_private_local_dispatch() {
    let harness = Harness::new();
    fs::write(harness.sandbox.join("input.txt"), b"bounded local input").unwrap();
    let executor = harness.executor();
    let request = valid_request();
    let permit = seal(&harness.issuer, &request);

    let result = executor.execute(&permit, &request, fixed_now());

    assert_eq!(
        result.result.execution_status(),
        ProviderExecutionStatus::Completed
    );
    assert!(matches!(
        result.result.output(),
        SafeProviderOutput::File { .. }
    ));
    assert!(!harness.marker.exists());
}
