# Typed Claims And ProviderExecutor Implementation Plan

**Goal:** Replace argument-key guessing and direct tool dispatch with provider-specific resource extraction, pure Rust policy evaluation, and one execution interface that requires a frozen permit.

**Architecture:** `runwarden-providers` extracts one canonical `ResourceClaim` from each supported provider request. A new kernel `PolicyEngine` evaluates that claim against a server-owned `SessionContext` without consuming approval state. `DefaultProviderExecutor` is the only public side-effect entry point; it accepts an `ExecutionPermit` whose hashes must match the frozen request. A separate monitor-only observer records hypothetical effects, never implements the executor trait, and cannot delegate.

**Tech Stack:** Rust 1.95.0, existing provider catalog and adapters, `url` 2.5, `hmac` 0.12.1 with the existing SHA-256 0.10 line, `getrandom` 0.4.3, `zeroize` 1.9.0, local idempotent receipt files.

## Global Constraints

- Resource claims are extracted once before policy evaluation and are passed
  unchanged to approval binding and execution.
- The kernel does not scan arbitrary keys containing `path` or `url` in the
  new runtime path.
- Agents cannot select roots, namespaces, authority, classification ceilings,
  approval ids, or execution permits.
- `ProviderExecutor::execute` is the only public trusted side-effect entry
  point after this plan.
- `OpaqueLegacy` claims are display-only and cannot receive an execution
  permit.
- Monitor-only mode never calls a side-effecting executor.
- Existing `KernelEnforcer` remains as a compatibility adapter until Plans 4,
  8, and 12 migrate all callers.
- The Linux code executor remains unavailable until Plan 9; it must return a
  structured unsupported result and never run without isolation.

---

## File Responsibility Map

- Create `crates/runwarden-providers/src/resource_claims/mod.rs`: extractor
  trait, context, registry, errors.
- Create `resource_claims/{file,email,network,store,input}.rs`: exact provider
  mappings.
- Create `crates/runwarden-kernel/src/policy.rs`: `SessionContext`, ordered
  `PolicyEvaluation`, and typed resource authorization.
- Create `crates/runwarden-providers/src/executor/mod.rs`: public executor
  contracts, frozen request, permit validation.
- Create `executor/default.rs`: unique dispatch.
- Create `executor/monitor_only.rs`: non-side-effecting A/B path.
- Create `crates/runwarden-providers/src/demo_tools/`: migrated file, email,
  store, API, and browser implementations.
- Modify `crates/runwarden-providers/src/lib.rs`: re-export safe contracts and
  make legacy dispatch crate-private.
- Modify `crates/runwarden-kernel/src/kernel.rs`: compatibility delegation to
  typed policy for migrated callers.

### Frozen Interfaces

```rust
pub trait ResourceExtractor: Send + Sync {
    fn extract(
        &self,
        provider: &KernelProvider,
        action: &str,
        arguments: &serde_json::Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError>;
}

pub fn evaluate_proposal(
    session: &SessionContext,
    usage: &BudgetUsageSnapshot,
    charge: &BudgetCharge,
    provider: &KernelProvider,
    call: &ProviderCall,
    claim: &ResourceClaim,
    now: time::OffsetDateTime,
) -> PolicyEvaluation;

pub trait ProviderExecutor: Send + Sync {
    fn execute(
        &self,
        permit: &ExecutionPermit,
        request: &ProviderExecutionRequest,
        now: time::OffsetDateTime,
    ) -> ProviderExecutionOutcome;

    fn reconcile(&self, operation_id: OperationId) -> ReconciliationResult;
    fn finalize_cleanup(
        &self,
        token: CleanupToken,
        disposition: CleanupDisposition,
    ) -> Result<(), CleanupError>;
}

#[derive(Default)]
pub struct MonitorOnlyObserver;

pub trait MonitorObserver {
    fn observe(
        &self,
        evaluation: &PolicyEvaluation,
        request: &ProviderExecutionRequest,
    ) -> MonitorObservation;
}

impl ProviderExecutionResult {
    pub fn blocked(error_kind: &str, reason_code: &str) -> Self {
        Self {
            execution_status: ProviderExecutionStatus::NotExecuted,
            side_effect_state: SideEffectState::BlockedBeforeExecution,
            output: SafeProviderOutput::None,
            output_hash: None,
            receipt: None,
            error_kind: Some(error_kind.to_string()),
            reason_code: Some(reason_code.to_string()),
        }
    }
}
```

`MonitorOnlyObserver` deliberately does not implement `ProviderExecutor` and
does not accept `ExecutionPermit`. It describes a counterfactual evaluation;
it cannot cross the durable execution-start boundary.

## Task 1: Freeze Provider Execution And Permit Contracts

**Files:**

- Create: `crates/runwarden-providers/src/executor/mod.rs`
- Modify: `crates/runwarden-providers/src/lib.rs`
- Modify: `crates/runwarden-providers/Cargo.toml`
- Modify: root `Cargo.toml` and `Cargo.lock`
- Test: `crates/runwarden-providers/tests/provider_executor.rs`

**Interfaces:**

- Produces: `ProviderExecutionRequest`, MAC-sealed `ExecutionPermit`,
  `ProviderExecutionOutcome`, `ProviderExecutionResult`, `ProviderExecutor`,
  and `ReconciliationResult`.
- Consumes: Plan 1 identifiers, resource claims, and side-effect states.

- [ ] **Step 1: Write failing permit-binding tests**

Create `provider_executor.rs`:

```rust
use runwarden_kernel::operation::{
    ProviderExecutionStatus, SafeProviderOutput, SideEffectState,
};
use runwarden_kernel::story::{
    ExecutionLeaseId, OperationId, SessionId, StoryId,
};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::executor::{
    PermitAuthority, PermitClaims, ProviderExecutionRequest,
};
use serde_json::json;

#[test]
fn permit_accepts_only_the_frozen_request() {
    let request = ProviderExecutionRequest::fixture_for_test(
        "external.email.send",
        "send",
        json!({"to":["finance@example.test"],"subject":"Q2"}),
    );
    let (issuer, verifier) = PermitAuthority::generate().unwrap();
    let permit = issuer.seal(PermitClaims::fixture_for_test(&request));
    assert!(verifier.validate(&permit, &request, fixed_now()).is_ok());

    let changed = ProviderExecutionRequest {
        arguments: json!({"to":["attacker@example.test"],"subject":"Q2"}),
        ..request.clone()
    };
    assert!(verifier.validate(&permit, &changed, fixed_now()).is_err());
}

#[test]
fn provider_result_uses_authoritative_side_effect_state() {
    let result = runwarden_providers::executor::ProviderExecutionResult::blocked(
        "sandbox_unavailable",
        "Linux isolation is unavailable",
    );
    assert_eq!(result.side_effect_state, SideEffectState::BlockedBeforeExecution);
    assert!(!result.side_effect_state.was_executed());
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cargo test -p runwarden-providers --test provider_executor
```

Expected: compilation fails because `executor` does not exist.

- [ ] **Step 3: Implement the frozen request and result types**

Add `hmac = "0.12.1"`, `getrandom = "0.4.3"`, and `zeroize = "1.9.0"` to
workspace dependencies and consume them from `runwarden-providers`. Also
consume the workspace `sha2`, `time`, and `thiserror` dependencies explicitly from that
crate; the module must not rely on transitive dependencies.

Create `executor/mod.rs`. Do not declare the `default` or `monitor_only`
submodules yet; Task 4 adds those declarations together with their files:

```rust
use runwarden_kernel::operation::{
    ProviderExecutionStatus, SafeProviderOutput, SideEffectState,
};
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::story::{
    ExecutionLeaseId, OperationId, SessionId, StoryId,
};
use runwarden_kernel::trace::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ProviderExecutionRequest {
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub provider: String,
    pub action: String,
    pub arguments: Value,
    pub argument_hash: Sha256Digest,
    pub resource_claim: ResourceClaim,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
}

pub struct ExecutionPermit {
    claims: PermitClaims,
    authentication_tag: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderExecutionResult {
    pub execution_status: ProviderExecutionStatus,
    pub side_effect_state: SideEffectState,
    pub output: SafeProviderOutput,
    pub output_hash: Option<Sha256Digest>,
    pub receipt: Option<ExecutionReceipt>,
    pub error_kind: Option<String>,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub operation_id: OperationId,
    pub kind: String,
    pub relative_path: WorkspaceRelativePath,
    pub sha256: Sha256Digest,
}

pub struct ProviderExecutionOutcome {
    pub result: ProviderExecutionResult,
    pub cleanup: Option<CleanupToken>,
}

pub struct CleanupToken { id: String, provider: String }

pub enum CleanupDisposition { ResultCommitted, JournalFailedRetainForReconcile }

#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    #[error("unknown cleanup token")]
    UnknownToken,
    #[error("cleanup token/provider mismatch")]
    ProviderMismatch,
    #[error("cleanup failed: {reason_code}")]
    Failed { reason_code: String },
}

pub enum ReconciliationResult {
    Completed(ProviderExecutionResult),
    NotExecuted,
    Unknown,
}

pub trait ProviderExecutor: Send + Sync {
    fn execute(
        &self,
        permit: &ExecutionPermit,
        request: &ProviderExecutionRequest,
        now: time::OffsetDateTime,
    ) -> ProviderExecutionOutcome;

    fn reconcile(&self, operation_id: OperationId) -> ReconciliationResult;
    fn finalize_cleanup(
        &self,
        token: CleanupToken,
        disposition: CleanupDisposition,
    ) -> Result<(), CleanupError>;
}
```

- [ ] **Step 4: Implement permit construction and validation**

Add a per-process `PermitAuthority::generate` at trusted CLI/MCP startup. It
returns a `PermitIssuer` for the runtime and a `PermitVerifier` installed in
`DefaultProviderExecutor`; neither is serialized or exposed through MCP.
Plan 4 converts its `runwarden_state::ExecutionStarted` plus lease binding into
state-independent claims, then the issuer MAC-seals them. The provider crate
remains free of a state dependency.

```rust
#[derive(Debug, Clone, Serialize)]
pub struct PermitClaims {
    pub lease_id: ExecutionLeaseId,
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub expires_at: time::OffsetDateTime,
    pub execution_started_version: u64,
}
```

Use HMAC-SHA-256 with a random 256-bit process secret over Canonical JSON v1 of
`PermitClaims`. `ExecutionPermit` stores the complete private `claims`
(including `execution_started_version`) plus the tag; only
`PermitIssuer::seal(PermitClaims)` constructs it. `PermitVerifier::validate`
performs constant-time MAC verification, compares every id/provider/action/hash,
recomputes `canonical_argument_hash(request.arguments)` and
`request.resource_claim.digest()` instead of trusting request hash fields,
rejects `OpaqueLegacy`, and checks `now < expires_at` using the explicit clock
value supplied by the trusted runtime. Tests change raw arguments while
retaining the old hash, change a claim while retaining its hash, forge a tag,
use another process authority, and cross the expiry boundary.

This authenticity protects the in-process capability boundary and accidental
cross-operation calls; it does not claim security against arbitrary code
execution inside the trusted Runwarden process. Agents have no surface that
accepts permit bytes, claims, MAC keys, or `now`.

`PermitAuthority::generate` fills `[u8; 32]` with `getrandom::fill` and returns
an error without starting MCP when the OS RNG fails. Issuer and verifier share
an `Arc<zeroize::Zeroizing<[u8; 32]>>`; neither implements `Debug`, `Serialize`,
or `Deserialize`, and the key is erased when the final handle drops. A private
module unit-test helper constructs a fixed key for MAC golden vectors;
integration tests call `generate` and never depend on a `#[cfg(test)]` symbol
from the library. Use
`Hmac::<Sha256>::new_from_slice`, `Mac::update`, and `Mac::verify_slice`; never
compare tags with ordinary equality.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-providers --test provider_executor
git add crates/runwarden-providers
git commit -m "feat(providers): define frozen execution permit"
```

## Task 2: Extract Provider-Specific Resource Claims

**Files:**

- Create: `crates/runwarden-providers/src/resource_claims/mod.rs`
- Create: `crates/runwarden-providers/src/resource_claims/file.rs`
- Create: `crates/runwarden-providers/src/resource_claims/email.rs`
- Create: `crates/runwarden-providers/src/resource_claims/network.rs`
- Create: `crates/runwarden-providers/src/resource_claims/store.rs`
- Create: `crates/runwarden-providers/src/resource_claims/input.rs`
- Test: `crates/runwarden-providers/tests/resource_claim_extraction.rs`

**Interfaces:**

- Produces: `ResourceExtractionContext` and `ResourceExtractorRegistry`.
- Guarantee: server configuration supplies root, namespace, and default data
  classification.

- [ ] **Step 1: Verify the Plan 1 first-party claim vocabulary**

Confirm `ResourceClaim` already contains the frozen variants:

```rust
InputInspection {
    source: String,
    content_hash: Sha256Digest,
    classification: DataClass,
},
Evidence {
    story_id: StoryId,
    operation_id: OperationId,
},
Artifact {
    relative_path: WorkspaceRelativePath,
    format: String,
},
```

Run the Plan 1 schema drift test before adding extractors. Do not redefine or
rename these variants in the provider crate.

- [ ] **Step 2: Write table-driven extraction tests**

Cover every contest provider:

```rust
let cases = [
    ("external.mcp.filesystem.read_file", json!({"path":"reports/q2.md"}), "file"),
    ("external.mcp.filesystem.write_file", json!({"path":"out/summary.md","content":"safe"}), "file"),
    ("external.email.send", json!({"to":["FINANCE@example.test"]}), "email"),
    ("external.api.request", json!({"method":"GET","url":"https://api.example.test/v1"}), "network"),
    ("external.mcp.browser.open_page", json!({"url":"https://docs.example.test/x"}), "network"),
    ("external.memory.read", json!({"key":"quarter"}), "memory"),
    ("external.knowledge.write", json!({"key":"policy","value":"x"}), "memory"),
    ("runwarden.input.inspect", json!({"input_text":"hello"}), "input_inspection"),
];
```

Serialize each claim and assert its `kind`. Add negative cases for missing
paths, malformed URLs, empty recipient sets, unsupported actions, and agent
arguments named `root`, `namespace`, or `classification`.

- [ ] **Step 3: Implement the extractor registry**

```rust
pub struct ResourceExtractionContext {
    pub filesystem_root: String,
    pub memory_namespace: String,
    pub knowledge_namespace: String,
    pub default_classification: DataClass,
}

pub struct ResourceExtractorRegistry {
    extractors: std::collections::BTreeMap<String, Box<dyn ResourceExtractor>>,
}

impl ResourceExtractorRegistry {
    pub fn contest_default() -> Self;
    pub fn extract(
        &self,
        provider: &KernelProvider,
        action: &str,
        arguments: &Value,
        context: &ResourceExtractionContext,
    ) -> Result<ResourceClaim, ResourceExtractionError>;
}
```

For v1, accept only non-empty ASCII mailbox forms with exactly one `@`, reject
surrounding whitespace/control characters, preserve the local-part bytes, and
ASCII-lowercase only the domain. Sort and deduplicate those canonical full
addresses. The email executor re-runs this same kernel-owned canonicalizer on
private arguments and requires exact equality with the permit-bound
`ResourceClaim::Email` recipients before sending; it never consumes a
differently normalized argument list. Test that `Finance@EXAMPLE.test` becomes
`Finance@example.test`, while `FINANCE@example.test` remains a distinct local
part.

Normalize network claims to uppercase method and URL origin only. Normalize file claims
to slash-separated relative paths without `.`; reject absolute paths and
parent traversal before policy.

- [ ] **Step 4: Prove extraction does not trust policy-like arguments**

Add a test passing:

```rust
json!({
    "path": "reports/q2.md",
    "root": "/etc",
    "classification": "public",
    "namespace": "admin"
})
```

Expected: `ResourceExtractionError::ReservedField` and no claim.

- [ ] **Step 5: Run tests and commit**

```bash
cargo run -p runwarden-kernel --example generate_schemas
cargo test -p runwarden-providers --test resource_claim_extraction
cargo test -p runwarden-kernel --test contract_schemas
git add crates/runwarden-kernel crates/runwarden-providers schemas
git commit -m "feat(providers): extract typed resource claims"
```

## Task 3: Add Pure Typed Policy Evaluation

**Files:**

- Create: `crates/runwarden-kernel/src/policy.rs`
- Modify: `crates/runwarden-kernel/src/lib.rs`
- Modify: `crates/runwarden-kernel/src/resource.rs`
- Test: `crates/runwarden-kernel/tests/typed_resource_policy.rs`

**Interfaces:**

- Produces: `SessionContext`, `PolicyEvaluation`, and `evaluate_proposal`.
- Does not read or mutate approval records.

- [ ] **Step 1: Write failing ordered-policy tests**

Build a session whose authority allows one report path, one email recipient,
and one public origin. Assert:

```rust
let allowed = evaluate_proposal(
    &session, &usage, &file_charge, &file_provider, &call, &file_claim, now,
);
assert_eq!(allowed.decision, PolicyDecision::Allowed);
assert_eq!(allowed.checks.iter().map(|check| check.check_id.as_str()).collect::<Vec<_>>(), [
    "session", "provider", "authz", "resource", "budget", "approval"
]);

let exfil = evaluate_proposal(
    &session, &usage, &email_charge, &email_provider, &call, &attacker_email, now,
);
assert_eq!(exfil.decision, PolicyDecision::Denied);
assert_eq!(exfil.denial_kind.as_deref(), Some("recipient_not_allowed"));

let review = evaluate_proposal(
    &session, &usage, &email_charge, &email_provider, &call, &finance_email, now,
);
assert_eq!(review.decision, PolicyDecision::RequiresReview);
```

- [ ] **Step 2: Define the policy inputs and output**

```rust
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub authority: AuthoritySnapshot,
    pub enforcement_mode: EnforcementMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub denial_kind: Option<String>,
    pub reason: String,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub budget_usage_version: u64,
    pub budget_charge: BudgetCharge,
    pub checks: Vec<PolicyCheck>,
}
```

- [ ] **Step 3: Implement ordered typed checks**

`evaluate_proposal` runs exactly these checks and records every evaluated or
short-circuited status:

1. story/session id and expiry;
2. exact provider allowlist and registry identity;
3. actor/authz state;
4. variant-specific resource authority;
5. canonical argument bytes and per-operation wall-time ceilings, plus
   cumulative call/file/network committed+reserved usage from the versioned
   `BudgetUsageSnapshot` and proposed `BudgetCharge`;
6. provider approval requirement.

`OpaqueLegacy` is denied with `legacy_claim_not_executable`. File checks compare
root, path prefix, access, and classification. Network checks compare the
provider-specific origin. Email checks compare every normalized recipient.
Memory checks compare namespace, key prefix when configured, and access.
Code checks require a matching runtime/workspace, no stronger network
capability, and every execution limit within `CodeAuthority`. Input inspection
checks source and classification. Evidence checks current story plus typed
operation id. Artifact checks validated relative prefix and format.

The pure function does not reserve counters. It returns the usage version and
charge in `PolicyEvaluation`; Plan 2 must CAS-reserve that exact pair during
lease acquisition. Add boundary tests for exact/over argument size, exact/over
wall time, exhausted calls, and concurrent-reservation-aware file/network
usage.

Change provider registry insertion to return an error for a duplicate id
instead of silently replacing the existing provider. Add a test that a second
registration of the same id returns `ProviderRegistryError::DuplicateId` and
leaves the original provider unchanged.

- [ ] **Step 4: Remove key-name scanning from the new path**

Keep legacy `KernelEnforcer` behavior for existing callers, but ensure
`evaluate_proposal` never calls `collect_argument_strings`,
`validate_roots`, or `validate_egress`. Add a source-level regression test:

```rust
let source = include_str!("../src/policy.rs");
assert!(!source.contains("collect_argument_strings"));
assert!(!source.contains("contains(\"url\")"));
assert!(!source.contains("ends_with(\"path\")"));
```

- [ ] **Step 5: Run tests, update kernel references, and commit**

```bash
cargo test -p runwarden-kernel --test typed_resource_policy
git add crates/runwarden-kernel docs/reference/kernel-manifest.md docs/reference/authority-and-session.md
git commit -m "feat(kernel): evaluate typed resource policy"
```

## Task 4: Build The Default Executor And Separate Monitor-Only Observer

**Files:**

- Create: `crates/runwarden-providers/src/executor/default.rs`
- Create: `crates/runwarden-providers/src/executor/monitor_only.rs`
- Modify: `crates/runwarden-providers/src/executor/mod.rs`
- Modify: `crates/runwarden-providers/src/lib.rs`
- Test: `crates/runwarden-providers/tests/provider_executor.rs`

**Interfaces:**

- Produces: `DefaultProviderExecutor::new(ExecutorConfig)` and
  `MonitorOnlyObserver`.
- Guarantee: monitor-only has no reference to a delegate executor, execution
  permit, approval lease, or demo-tool module.

- [ ] **Step 1: Write a monitor-only no-side-effect test**

Use a temp sandbox and an email request. Assert:

```rust
let observer = MonitorOnlyObserver::default();
let result = observer.observe(&allowed_evaluation, &request);
assert_eq!(result.execution_status, "simulated_would_execute");
assert_eq!(result.side_effect_state, SideEffectState::Simulated);
assert!(!sandbox.join("mail").exists());
```

Add denied and review shadow-policy cases. Every syntactically valid catalogued
proposal still returns `simulated_would_execute` and `SideEffectState::Simulated`;
the differing policy decision is diagnostic metadata only. None constructs an
execution permit or lease. Malformed/unknown proposals return `not_executable`
and `NotAttempted`.

- [ ] **Step 2: Define executor configuration**

```rust
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub sandbox_root: std::path::PathBuf,
    pub trusted_runtime_root: std::path::PathBuf,
    pub max_output_bytes: usize,
    pub timeout: std::time::Duration,
}
```

The configuration is constructed by trusted CLI/MCP startup and never from
provider-call arguments.

- [ ] **Step 3: Implement default dispatch**

`DefaultProviderExecutor::execute` performs these actions in order:

1. `PermitVerifier::validate(permit, request, now)`, including fresh hashes and
   MAC;
2. confirm provider exists in the Rust catalog;
3. match exact provider id to a private implementation;
4. pass the frozen typed claim and operation id to that implementation;
5. redact output and calculate `output_hash`;
6. return a truthful side-effect state plus an optional opaque cleanup token;
7. never delete reconciliation material inside `execute` when a cleanup token
   is returned—the runtime acknowledges journal outcome through
   `finalize_cleanup`.

Add `mod default;` and `pub use default::DefaultProviderExecutor;` to
`executor/mod.rs` only after `default.rs` exists.

The code execution provider returns:

```rust
ProviderExecutionResult::blocked(
    "sandbox_unavailable",
    "sandbox_not_installed",
)
```

- [ ] **Step 4: Implement monitor-only as a separate observer type**

`MonitorOnlyObserver` has no field and never imports `DefaultProviderExecutor`,
`ExecutionPermit`, or demo-tool modules. It validates that the evaluation's
resource and policy snapshot hashes match the request, then returns a redacted
claim summary. Every valid proposal uses `simulated_would_execute` and
`SideEffectState::Simulated` regardless of the shadow policy decision, modeling
an unprotected tool path that would attempt the effect. Changing only policy
configuration must not change its simulated-effect digest. Malformed or
uncatalogued proposals are `not_executable`, never a security success.

The observer is an assurance/evaluation primitive, not a production runtime
executor. Production orchestration continues to require `ProviderExecutor` and
a real lease-backed `ExecutionPermit`.

Define the observer result in `monitor_only.rs`:

```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct MonitorObservation {
    pub shadow_policy_decision: PolicyDecision,
    pub baseline_disposition: BaselineDisposition,
    pub simulated_effect: Option<SimulatedEffect>,
    pub side_effect_state: SideEffectState,
    pub resource_claim: ResourceClaim,
}

pub enum BaselineDisposition {
    SimulatedWouldExecute,
    NotExecutable { reason_code: String },
}

pub struct SimulatedEffect {
    pub provider_id: String,
    pub action: String,
    pub resource_claim_digest: Sha256Digest,
    pub arguments_commitment: Sha256Digest,
    pub effect_kind: String,
}
```

Then export it from `executor/mod.rs` only after that file exists:

```rust
mod monitor_only;
pub use monitor_only::{MonitorObservation, MonitorObserver, MonitorOnlyObserver};
```

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-providers --test provider_executor
git add crates/runwarden-providers
git commit -m "feat(providers): add single provider executor"
```

## Task 5: Migrate Local Business Tools And Add Idempotent Email Receipts

**Files:**

- Create: `crates/runwarden-providers/src/demo_tools/mod.rs`
- Create: `crates/runwarden-providers/src/demo_tools/file.rs`
- Create: `crates/runwarden-providers/src/demo_tools/email.rs`
- Create: `crates/runwarden-providers/src/demo_tools/store.rs`
- Create: `crates/runwarden-providers/src/demo_tools/simulated_network.rs`
- Modify: `crates/runwarden-providers/src/lib.rs`
- Test: `crates/runwarden-providers/tests/provider_idempotency.rs`
- Modify: `crates/runwarden-providers/tests/runtime_isolation.rs`

**Interfaces:**

- Produces: private tool functions called only by `DefaultProviderExecutor`.
- Produces: per-operation email receipt reconciliation.

- [ ] **Step 1: Write the email exactly-once test**

Execute the same permitted email operation twice and assert:

```rust
let first = executor.execute(&permit, &request, now);
let second = executor.execute(&permit, &request, now);
assert_eq!(first.result.receipt, second.result.receipt);
let receipts = std::fs::read_dir(sandbox.join("mail/receipts")).unwrap().count();
assert_eq!(receipts, 1);
let mailbox = runwarden_providers::demo_tools::mailbox_view_for_test(&sandbox).unwrap();
assert_eq!(mailbox.matches("finance@example.test").count(), 1);
```

Add a changed argument hash with the same operation id and assert an integrity
error without a new receipt.

- [ ] **Step 2: Move local tools behind the executor**

Move the current file/email/store/simulated API/browser bodies into the files
listed above. Change `tools::execute_external_tool` to `pub(crate)` and migrate
or delete every legacy CLI test in this same checkpoint; do not retain a public
deprecated execution wrapper. Add a source contract test that production
crates outside `runwarden-providers` have no call to the crate-private body.

- [ ] **Step 3: Implement immutable email receipts**

For operation `O`, serialize one canonical record containing operation id,
argument hash, recipients, subject hash, body hash, and recorded time. Write a
unique temp file, fsync it, and atomically create
`mail/receipts/<O>.json` with `std::fs::hard_link`. If the target exists, read
and verify the stored argument hash before returning its receipt. The mailbox
view sorts receipt files and renders them; it is not an append-only authority.

- [ ] **Step 4: Preserve path containment and truthful network simulation**

Run the existing symlink and path-escape tests against the migrated file tool.
API and browser remain `SideEffectState::Simulated` and never open a socket.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-providers --test provider_idempotency
cargo test -p runwarden-providers --test runtime_isolation
cargo test -p runwarden-providers --test catalog
git add crates/runwarden-providers
git commit -m "refactor(providers): mediate local tools through executor"
```

## Task 6: Route External MCP Adapters Through The Executor

**Files:**

- Modify: `crates/runwarden-providers/src/executor/default.rs`
- Move: external adapter code from `crates/runwarden-providers/src/lib.rs`
  into `crates/runwarden-providers/src/adapters/{mod.rs,stdio.rs,http.rs,sse.rs}`
- Modify: `crates/runwarden-providers/tests/external_provider_contract.rs`
- Test: `crates/runwarden-providers/tests/executor_external_adapter.rs`
- Modify: `docs/reference/provider-contract.md`
- Modify: `docs/reference/provider-integration.md`
- Modify: `docs/reference/provider-model.md`

**Interfaces:**

- Replaces: public adapter execution based on a reusable `ProviderOutcome`.
- Requires: exact `ExecutionPermit` plus frozen request.

- [ ] **Step 1: Write a bypass-rejection test**

Assert that denied, expired, mismatched, and fabricated permits never spawn the
fixture adapter. Use a marker file in the fixture executable and assert it is
absent after each rejection.

- [ ] **Step 2: Change the mediated adapter signature**

The only callable adapter entry becomes crate-private:

```rust
pub(crate) fn execute_mediated_external_mcp_adapter(
    manifest: &ProviderManifest,
    permit: &ExecutionPermit,
    request: &ProviderExecutionRequest,
    runtime: &ExternalMcpRuntime,
) -> ProviderExecutionResult;
```

It validates the permit before manifest/transport work and preserves exact
command allowlisting, no shell or `-c`, trusted runtime root, bounded output,
process-tree cleanup, and private/local DNS denial.

- [ ] **Step 3: Wire the default executor and remove public bypasses**

`DefaultProviderExecutor` dispatches an external MCP provider to the mediated
adapter. No MCP/CLI crate may import an adapter module. Use `rg` in a test or
gate to enforce that only `executor/default.rs` names the adapter function.

- [ ] **Step 4: Run adapter and workspace regression tests**

```bash
cargo test -p runwarden-providers --test external_provider_contract
cargo test -p runwarden-providers --test executor_external_adapter
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 5: Update references and commit**

Document the unique executor, typed claim, permit binding, monitor-only
behavior, and code-sandbox unsupported state.

```bash
git add crates/runwarden-providers docs/reference
git commit -m "feat(providers): enforce the mediated adapter entry point"
```

## Task 7: Verify The Provider Boundary

**Files:**

- Verify only; fix only Plan 3 files.

**Interfaces:**

- Certifies the sole public `ProviderExecutor` boundary and typed policy path.

- [ ] **Step 1: Prove there is one public executor path**

```bash
rg -n "pub fn execute_external_tool|pub fn execute_mediated_external_mcp_adapter" crates/runwarden-providers/src
rg -n "execute_external_tool|execute_mediated_external_mcp_adapter" crates/runwarden-mcp crates/runwarden-cli
```

Expected: no public legacy function and no CLI/MCP direct call.

- [ ] **Step 2: Run provider and kernel gates**

```bash
cargo test -p runwarden-kernel --test typed_resource_policy
cargo test -p runwarden-providers
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all commands exit zero.

- [ ] **Step 3: Confirm new docs and schemas are indexed**

```bash
git diff --exit-code -- schemas
rg -n "typed resource|ProviderExecutor|execution permit" docs/reference docs/README.md
```

Expected: schema drift is clean and the provider boundary is documented.
