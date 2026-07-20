# Durable MCP And Reviewer API Implementation Plan

**Goal:** Make one agent tool request survive review, approval, execution, disconnect, and status lookup as one durable operation with no manual parameter retry.

**Architecture:** A new Rust `runwarden-runtime` crate coordinates the Plan 1 kernel contracts, Plan 2 journal, and Plan 3 executor. MCP parses only provider inputs, resolves the active server-owned session, and delegates to the runtime. The runtime persists proposal and policy before review, waits on SQLite, acquires/consumes a one-shot lease before execution, and returns the same operation on status/resume. Axum reviewer APIs use nonce, origin, expiry, and entity-version checks; SSE replays committed events by sequence.

**Tech Stack:** Rust 1.95.0, SQLite WAL through `runwarden-state`, Axum 0.8, Tokio, MCP JSON-RPC, 100 ms cross-process polling, 120-second contest approval window.

## Global Constraints

- Agents still see only `runwarden-mcp`; raw and downstream tools stay hidden.
- MCP rejects every session, root, authz, approval, budget, transport, and
  classification override already forbidden by the project.
- The active story/session/authority comes from the state directory and is
  cached at trusted process startup.
- Any journal error before `mark_execution_started` means the executor is not
  called.
- After `mark_execution_started`, a missing durable result is reported as
  `outcome_unknown`, never allowed, denied, completed, or safe.
- Resume accepts only an operation id. It loads the frozen private arguments;
  replacement arguments are impossible by schema.
- Approval decisions require loopback origin, per-process reviewer nonce,
  non-empty reason, and expected approval/operation version.
- SSE publishes committed database events only and resumes by story sequence.
- TypeScript/browser code remains presentation-only; this plan changes no
  browser policy logic.

---

## File Responsibility Map

- Create `crates/runwarden-runtime/`: reusable operation orchestration shared
  by MCP, scenarios, and later CLI commands.
- Create `runwarden-runtime/src/{lib,context,operation,approval,errors}.rs`.
- Refactor `runwarden-mcp/src/lib.rs` into compatibility re-exports.
- Create `runwarden-mcp/src/{server,tools,provider_call,approval_wait,config}.rs`.
- Create `runwarden-cli/src/web_server/{mod,api,sse,reviewer_nonce}.rs`.
- Keep `runwarden-cli/src/server.rs` as a compatibility facade until Plan 7
  moves assets and removes the old console.

### Frozen Interfaces

```rust
pub struct OperationRuntime<J, E, C>
where
    J: RuntimeJournal,
    E: ProviderExecutor,
    C: Clock,
{
    journal: J,
    executor: E,
    clock: C,
    context: RuntimeContext,
    permit_issuer: PermitIssuer,
    lease_owner: String,
    wait_policy: ApprovalWaitPolicy,
}

pub trait RuntimeApi: Send + Sync {
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError>;
    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
}

pub trait McpRuntime: Send + Sync {
    fn invoke(&self, request: RuntimeRequest) -> Result<RuntimeResponse, RuntimeError>;
    fn operation_status(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
    fn resume(&self, operation_id: OperationId) -> Result<RuntimeResponse, RuntimeError>;
}

pub struct McpServer<R> {
    runtime: std::sync::Arc<R>,
    max_request_bytes: usize,
    invocation_keys: InvocationKeyDeriver,
}

pub trait JsonRpcHandler {
    fn handle_jsonrpc(&self, body: &str)
        -> anyhow::Result<Option<serde_json::Value>>;
}
```

`OperationRuntime<J,E,C>` implements both `RuntimeApi` and `McpRuntime` with
the full `J/E/C` bounds repeated on each impl. `McpServer<R>` implements
`JsonRpcHandler where R: McpRuntime`. This block is real compilable Rust; there
are no forward declarations or inherent methods without bodies.

## Task 1: Add The Shared Rust Operation Runtime

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/runwarden-runtime/Cargo.toml`
- Create: `crates/runwarden-runtime/src/lib.rs`
- Create: `crates/runwarden-runtime/src/context.rs`
- Create: `crates/runwarden-runtime/src/errors.rs`
- Create: `crates/runwarden-runtime/src/operation.rs`
- Test: `crates/runwarden-runtime/tests/fail_closed.rs`
- Test: `crates/runwarden-runtime/tests/server_owned_context.rs`

**Interfaces:**

- Produces: `RuntimeRequest`, `RuntimeResponse`, `RuntimeDisposition`,
  `RuntimeError`, `RuntimeJournal`, and `Clock`.
- Consumes: `StateStore`, `ResourceExtractorRegistry`, `evaluate_proposal`,
  and `ProviderExecutor`.

- [ ] **Step 1: Write a failing pre-execution journal test**

Create a `RecordingExecutor` and `FailingJournal` test double. In Task 1 fail
the write points implemented by this task: operation proposal, policy result,
and approval creation. Assert:

```rust
let result = runtime.invoke(request.clone());
assert!(result.is_err());
assert_eq!(executor.call_count(), 0);
```

The failure names are deterministic: `create_operation`, `record_policy`, and
`create_approval`. Task 2 adds the lease and execution-start cases when those
paths exist.

- [ ] **Step 2: Add the crate dependencies**

Create the manifest:

```toml
[package]
name = "runwarden-runtime"
version = "0.1.0"
edition.workspace = true
license.workspace = true
publish.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
runwarden-kernel = { path = "../runwarden-kernel" }
runwarden-providers = { path = "../runwarden-providers" }
runwarden-state = { path = "../runwarden-state" }
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
thiserror.workspace = true
time.workspace = true
uuid.workspace = true

[dev-dependencies]
tempfile = "3.23"
```

Add it to workspace members.

- [ ] **Step 3: Define runtime requests and responses**

```rust
#[derive(Debug, Clone)]
pub struct RuntimeRequest {
    pub invocation_key: InvocationKey,
    pub provider: String,
    pub action: String,
    pub arguments: serde_json::Value,
    pub parent_model_call_id: Option<String>,
    pub proposed_tool_call_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDisposition {
    Proposed,
    Denied,
    AwaitingApproval,
    Approved,
    Executing,
    Completed,
    Failed,
    Expired,
    OutcomeUnknown,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeResponse {
    pub operation_id: OperationId,
    pub operation_version: u64,
    pub operation_state: OperationState,
    pub disposition: RuntimeDisposition,
    pub policy_decision: Option<PolicyDecision>,
    pub side_effect_state: SideEffectState,
    pub approval: Option<ApprovalView>,
    pub provider_result: Option<ProviderResultView>,
    pub observation_refs: Vec<ObservationId>,
}
```

- [ ] **Step 4: Define injectable journal and clock contracts**

`RuntimeJournal` contains only the state methods needed by orchestration. The
production implementation delegates to `StateStore`; test doubles can fail one
named point. `Clock::now() -> OffsetDateTime` replaces direct wall-clock calls
in runtime logic.

```rust
pub trait RuntimeJournal: Send + Sync {
    fn active_context(&self, instance_token_hash: &str, now: OffsetDateTime)
        -> Result<RuntimeContext, JournalError>;
    fn create_operation(&self, input: NewOperation)
        -> Result<CreateOperationOutcome, JournalError>;
    fn budget_snapshot(&self, session_id: SessionId)
        -> Result<BudgetUsageSnapshot, JournalError>;
    fn record_policy(&self, input: RecordPolicyInput)
        -> Result<SecurityOperation, JournalError>;
    fn create_approval(&self, input: NewApproval)
        -> Result<ApprovalRecordV1, JournalError>;
    fn approval_for_operation(&self, operation_id: OperationId)
        -> Result<Option<ApprovalRecordV1>, JournalError>;
    fn expire_approval(&self, input: ExpireApprovalInput)
        -> Result<ApprovalRecordV1, JournalError>;
    fn acquire_execution_lease(&self, input: LeaseRequest)
        -> Result<ExecutionLease, JournalError>;
    fn execution_lease(&self, operation_id: OperationId)
        -> Result<Option<ExecutionLease>, JournalError>;
    fn release_unstarted_lease(&self, input: ReleaseLeaseInput)
        -> Result<SecurityOperation, JournalError>;
    fn mark_execution_started(&self, lease: &ExecutionLease)
        -> Result<ExecutionStarted, JournalError>;
    fn record_execution_result(&self, input: ExecutionResultInput)
        -> Result<(), JournalError>;
    fn mark_outcome_unknown(&self, input: MarkOutcomeUnknownInput)
        -> Result<SecurityOperation, JournalError>;
    fn operation(&self, operation_id: OperationId)
        -> Result<SecurityOperation, JournalError>;
    fn load_private_operation_material(&self, operation_id: OperationId)
        -> Result<PrivateOperationMaterial, JournalError>;
    fn has_execution_started(&self, operation_id: OperationId)
        -> Result<bool, JournalError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}
```

Define `RuntimeError` variants:

```rust
pub enum RuntimeError {
    ContextUnavailable(String),
    ProviderUnknown(String),
    ResourceInvalid(String),
    JournalBeforeExecution(String),
    JournalAfterExecution { operation_id: OperationId, reason: String },
    ApprovalDenied { operation_id: OperationId, reason: String },
    ApprovalExpired { operation_id: OperationId },
    OperationConflict { operation_id: OperationId },
    OperationNotResumable { operation_id: OperationId, state: OperationState },
}
```

- [ ] **Step 5: Load one server-owned active context**

`RuntimeContextLoader::load` reads `active_instances`, story, session, and
authority once at process startup. It validates the session expiry, active
flag, policy snapshot hash, and instance token hash. It rejects a missing or
ambiguous active instance. Provider arguments are not inputs to this loader.

Production startup reads only trusted parent-process configuration:

```rust
pub struct RuntimeStartup {
    pub state_dir: std::path::PathBuf,
    pub instance_token: String,
}

impl RuntimeStartup {
    pub fn from_env() -> Result<Self, RuntimeError> {
        Ok(Self {
            state_dir: std::env::var_os("RUNWARDEN_STATE_DIR")
                .map(std::path::PathBuf::from)
                .ok_or_else(|| RuntimeError::ContextUnavailable(
                    "RUNWARDEN_STATE_DIR is not set".to_string(),
                ))?,
            instance_token: std::env::var("RUNWARDEN_INSTANCE_TOKEN")
                .map_err(|_| RuntimeError::ContextUnavailable(
                    "RUNWARDEN_INSTANCE_TOKEN is not set".to_string(),
                ))?,
        })
    }
}
```

These values are inherited from the trusted launcher, never accepted in MCP
tool arguments or agent configuration fields.

Trusted process construction also calls `PermitAuthority::generate` exactly
once. It moves the issuer into `OperationRuntime` and the paired verifier into
`DefaultProviderExecutor`; RNG failure aborts startup. Cross-crate tests call
`PermitAuthority::generate` once and pass the returned pair to runtime and
executor; deterministic MAC golden vectors remain private unit tests in the
provider crate.

- [ ] **Step 6: Implement the pre-review operation path**

`invoke` performs:

1. catalog lookup;
2. provider-specific claim extraction;
3. canonical full argument hash and Rust redacted view;
4. durable `create_operation`;
5. pure `evaluate_proposal`;
6. durable `record_policy`;
7. return denied, create pending approval, or continue to lease.

If `create_operation` returns `created=false`, verify the frozen binding and
route the existing operation through `operation_status`/`resume`; never record
policy or approval twice. Add a lost-response test that drops the first
response after durable creation, retries with the same `InvocationKey`, and
asserts one operation, one approval, and at most one executor call. Reusing the
key with changed arguments returns integrity conflict.

The continue-to-lease branch passes
`LeaseAuthorization::StoredPolicyAllow`; the journal re-reads and validates the
stored allowed decision. The post-review branch passes
`LeaseAuthorization::ReviewerApproval` with an explicit approval id/version.
No caller can encode “maybe approved” with `Option<u64>`.

Do not execute or wait in this task. Return `AwaitingApproval` immediately for
the test runtime when its configured wait policy is zero.

- [ ] **Step 7: Run tests and commit**

```bash
cargo test -p runwarden-runtime --test fail_closed
cargo test -p runwarden-runtime --test server_owned_context
git add Cargo.toml Cargo.lock crates/runwarden-runtime
git commit -m "feat(runtime): orchestrate durable provider proposals"
```

## Task 2: Complete Approval Wait, Lease, Execution, And Recovery

**Files:**

- Create: `crates/runwarden-runtime/src/approval.rs`
- Modify: `crates/runwarden-runtime/src/operation.rs`
- Test: `crates/runwarden-runtime/tests/approval_execution.rs`
- Test: `crates/runwarden-runtime/tests/post_effect_failure.rs`
- Test: `crates/runwarden-runtime/tests/reconciliation.rs`

**Interfaces:**

- Produces: `ApprovalWaitPolicy` and complete `invoke/status/resume` behavior.
- Guarantee: executor call count is at most one for one operation id.
- Consumes: the persisted `ExecutionLease.lease_owner` and
  `StateStore::execution_lease`/`has_execution_started` contracts from Plan 2.

- [ ] **Step 1: Write the same-operation approval test**

Start `runtime.invoke` on a thread with a 2-second wait policy. Wait until the
approval row exists, approve it through `StateStore::decide_approval`, and join
the invocation. Assert:

```rust
assert_eq!(response.operation_id, pending_operation_id);
assert!(matches!(response.disposition, RuntimeDisposition::Completed));
assert_eq!(executor.call_count(), 1);
assert_eq!(store.approval(approval_id).unwrap().state, ApprovalState::Consumed);
assert_eq!(store.operation(pending_operation_id).unwrap().state, OperationState::Completed);
```

Extend `fail_closed.rs` here (not Task 1) with
`acquire_execution_lease` and `mark_execution_started` failure injection. Both
must leave executor call count zero.

- [ ] **Step 2: Implement bounded database polling**

```rust
pub struct ApprovalWaitPolicy {
    pub timeout: std::time::Duration,
    pub poll_interval: std::time::Duration,
}

impl ApprovalWaitPolicy {
    pub fn contest_default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(120),
            poll_interval: std::time::Duration::from_millis(100),
        }
    }
}
```

Poll only the approval/operation rows. Pending continues, approved advances,
denied and expired return structured responses, and timeout returns the same
operation in `AwaitingApproval` rather than creating a new request.
When wall time reaches `expires_at`, call the journal's versioned
`expire_approval`; do not leave an expired row in `pending` state.

- [ ] **Step 3: Acquire or recover the durable lease, then convert it into an execution permit**

For a stored policy allow or newly reviewer-approved operation, acquire a lease
with the runtime's random per-process `lease_owner` and the matching explicit
`LeaseAuthorization` variant. For an `ExecutionLeased` resume, first require no
execution-start event, then load the existing lease:

- a valid lease owned by this process is reused and is not acquired again;
- a valid lease owned by another process returns `OperationConflict` and never
  calls the executor;
- an expired lease is released with Plan 2's versioned recovery transaction,
  then a new lease is acquired from the restored `Approved` state or, for a
  direct policy allow, from `PolicyEvaluated` with the persisted decision still
  `Allowed`.

Load the frozen private material and rebuild the same
`ProviderExecutionRequest`. First call `mark_execution_started` and capture its
new durable version. Convert that plus the selected `ExecutionLease` into Plan
3 `PermitClaims`, call the injected `PermitIssuer::seal`, then invoke the
executor with `clock.now()`. The paired `PermitVerifier` was installed in the
executor at trusted startup. No `PermitMaterial` or unauthenticated constructor
exists.

- [ ] **Step 4: Persist provider results conservatively**

- Results persist the exact `ProviderExecutionStatus`, typed
  `SafeProviderOutput`, and `SideEffectState`. `FailedBeforeSideEffect` is
  non-executed; `ExecutedWithError` counts as executed; uncertainty is
  `OutcomeUnknown`. Production runtime never receives `Simulated`.
- If result persistence fails after executor return, attempt
  `mark_outcome_unknown`. Regardless of that second write's result, return
  `RuntimeError::JournalAfterExecution` and never serialize a completed claim.
- Recovery calls `executor.reconcile(operation_id)`. A verified receipt may
  restore `Completed`; `NotExecuted` becomes `Failed`; `Unknown` becomes
  `OutcomeUnknown`.

After result persistence succeeds, call
`finalize_cleanup(token, ResultCommitted)`. If persistence fails, call
`finalize_cleanup(token, JournalFailedRetainForReconcile)` so sandbox evidence
survives reconciliation. After reconciliation reaches a durable terminal
result, issue the final committed cleanup. Cleanup failure emits an alert but
does not rewrite a truthful provider result.

- [ ] **Step 5: Implement status and resume**

`operation_status` confirms that the operation belongs to the active story and
session, then returns its display-safe snapshot. `resume` accepts only states
`Approved`, stored-policy `PolicyEvaluated`, or `ExecutionLeased` with no
execution-start event. `PolicyEvaluated` is resumable only when the persisted
decision is `Allowed`. It never retries
`Executing`, `Completed`, `Failed`, `Denied`, or `OutcomeUnknown`.

Add tests for all three leased cases: same-owner reuse executes once,
foreign-owner live lease conflicts with zero executor calls, and expired
pre-start lease releases then reacquires once. A resume never inserts a second
operation or approval row.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-runtime --test approval_execution
cargo test -p runwarden-runtime --test post_effect_failure
cargo test -p runwarden-runtime --test reconciliation
git add crates/runwarden-runtime
git commit -m "feat(runtime): resume approved operations exactly once"
```

## Task 3: Refactor MCP Around The Durable Runtime

**Files:**

- Create: `crates/runwarden-mcp/src/server.rs`
- Create: `crates/runwarden-mcp/src/tools.rs`
- Create: `crates/runwarden-mcp/src/provider_call.rs`
- Create: `crates/runwarden-mcp/src/approval_wait.rs`
- Create: `crates/runwarden-mcp/src/config.rs`
- Modify: `crates/runwarden-mcp/src/lib.rs`
- Modify: `crates/runwarden-mcp/src/main.rs`
- Modify: `crates/runwarden-mcp/Cargo.toml`
- Test: `crates/runwarden-mcp/tests/durable_provider_call.rs`
- Test: `crates/runwarden-mcp/tests/operation_status.rs`
- Test: `crates/runwarden-mcp/tests/approval_resume.rs`
- Modify: `crates/runwarden-mcp/tests/jsonrpc.rs`

**Interfaces:**

- Produces: agent tools `runwarden.operation.status` and
  `runwarden.operation.resume`.
- Preserves: all existing Runwarden-only agent configuration invariants.

- [ ] **Step 1: Write failing tool-list and schema tests**

Assert the tool list contains the existing eight tools plus:

```rust
assert!(tool_names.contains(&"runwarden.operation.status".to_string()));
assert!(tool_names.contains(&"runwarden.operation.resume".to_string()));
```

Assert both schemas require only `operation_id`, reject additional properties,
and reject provider, arguments, approval, session, root, env, cwd, URL, or
transport fields.

- [ ] **Step 2: Add runtime dependencies and server construction**

Add `runwarden-runtime` and `runwarden-state` dependencies. Consume the
workspace `hmac`, `sha2`, `zeroize`, and `thiserror` dependencies explicitly from
`runwarden-mcp`. Define:

```rust
pub struct McpServer<R> {
    runtime: std::sync::Arc<R>,
    max_request_bytes: usize,
    invocation_keys: InvocationKeyDeriver,
}

impl<R: McpRuntime> McpServer<R> {
    pub fn new(
        runtime: std::sync::Arc<R>,
        max_request_bytes: usize,
        invocation_keys: InvocationKeyDeriver,
    ) -> Self {
        Self { runtime, max_request_bytes, invocation_keys }
    }

    pub fn handle_jsonrpc(
        &self,
        body: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        handle_jsonrpc_impl(
            self.runtime.as_ref(),
            &self.invocation_keys,
            self.max_request_bytes,
            body,
        )
    }
}

pub struct InvocationKeyDeriver {
    active_instance_id: String,
    instance_token: zeroize::Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum JsonRpcRequestId {
    String(String),
    Integer(i64),
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationKeyError {
    #[error("trusted instance binding is empty")]
    EmptyTrustedBinding,
    #[error("tool name is invalid")]
    InvalidToolName,
    #[error("invocation key material could not be serialized")]
    Serialization,
}

impl InvocationKeyDeriver {
    pub fn from_trusted_instance(
        active_instance_id: String,
        instance_token: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<Self, InvocationKeyError> {
        if active_instance_id.is_empty() || instance_token.is_empty() {
            return Err(InvocationKeyError::EmptyTrustedBinding);
        }
        Ok(Self { active_instance_id, instance_token })
    }

    pub fn derive(
        &self,
        request_id: &JsonRpcRequestId,
        tool_name: &str,
    ) -> Result<InvocationKey, InvocationKeyError> {
        use hmac::Mac as _;

        if tool_name.is_empty() || tool_name.len() > 128 || !tool_name.is_ascii() {
            return Err(InvocationKeyError::InvalidToolName);
        }
        let material = serde_json::json!({
            "schema_version": "1.0.0",
            "active_instance_id": self.active_instance_id.as_str(),
            "request_id": request_id,
            "tool_name": tool_name,
        });
        let canonical = runwarden_kernel::trace::canonical_json_v1(&material);
        let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(
            self.instance_token.as_slice(),
        ).map_err(|_| InvocationKeyError::Serialization)?;
        mac.update(&canonical);
        let tag = mac.finalize().into_bytes();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&tag);
        Ok(InvocationKey::from_hmac_bytes(bytes))
    }
}
```

Keep `handle_jsonrpc_body` as a test compatibility wrapper that constructs a
runtime only in an isolated temporary state; production `main.rs` constructs
one server and one cached active context.

- [ ] **Step 3: Route provider calls without policy envelope arguments**

`provider_call.rs` removes `provider` from the flat argument map, treats the
remaining map as provider arguments, sets action from the Rust provider
descriptor, and calls `runtime.invoke`. It never constructs a fixed
`mcp-inline` session and never loads JSON approval files.

Before dispatch, `McpServer` derives `InvocationKey` as
HMAC-SHA-256(`RUNWARDEN_INSTANCE_TOKEN`, Canonical JSON v1 of active instance
id, normalized JSON-RPC request id, and tool name). It intentionally excludes
arguments: retrying one request id with changed arguments reaches Plan 2's
binding mismatch and fails instead of creating another operation. The key is
trusted runtime metadata, never a tool-schema field. A same-id lost-response
retry across reconnect/restart returns the original operation while the active
instance token remains valid.

`JsonRpcRequestId` accepts only a JSON string or an integer in the exact
interoperable range; notifications/null, floats, booleans, arrays, and objects
cannot invoke side-effecting tools. Canonical material is a deny-unknown typed
object with schema version `1.0.0`, the active instance id, request id, and tool
name. `InvocationKeyDeriver` reads the raw token only from trusted inherited
environment, retains it in `Zeroizing`, implements neither `Debug` nor
serialization, and returns P1's validated `inv_` plus 64-lowercase-hex type.
Tests freeze a vector, restart with the same instance/token, change each input,
retry changed arguments under the same derived key, and prove token bytes never
enter logs/events/API responses.

- [ ] **Step 4: Implement status and resume result shapes**

Both tools return `operation_id`, version, disposition, policy decision,
approval view, side-effect state, redacted provider result, and observation
refs. Policy denial or pending review is an MCP tool result with `isError=true`;
JSON-RPC protocol failures remain JSON-RPC errors.

- [ ] **Step 5: Delete file-backed authority from the production MCP path**

Remove production calls to `read_all_approvals_mcp`,
`persist_pending_approval_mcp`, `persist_consumed_approval_mcp`, and
`append_mcp_provider_event`. Preserve a one-release import command only if a
legacy test fixture requires it; imported records are marked legacy and cannot
authorize new execution.

- [ ] **Step 6: Run MCP tests and commit**

```bash
cargo test -p runwarden-mcp --test durable_provider_call
cargo test -p runwarden-mcp --test operation_status
cargo test -p runwarden-mcp --test approval_resume
cargo test -p runwarden-mcp --test e2e_agent_flow
cargo test -p runwarden-mcp --test jsonrpc
git add crates/runwarden-mcp
git commit -m "feat(mcp): persist and resume provider operations"
```

## Task 4: Prove Cross-Process One-Shot Execution

**Files:**

- Test: `crates/runwarden-mcp/tests/concurrent_approval_processes.rs`
- Test: `crates/runwarden-mcp/tests/disconnect_recovery.rs`
- Modify: `crates/runwarden-mcp/tests/stdio_server.rs`

**Interfaces:**

- Certifies SQLite CAS at the actual MCP process boundary.

- [ ] **Step 1: Write the two-process resume test**

Prepare one approved email operation in a temp state directory. Spawn two
`CARGO_BIN_EXE_runwarden-mcp` processes with the same trusted state and sandbox
environment. Send the same `runwarden.operation.resume` JSON-RPC request to
both stdin streams at the same barrier time. Assert:

```rust
assert_eq!(completed_responses, 1);
assert_eq!(conflict_or_terminal_responses, 1);
assert_eq!(receipt_file_count, 1);
```

Both processes must use the same active instance token and must not receive
provider arguments through the request.

- [ ] **Step 2: Write disconnect/status recovery coverage**

Close the first client after receiving a pending operation id. Approve through
the journal, reconnect a fresh MCP process, call `operation.resume`, then call
`operation.status`. Assert the same operation id reaches `Completed` and a
second resume returns the terminal snapshot without executor invocation.

- [ ] **Step 3: Preserve bounded stdio framing**

Run existing Content-Length/NDJSON, malformed request, oversize request, and
EOF cleanup tests. A waiting call may block that one stdio request, but the
reviewer process communicates through SQLite and does not require a second
message on the same connection.

- [ ] **Step 4: Run repeatedly and commit**

```bash
cargo test -p runwarden-mcp --test concurrent_approval_processes
cargo test -p runwarden-mcp --test disconnect_recovery
cargo test -p runwarden-mcp --test stdio_server
git add crates/runwarden-mcp
git commit -m "test(mcp): prove cross-process approval consumption"
```

## Task 5: Add Nonce- And Version-Protected Reviewer APIs

**Files:**

- Create: `crates/runwarden-cli/src/web_server/mod.rs`
- Create: `crates/runwarden-cli/src/web_server/api.rs`
- Create: `crates/runwarden-cli/src/web_server/reviewer_nonce.rs`
- Modify: `crates/runwarden-cli/src/server.rs`
- Modify: `crates/runwarden-cli/Cargo.toml`
- Test: `crates/runwarden-cli/tests/story_api.rs`
- Test: `crates/runwarden-cli/tests/approval_api.rs`
- Test: `crates/runwarden-cli/tests/reviewer_csrf.rs`

**Interfaces:**

- Produces all read routes from the design and the approval-decision POST.
- Defers story export POST implementation to Plan 6.

- [ ] **Step 1: Write failing API contract tests**

Test:

```text
GET  /api/bootstrap
GET  /api/stories
GET  /api/stories/{story_id}
GET  /api/stories/{story_id}/events?after_seq={sequence}
GET  /api/stories/{story_id}/operations/{operation_id}
GET  /api/stories/{story_id}/report
GET  /api/stories/{story_id}/evidence/verify
POST /api/approvals/{approval_id}/decision
```

Freeze the wire DTO (Rust field names serialize as snake_case):

```rust
#[derive(serde::Serialize)]
struct ReviewerBootstrap {
    schema_version: String,
    mode: String,
    active_story_id: StoryId,
    reviewer_nonce: String,
    accepted_origin: String,
    evidence: StoryEvidenceView,
}
```

Readers accept supported schema major `1` and preserve the actual minor
version string; no browser type narrows it to the literal `"1.0.0"`. The
response contains no private arguments or other secrets.

- [ ] **Step 2: Implement the reviewer nonce**

Generate 32 random bytes at server construction, encode URL-safe base64, store
only in memory, and compare with constant-time equality. Return it through
loopback bootstrap. Require it in `X-Runwarden-Reviewer-Nonce` for POST.

Add `getrandom = "0.4.3"`, `base64 = "0.22.1"`, and `subtle = "2.6.1"` to workspace dependencies if
absent. Decode to 32 bytes and use `subtle::ConstantTimeEq`; reject malformed
length before comparison. Do not store the
nonce in SQLite or a static HTML export.

Every response containing the nonce sets `Cache-Control: no-store,
no-cache, must-revalidate, private`, `Pragma: no-cache`, and `Expires: 0`.
The reviewer server binds loopback only, emits no permissive CORS headers,
rejects credentialed cross-origin requests, and allows the configured exact
origin. Tests cover response caching headers, absent/foreign Origin, `null`,
preflight, and restart-invalidated nonce.

- [ ] **Step 3: Enforce loopback origin and body versions**

Approval body:

```rust
#[derive(serde::Deserialize)]
struct ApprovalDecisionBody {
    decision: ReviewerDecision,
    reviewer: String,
    reason: String,
    expected_approval_version: u64,
    expected_operation_version: u64,
}
```

The approval id exists only in the URL path, never in the JSON body. The exact
wire keys are `decision`, `reviewer`, `reason`,
`expected_approval_version`, and `expected_operation_version`; decision values
are `approve`/`deny` from Plan 2's serde-tagged authority enum.

Reject missing/foreign/`null` Origin, bad nonce, empty reviewer/reason,
expired approval, stale version, changed binding hash, or inactive story. Use
HTTP 409 for version/state conflicts, 403 for nonce/origin, 404 for
cross-story ids, and 422 for invalid body.

- [ ] **Step 4: Serve display-safe state only**

Every GET delegates to `StateStore` snapshot APIs that do not select private
arguments. In this plan, evidence verification runs only
`StoryEvidenceView::verify_structure` and returns
`verification_scope="structural"`; it cannot claim report-semantic support or
set evidence `Verified`. Plan 6 installs the full assurance verifier and
upgrades this same route after its one-way dependency is available. The API
serializes the Rust-produced result; it never infers a favorable state from an
empty error list.

- [ ] **Step 5: Run API tests and commit**

```bash
cargo test -p runwarden-cli --test story_api
cargo test -p runwarden-cli --test approval_api
cargo test -p runwarden-cli --test reviewer_csrf
git add Cargo.toml Cargo.lock crates/runwarden-cli
git commit -m "feat(cli): protect reviewer approval APIs"
```

## Task 6: Add Database-Backed Resumable SSE

**Files:**

- Create: `crates/runwarden-cli/src/web_server/sse.rs`
- Test: `crates/runwarden-cli/tests/sse_resume.rs`
- Modify: `crates/runwarden-cli/src/web_server/mod.rs`

**Interfaces:**

- Produces: `GET /events?story_id={id}&after_seq={sequence}`.
- Guarantee: event id is the committed story sequence.

- [ ] **Step 1: Write reconnect and missed-event tests**

Connect after sequence 0, read events 1 and 2, disconnect, append events 3 and
4 directly through state, reconnect with `Last-Event-ID: 2`, and assert the
first two received ids are 3 and 4 in order. Repeat with `after_seq=2`.

- [ ] **Step 2: Implement committed-event polling**

The SSE stream:

1. validates the requested story is active or reviewable;
2. parses `Last-Event-ID` as a u64, falling back to `after_seq`;
3. calls `events_after` in pages of 256;
4. emits `id`, `event=story_event`, and JSON data;
5. polls every 100 ms after catching up;
6. sends a keepalive comment every 15 seconds;
7. stops when the client disconnects.

Do not use a broadcast channel as the source of truth.

- [ ] **Step 3: Add slow-client bounds**

Cap one response page at 256 events and one serialized event at 256 KiB. If an
event violates the bound, terminate with a server log and keep it available
through paginated JSON GET for investigation.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-cli --test sse_resume
git add crates/runwarden-cli
git commit -m "feat(cli): resume committed story events over SSE"
```

## Task 7: Replace The Interactive Retry Demo With One Approval Loop

**Files:**

- Modify: `crates/runwarden-cli/tests/contest_workflow.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Modify: `docs/reference/mcp.md`
- Modify: `docs/reference/authority-and-session.md`
- Modify: `docs/reference/webui-review-console.md`
- Create: `docs/reference/reviewer-http-sse-api.md`
- Modify: `docs/reference/provider-integration.md`
- Modify: `docs/README.md`

**Interfaces:**

- Replaces the current “approve then manually resend identical parameters”
  behavior.

- [ ] **Step 1: Rewrite the closed-loop integration test**

The test starts one provider call on a thread, waits for the API pending view,
approves it over HTTP, and asserts the original call returns completed. It does
not issue a second provider call. It then calls status and checks one receipt.

- [ ] **Step 2: Wire CLI demo startup to the state/runtime stack**

Interactive demo creates or opens the active story/session, constructs one
runtime, starts the reviewer server, and passes the same state directory and
active instance token to MCP/OpenCode launch instructions. Starting a second
demo against the state directory returns a clear conflict.

- [ ] **Step 3: Update exact tool and HTTP references**

Document the ten MCP tools, pending wait, status/resume, 120-second default,
nonce/origin/version rules, SSE resume, approval lease/consumption timing, and
unknown-outcome semantics. Remove file-backed retry instructions.

- [ ] **Step 4: Run the live approval gate**

```bash
cargo test -p runwarden-runtime
cargo test -p runwarden-mcp
cargo test -p runwarden-cli --test contest_workflow
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all commands pass.

- [ ] **Step 5: Commit the merge checkpoint**

```bash
git add crates docs
git commit -m "feat(demo): close the durable reviewer approval loop"
```

## Task 8: Verify Fail-Closed Behavior At Every Boundary

**Files:**

- Verify only; fix failures in Plan 4 files.

**Interfaces:**

- Certifies same-operation MCP resume, reviewer CAS, SSE replay, and fail-closed
  journal semantics.

- [ ] **Step 1: Run the crash and contention suites five times**

```bash
for run in 1 2 3 4 5; do cargo test -p runwarden-mcp --test concurrent_approval_processes || exit 1; done
```

Expected: no duplicate receipt and no flaky sequence/lease failure.

- [ ] **Step 2: Search for removed authority bypasses**

```bash
rg -n "mcp-inline|persist_pending_approval_mcp|persist_consumed_approval_mcp|append_mcp_provider_event" crates/runwarden-mcp/src
rg -n "\.ok\(\)|unwrap_or\(payload\)" crates/runwarden-mcp/src crates/runwarden-runtime/src
```

Expected: production MCP contains none of the legacy fixed-session/file-write
helpers and does not discard journal errors.

- [ ] **Step 3: Run final repository gates**

```bash
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all exit zero and the workspace contains no unreviewed generated
state files.
