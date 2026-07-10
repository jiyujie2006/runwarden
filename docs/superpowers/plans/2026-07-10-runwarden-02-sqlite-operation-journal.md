# SQLite Operation Journal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace file-backed approval and multi-writer JSONL authority with a local SQLite WAL journal that atomically persists stories, operations, approvals, and ordered evidence.

**Architecture:** A new `runwarden-state` crate depends on `runwarden-kernel` contracts and opens a short-lived SQLite connection per operation. `BEGIN IMMEDIATE` transactions serialize story sequence allocation and approval leases across processes. Private arguments are stored separately from redacted, hash-chained events and are never returned by snapshot/export APIs.

**Tech Stack:** Rust 1.95.0, `rusqlite` 0.40.1 with bundled SQLite, SQLite WAL/foreign keys/FULL synchronous mode, `serde_json`, `time`, UUIDv7.

## Global Constraints

- Dependency direction is `runwarden-state -> runwarden-kernel`; the kernel
  never imports SQLite.
- The state directory is mode `0700` and database-related files are mode
  `0600` on Unix.
- SQLite uses `journal_mode=WAL`, `foreign_keys=ON`, `synchronous=FULL`, and a
  5-second busy timeout.
- Every state change uses a monotonically increasing entity version.
- Story events accept only Plan 1 `StoryEventPayload`; the private-field
  `RedactedEventPayload` is constructed inside `StoryEvent::seal`. Private
  arguments occupy a separate column and type that does not implement
  `Serialize`.
- A provider cannot run until policy, approval/lease, and execution-start
  intent commits have succeeded.
- Cross-process conflicts return structured `JournalError::Conflict`; they are
  never silently retried into duplicate execution.
- JSONL becomes a compatibility export, not the authoritative store.
- Update `docs/reference/operation-journal.md`, authority, evidence, and MCP
  references with behavior changes.

---

## File Responsibility Map

- Create `crates/runwarden-state/Cargo.toml`: crate dependencies.
- Create `crates/runwarden-state/migrations/0001_story_journal.sql`: complete
  v1 schema.
- Create `crates/runwarden-state/src/lib.rs`: public exports and errors.
- Create `crates/runwarden-state/src/store.rs`: connection configuration,
  migration, directory permissions, transaction helpers.
- Create `crates/runwarden-state/src/stories.rs`: story and active-instance
  persistence.
- Create `crates/runwarden-state/src/sessions.rs`: immutable session and
  authority snapshots.
- Create `crates/runwarden-state/src/operations.rs`: private material,
  versioned operation transitions, policy checks.
- Create `crates/runwarden-state/src/approvals.rs`: decisions, execution lease
  CAS, and approval consumption.
- Create `crates/runwarden-state/src/events.rs`: atomic sequence allocation and
  event-chain append.
- Create `crates/runwarden-state/src/recovery.rs`: safe pre-start lease release
  and unknown-outcome candidates.
- Create `crates/runwarden-state/src/snapshots.rs`: display-safe story reads.
- Create `crates/runwarden-state/src/legacy_jsonl.rs`: verified compatibility
  bytes.

### Frozen Interfaces

```rust
pub struct StateStore { database_path: std::path::PathBuf }

impl StateStore {
    pub fn open(state_dir: impl AsRef<std::path::Path>) -> Result<Self, JournalError>;
    pub fn diagnostics(&self) -> Result<StoreDiagnostics, JournalError>;
    pub fn create_story(&self, story: &SecurityStory) -> Result<(), JournalError>;
    pub fn story(&self, story_id: StoryId) -> Result<SecurityStory, JournalError>;
    pub fn create_session(&self, session: &SessionRecord) -> Result<(), JournalError>;
    pub fn session(&self, session_id: SessionId) -> Result<SessionRecord, JournalError>;
    pub fn activate_demo(&self, activation: &DemoActivation) -> Result<(), JournalError>;
    pub fn active_demo(&self) -> Result<Option<ActiveDemo>, JournalError>;
    pub fn budget_snapshot(&self, session_id: SessionId) -> Result<BudgetUsageSnapshot, JournalError>;
    pub fn create_operation(&self, operation: NewOperation) -> Result<CreateOperationOutcome, JournalError>;
    pub fn operation(&self, operation_id: OperationId) -> Result<SecurityOperation, JournalError>;
    pub fn load_private_operation_material(&self, operation_id: OperationId) -> Result<PrivateOperationMaterial, JournalError>;
    pub fn record_policy(&self, input: RecordPolicyInput) -> Result<SecurityOperation, JournalError>;
    pub fn create_approval(&self, input: NewApproval) -> Result<ApprovalRecordV1, JournalError>;
    pub fn approval(&self, approval_id: ApprovalId) -> Result<ApprovalRecordV1, JournalError>;
    pub fn approval_for_operation(&self, operation_id: OperationId) -> Result<Option<ApprovalRecordV1>, JournalError>;
    pub fn decide_approval(&self, input: ApprovalDecisionInput) -> Result<ApprovalRecordV1, JournalError>;
    pub fn expire_approval(&self, input: ExpireApprovalInput) -> Result<ApprovalRecordV1, JournalError>;
    pub fn acquire_execution_lease(&self, input: LeaseRequest) -> Result<ExecutionLease, JournalError>;
    pub fn execution_lease(&self, operation_id: OperationId) -> Result<Option<ExecutionLease>, JournalError>;
    pub fn has_execution_started(&self, operation_id: OperationId) -> Result<bool, JournalError>;
    pub fn mark_execution_started(&self, lease: &ExecutionLease) -> Result<ExecutionStarted, JournalError>;
    pub fn record_execution_result(&self, input: ExecutionResultInput) -> Result<(), JournalError>;
    pub fn append_event(&self, input: NewStoryEvent) -> Result<CommittedStoryEvent, JournalError>;
    pub fn story_snapshot(&self, story_id: StoryId) -> Result<SecurityStory, JournalError>;
    pub fn story_evidence(&self, story_id: StoryId) -> Result<StoryEvidenceView, JournalError>;
    pub fn events_after(&self, story_id: StoryId, sequence: u64, limit: u64) -> Result<Vec<StoryEvent>, JournalError>;
    pub fn replay_frames(&self, story_id: StoryId, sequence: u64, limit: u64) -> Result<Vec<StoryReplayFrame>, JournalError>;
    pub fn release_unstarted_lease(&self, input: ReleaseLeaseInput) -> Result<SecurityOperation, JournalError>;
    pub fn recovery_candidates(&self, now: OffsetDateTime) -> Result<Vec<RecoveryCandidate>, JournalError>;
    pub fn mark_outcome_unknown(&self, input: MarkOutcomeUnknownInput) -> Result<SecurityOperation, JournalError>;
    pub fn export_legacy_jsonl(&self, story_id: StoryId) -> Result<Vec<u8>, JournalError>;
}
```

`force_wal_write_for_test` is a `#[doc(hidden)]` public test-support method
because integration tests compile the library without `cfg(test)`. It is not
used by production callers. `StoreDiagnostics` contains only schema/PRAGMA
metadata and never row contents.

## Task 1: Create The State Crate And Migration

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/runwarden-state/Cargo.toml`
- Create: `crates/runwarden-state/src/lib.rs`
- Create: `crates/runwarden-state/src/store.rs`
- Create: `crates/runwarden-state/migrations/0001_story_journal.sql`
- Test: `crates/runwarden-state/tests/migrations.rs`
- Test: `crates/runwarden-state/tests/state_permissions.rs`
- Test: `crates/runwarden-state/tests/cross_story_constraints.rs`

**Interfaces:**

- Produces: `StateStore::open` and `JournalError`.
- Produces: schema version `1` and all logical tables required by the design.

- [ ] **Step 1: Write failing migration and permission tests**

Create `tests/migrations.rs`:

```rust
use runwarden_state::StateStore;

#[test]
fn opening_a_store_applies_schema_v1_and_required_pragmas() {
    let temp = tempfile::tempdir().unwrap();
    let store = StateStore::open(temp.path().join("state")).unwrap();
    let diagnostics = store.diagnostics().unwrap();
    assert_eq!(diagnostics.schema_version, 1);
    assert_eq!(diagnostics.journal_mode, "wal");
    assert!(diagnostics.foreign_keys);
    assert_eq!(diagnostics.synchronous, 2);
    for table in [
        "stories", "sessions", "active_instances", "operations",
        "budget_usage", "budget_reservations", "resource_claims",
        "policy_checks", "approvals", "events",
        "story_frames", "report_claims", "exports",
    ] {
        assert!(diagnostics.tables.contains(&table.to_string()), "missing {table}");
    }
}
```

Create the Unix test in `tests/state_permissions.rs`:

```rust
#[cfg(unix)]
#[test]
fn state_directory_and_database_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let store = runwarden_state::StateStore::open(&state_dir).unwrap();
    store.force_wal_write_for_test().unwrap();
    assert_eq!(std::fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777, 0o700);
    for name in ["runwarden.db", "runwarden.db-wal", "runwarden.db-shm"] {
        let path = state_dir.join(name);
        if path.exists() {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail**

```bash
cargo test -p runwarden-state --test migrations
```

Expected: Cargo reports that package `runwarden-state` does not exist.

- [ ] **Step 3: Add the crate and exact dependencies**

Add `crates/runwarden-state` to the root workspace members and add:

```toml
rusqlite = { version = "0.40.1", features = ["bundled"] }
```

Create the crate manifest:

```toml
[package]
name = "runwarden-state"
version = "0.1.0"
edition.workspace = true
license.workspace = true
publish.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
runwarden-kernel = { path = "../runwarden-kernel" }
rusqlite.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
time.workspace = true
uuid.workspace = true

[dev-dependencies]
tempfile = "3.23"
```

- [ ] **Step 4: Add the full v1 migration**

Create `0001_story_journal.sql` with `STRICT` tables and these columns:

```sql
PRAGMA user_version = 1;

CREATE TABLE stories (
    story_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    title TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    run_mode TEXT NOT NULL,
    enforcement_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    safe_story_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(json_valid(safe_story_json))
) STRICT;

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    authority_json TEXT NOT NULL,
    policy_snapshot_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 0,
    UNIQUE(story_id, session_id),
    CHECK(json_valid(authority_json))
) STRICT;

CREATE TABLE active_instances (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    instance_id TEXT NOT NULL UNIQUE,
    story_id TEXT NOT NULL REFERENCES stories(story_id),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    process_id INTEGER NOT NULL,
    host_id TEXT NOT NULL,
    instance_token_hash TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id)
) STRICT;

CREATE TABLE budget_usage (
    story_id TEXT NOT NULL,
    session_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0,
    calls_reserved INTEGER NOT NULL DEFAULT 0,
    calls_committed INTEGER NOT NULL DEFAULT 0,
    file_bytes_reserved INTEGER NOT NULL DEFAULT 0,
    file_bytes_committed INTEGER NOT NULL DEFAULT 0,
    network_bytes_reserved INTEGER NOT NULL DEFAULT 0,
    network_bytes_committed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id)
) STRICT;

CREATE TABLE budget_reservations (
    lease_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    charge_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(json_valid(charge_json))
) STRICT;

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    invocation_key TEXT NOT NULL,
    parent_model_call_id TEXT,
    proposed_tool_call_id TEXT,
    provider TEXT NOT NULL,
    action TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    redacted_arguments_json TEXT NOT NULL,
    private_arguments_json BLOB NOT NULL,
    policy_snapshot_hash TEXT NOT NULL,
    policy_decision TEXT,
    policy_reason TEXT,
    state TEXT NOT NULL,
    side_effect_state TEXT NOT NULL,
    provider_result_json TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    lease_id TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    lease_pre_state TEXT,
    lease_instance_id TEXT,
    lease_instance_token_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(story_id, operation_id),
    UNIQUE(story_id, session_id, invocation_key),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(json_valid(redacted_arguments_json)),
    CHECK(json_valid(CAST(private_arguments_json AS TEXT))),
    CHECK(provider_result_json IS NULL OR json_valid(provider_result_json))
) STRICT;

CREATE TABLE resource_claims (
    story_id TEXT NOT NULL,
    operation_id TEXT PRIMARY KEY,
    claim_json TEXT NOT NULL,
    claim_hash TEXT NOT NULL,
    FOREIGN KEY(story_id, operation_id)
      REFERENCES operations(story_id, operation_id) ON DELETE CASCADE,
    CHECK(json_valid(claim_json))
) STRICT;

CREATE TABLE policy_checks (
    story_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    check_json TEXT NOT NULL,
    PRIMARY KEY(operation_id, ordinal),
    FOREIGN KEY(story_id, operation_id)
      REFERENCES operations(story_id, operation_id) ON DELETE CASCADE,
    CHECK(json_valid(check_json))
) STRICT;

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    reviewer TEXT,
    reason TEXT,
    expires_at TEXT NOT NULL,
    lease_id TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(story_id, operation_id)
      REFERENCES operations(story_id, operation_id) ON DELETE CASCADE,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(json_valid(binding_json)),
    CHECK(
      json_type(binding_json, '$.maximum_consumptions') IS 'integer'
      AND json_extract(binding_json, '$.maximum_consumptions') IS 1
    )
) STRICT;

CREATE TABLE events (
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    obs_id TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    operation_id TEXT,
    event_type TEXT NOT NULL,
    provider TEXT,
    redacted_payload_json TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(story_id, sequence),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    FOREIGN KEY(story_id, operation_id) REFERENCES operations(story_id, operation_id),
    CHECK(json_valid(redacted_payload_json))
) STRICT;

CREATE TABLE story_frames (
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    story_version INTEGER NOT NULL,
    event_hash TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    previous_frame_hash TEXT,
    frame_hash TEXT NOT NULL UNIQUE,
    safe_story_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(story_id, sequence),
    FOREIGN KEY(story_id, sequence) REFERENCES events(story_id, sequence),
    CHECK(json_valid(safe_story_json))
) STRICT;

CREATE TABLE report_claims (
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    claim_id TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    PRIMARY KEY(story_id, claim_id),
    CHECK(json_valid(claim_json))
) STRICT;

CREATE TABLE exports (
    export_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id),
    story_version INTEGER NOT NULL,
    relative_path TEXT NOT NULL UNIQUE,
    staging_name TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    manifest_hash TEXT,
    chain_head TEXT,
    final_frame_hash TEXT,
    created_at TEXT NOT NULL,
    finalized_at TEXT,
    CHECK(state IN ('preparing', 'ready_to_publish', 'finalized', 'failed'))
) STRICT;

CREATE INDEX operations_story_state_idx ON operations(story_id, state);
CREATE INDEX events_story_event_idx ON events(story_id, event_type);
CREATE INDEX approvals_state_expiry_idx ON approvals(state, expires_at);
```

- [ ] **Step 5: Implement store opening and diagnostics**

`StateStore::open` creates the directory, applies owner-only permissions,
opens `runwarden.db`, runs the migration in a transaction, and configures every
new connection with:

```rust
connection.pragma_update(None, "journal_mode", "WAL")?;
connection.pragma_update(None, "foreign_keys", true)?;
connection.pragma_update(None, "synchronous", "FULL")?;
connection.busy_timeout(std::time::Duration::from_secs(5))?;
```

Define structured errors in `src/lib.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal entity was not found: {entity} {id}")]
    NotFound { entity: &'static str, id: String },
    #[error("journal version conflict for {entity} {id}: expected {expected}, actual {actual}")]
    Conflict { entity: &'static str, id: String, expected: u64, actual: u64 },
    #[error("invalid {entity} transition from {from} to {to}")]
    InvalidTransition { entity: &'static str, from: String, to: String },
    #[error("journal integrity failure: {0}")]
    Integrity(String),
    #[error("journal permission failure: {0}")]
    Permission(String),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
```

Add `cross_story_constraints.rs`: attempt to insert an operation, approval,
event, frame, and later model proposal using a story id paired with another
story's session/operation. Each insert must fail with a foreign-key error.
Attempt malformed JSON in every `*_json` column and require a CHECK failure.
These are migration-level tests using a test-only raw connection; production
APIs never expose raw SQL.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-state --test migrations
cargo test -p runwarden-state --test state_permissions
git add Cargo.toml Cargo.lock crates/runwarden-state
git commit -m "feat(state): add SQLite story journal"
```

## Task 2: Persist Stories, Sessions, And The Single Active Demo

**Files:**

- Create: `crates/runwarden-state/src/stories.rs`
- Create: `crates/runwarden-state/src/sessions.rs`
- Modify: `crates/runwarden-state/src/lib.rs`
- Test: `crates/runwarden-state/tests/story_session.rs`

**Interfaces:**

- Produces: `SessionRecord`, `DemoActivation`, `ActiveDemo`, and the story and
  session methods from `Frozen Interfaces`.
- Guarantee: one state directory has at most one active instance.

- [ ] **Step 1: Write failing story/session tests**

Create `story_session.rs` with a shared `story_fixture()` and assert:

```rust
store.create_story(&story).unwrap();
store.create_session(&session).unwrap();
store.activate_demo(&activation).unwrap();
let active = store.active_demo().unwrap().unwrap();
assert_eq!(active.story_id, story.story_id);
assert_eq!(active.session_id, story.authority.session_id);

let second = store.activate_demo(&second_activation).unwrap_err();
assert!(matches!(second, JournalError::Conflict { entity: "active_instance", .. }));
```

Also assert that an expired session cannot be activated.

- [ ] **Step 2: Implement immutable session records**

Define:

```rust
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub story_id: StoryId,
    pub authority: AuthoritySnapshot,
    pub policy_snapshot_hash: String,
    pub expires_at: time::OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct DemoActivation {
    pub instance_id: String,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub process_id: u32,
    pub host_id: String,
    pub instance_token_hash: String,
    pub now: time::OffsetDateTime,
}
```

`create_session` rejects a `policy_snapshot_hash` that differs from the
embedded `AuthoritySnapshot`. `activate_demo` uses an insert into singleton row
`1`; it does not replace an existing row.

- [ ] **Step 3: Implement versioned safe story updates**

Add:

```rust
pub struct StoryStatusUpdate {
    pub story_id: StoryId,
    pub expected_version: u64,
    pub status: StoryStatus,
    pub evidence_status: EvidenceStatus,
    pub final_outcome_summary: String,
    pub now: OffsetDateTime,
}
```

Use one SQL update with `WHERE story_id = ? AND version = ?`; if the affected
row count is zero, load the actual version and return `JournalError::Conflict`.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-state --test story_session
git add crates/runwarden-state
git commit -m "feat(state): persist story sessions and activation"
```

## Task 3: Persist Operations And Keep Private Material Out Of Snapshots

**Files:**

- Create: `crates/runwarden-state/src/operations.rs`
- Create: `crates/runwarden-state/src/snapshots.rs`
- Test: `crates/runwarden-state/tests/operation_journal.rs`
- Test: `crates/runwarden-state/tests/snapshot_reads.rs`

**Interfaces:**

- Produces: `NewOperation`, `PrivateOperationMaterial`, `RecordPolicyInput`,
  `load_private_operation_material`.
- Guarantee: `PrivateOperationMaterial` does not implement `Serialize` or
  `JsonSchema` and is absent from all snapshots.

- [ ] **Step 1: Write failing private-material separation tests**

Create an operation whose private arguments contain `secret-raw-marker` and
whose redacted view contains `[REDACTED]`. Assert:

```rust
let operation = store.create_operation(new_operation).unwrap().operation;
let snapshot = store.story_snapshot(story.story_id).unwrap();
assert!(!serde_json::to_string(&snapshot).unwrap().contains("secret-raw-marker"));
assert_eq!(operation.state, OperationState::Proposed);
let private = store.load_private_operation_material(operation.operation_id).unwrap();
assert_eq!(private.arguments["token"], "secret-raw-marker");
```

- [ ] **Step 2: Define operation input types**

```rust
pub struct PrivateOperationMaterial {
    pub arguments: serde_json::Value,
}

pub struct CreateOperationOutcome {
    pub created: bool,
    pub operation: SecurityOperation,
}

pub struct NewOperation {
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub invocation_key: InvocationKey,
    pub parent_model_call_id: Option<String>,
    pub proposed_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub resource_claim: ResourceClaim,
    pub argument_hash: Sha256Digest,
    pub arguments: SafeArgumentView,
    pub private_material: PrivateOperationMaterial,
    pub policy_snapshot_hash: Sha256Digest,
    pub now: OffsetDateTime,
}

pub struct RecordPolicyInput {
    pub operation_id: OperationId,
    pub expected_version: u64,
    pub decision: PolicyDecision,
    pub reason: String,
    pub next_state: OperationState,
    pub checks: Vec<PolicyCheck>,
    pub now: OffsetDateTime,
}
```

- [ ] **Step 3: Implement operation creation and transitions**

`create_operation` uses one transaction to insert the operation and resource
claim and append `operation_proposed`. `record_policy` validates
`OperationState::can_transition_to`, requires the state implied by the
decision (`Allowed -> PolicyEvaluated`, `Denied -> Denied`,
`RequiresReview -> AwaitingApproval`), stores the decision/reason, inserts
ordered checks, advances the version, and appends `policy_evaluated` in the
same transaction.

The sole exception is a story already created as
`EnforcementMode::MonitorOnly`: every shadow decision persists with operation
state `PolicyEvaluated`, after which only Plan 10's
`record_monitor_observation` may transition it to `ObservedOnly`. Production
enforced stories cannot use that method or state.

On the `(story_id, session_id, invocation_key)` unique conflict,
`create_operation` loads the existing operation in the same transaction. If
provider/action/argument/resource/policy hashes all match it returns
`CreateOperationOutcome { created: false, operation }` without a new event;
any binding mismatch returns `JournalError::Integrity`. A lost-response retry
therefore discovers the original durable operation instead of creating a
second side effect.

Store private JSON bytes directly in `private_arguments_json`. Never clone
those bytes into event payload, `SecurityOperation`, debug output, or an error.

- [ ] **Step 4: Implement display-safe snapshots**

`story_snapshot` joins stories, sessions, operations, claims, checks,
approvals, and report claims plus only event count/final-hash scalars. It does
not load historical event payload rows. `story_evidence` separately loads the
safe snapshot, ordered events, and replay frames, then runs
`StoryEvidenceView::verify_structure`. Neither query selects
`private_arguments_json`.

Add a regression assertion that the literal column name is absent from the
snapshot query source:

```rust
assert!(!runwarden_state::snapshots::STORY_SNAPSHOT_SQL.contains("private_arguments_json"));
```

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-state --test operation_journal
cargo test -p runwarden-state --test snapshot_reads
git add crates/runwarden-state
git commit -m "feat(state): journal private and redacted operation views"
```

## Task 4: Add Approval Decisions And Atomic Execution Leases

**Files:**

- Create: `crates/runwarden-state/src/approvals.rs`
- Test: `crates/runwarden-state/tests/approval_contention.rs`
- Test: `crates/runwarden-state/tests/approval_lifecycle.rs`

**Interfaces:**

- Produces: `NewApproval`, `ApprovalDecisionInput`, `LeaseRequest`, and
  `ExecutionLease`.
- Guarantee: exactly one connection can reserve an approved operation.

- [ ] **Step 1: Write a two-connection lease contention test**

Open two `StateStore` values pointing at the same directory. Synchronize two
threads with `Barrier`, then call `acquire_execution_lease` using the same
operation and expected versions. Assert:

```rust
let acquired = results.iter().filter(|result| result.is_ok()).count();
let conflicts = results.iter().filter(|result| {
    matches!(result, Err(JournalError::Conflict { entity: "approval", .. }))
}).count();
assert_eq!(acquired, 1);
assert_eq!(conflicts, 1);
```

- [ ] **Step 2: Define the approval and lease inputs**

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DurableApprovalBinding {
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub operation_id: OperationId,
    pub actor_id: String,
    pub authz_id: String,
    pub provider: String,
    pub action: String,
    pub resource_claim_hash: Sha256Digest,
    pub argument_hash: Sha256Digest,
    pub data_classification: Option<DataClass>,
    pub risk_tags: Vec<String>,
    pub policy_snapshot_hash: Sha256Digest,
    pub maximum_consumptions: OneShotConsumption,
}

/// Serializes as JSON number `1`; private construction and custom
/// deserialization reject every other value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneShotConsumption(());

pub struct NewApproval {
    pub approval_id: ApprovalId,
    pub operation_id: OperationId,
    pub binding: DurableApprovalBinding,
    pub expires_at: OffsetDateTime,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecordV1 {
    pub approval_id: ApprovalId,
    pub operation_id: OperationId,
    pub binding: DurableApprovalBinding,
    pub binding_hash: String,
    pub state: ApprovalState,
    pub reviewer: Option<String>,
    pub reason: Option<String>,
    pub expires_at: OffsetDateTime,
    pub lease_id: Option<ExecutionLeaseId>,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerDecision { Approve, Deny }

pub struct ApprovalDecisionInput {
    pub approval_id: ApprovalId,
    pub expected_version: u64,
    pub expected_operation_version: u64,
    pub reviewer: String,
    pub reason: String,
    pub decision: ReviewerDecision,
    pub now: OffsetDateTime,
}

pub struct ExpireApprovalInput {
    pub approval_id: ApprovalId,
    pub expected_approval_version: u64,
    pub expected_operation_version: u64,
    pub now: OffsetDateTime,
}

pub enum LeaseAuthorization {
    StoredPolicyAllow,
    ReviewerApproval {
        approval_id: ApprovalId,
        expected_approval_version: u64,
    },
}

pub struct LeaseRequest {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub authorization: LeaseAuthorization,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub instance_id: String,
    pub instance_token_hash: String,
    pub expected_budget_version: u64,
    pub budget_charge: BudgetCharge,
    pub expires_at: OffsetDateTime,
    pub now: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ExecutionLease {
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub approval_id: Option<ApprovalId>,
    pub pre_lease_state: OperationState,
    pub instance_id: String,
    pub instance_token_hash: String,
    pub budget_charge: BudgetCharge,
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
    pub resource_claim_hash: Sha256Digest,
    pub policy_snapshot_hash: Sha256Digest,
    pub expires_at: OffsetDateTime,
}

pub struct ExecutionStarted {
    pub operation_id: OperationId,
    pub operation_version: u64,
    pub approval_version: Option<u64>,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
}

pub struct ExecutionResultInput {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub next_state: OperationState,
    pub side_effect_state: SideEffectState,
    pub provider_result: ProviderResultView,
    pub actual_budget_charge: BudgetCharge,
    pub now: OffsetDateTime,
}

pub struct ReleaseLeaseInput {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub now: OffsetDateTime,
}

pub struct MarkOutcomeUnknownInput {
    pub operation_id: OperationId,
    pub expected_operation_version: u64,
    pub lease_id: ExecutionLeaseId,
    pub lease_owner: String,
    pub reason_code: String,
    pub now: OffsetDateTime,
}
```

`OneShotConsumption::new()` is the only constructor and always represents one.
Its `Serialize` implementation emits `1`; its manual `Deserialize` accepts only
the integer `1`. The approvals table also has a migration `CHECK` requiring
`json_extract(binding_json, '$.maximum_consumptions') = 1`, so neither Rust nor
legacy SQL import can encode a multi-use approval. Contract tests reject 0, 2,
negative, floating, string, missing, and null values.

- [ ] **Step 3: Implement reviewer decision CAS**

Reject empty reviewer/reason, expired approvals, and non-pending states. Use:

```sql
UPDATE approvals
SET state = ?1, reviewer = ?2, reason = ?3,
    version = version + 1, updated_at = ?4
WHERE approval_id = ?5 AND state = 'pending' AND version = ?6
```

Map a zero-row update to a structured conflict or expiry after reading the
current row.

In the same immediate transaction, CAS the bound operation from
`awaiting_approval` to `approved` or `denied_by_reviewer` using
`expected_operation_version`, then append the decision event/frame. If either
CAS fails, roll back both rows.

`expire_approval` requires `now >= expires_at`, CASes a pending approval to
`expired` and its awaiting operation to `expired`, and appends the expiry
event/frame in one transaction.

- [ ] **Step 4: Implement lease acquisition and execution start**

`acquire_execution_lease` begins an immediate transaction and has two explicit
authorization branches; an optional approval version is never used:

- `StoredPolicyAllow` requires operation state `policy_evaluated`, a stored
  `PolicyDecision::Allowed`, matching session/policy/resource/argument hashes,
  and no approval row for the operation. It leases only the operation and sets
  `ExecutionLease.approval_id=None`.
- `ReviewerApproval` requires the named approval in `approved`, its exact
  version and binding hashes, and operation state `approved`. It CASes that
  approval to `leased` and sets `ExecutionLease.approval_id=Some(...)`.

Both branches update the operation to `execution_leased`, write the same
`execution_lease_acquired` event, and commit atomically. Add separate direct
allow, reviewed-allow, and cross-process contention tests.

In that same transaction, CAS `budget_usage.version` against
`expected_budget_version`, check committed plus reserved charge against the
session maxima, increment reserved counters, and insert one reservation keyed
by lease id. A concurrent lease that would exceed any maximum fails without an
operation/approval transition. `record_execution_result` requires actual
charge no greater than the reservation, moves actual units to committed, and
releases the remainder. A proven pre-side-effect failure or expired pre-start
lease releases it; `OutcomeUnknown` conservatively commits the full reserved
charge. Tests race two individually valid leases whose sum exceeds the limit
and require exactly one reservation.

Before either branch reserves anything, the same transaction re-reads the
singleton active instance and joined session. It requires exact
story/session/instance id/token hash, active session, `now < session.expires_at`,
and the stored policy snapshot hash. The lease persists the instance binding.
`mark_execution_started` repeats these checks in its own transaction. Cached
startup context is an input optimization, never the authorization authority;
demo deactivation, token replacement, or session expiry between evaluation and
start fails closed.

`mark_execution_started` begins a second immediate transaction, verifies the
lease id/owner/expiry and persisted active-instance binding, conditionally updates the named approval from `leased`
to `consumed` when `approval_id` is present, updates the operation to
`executing`, appends `provider_execution_started`, and returns the newly
committed `ExecutionStarted` versions. A direct policy
allow has no approval row to update. Only successful return authorizes the
caller to invoke a provider.

Approval bindings use `data_classification=None` for resource variants such as
`CodeExecution` that have no data classification, and carry stable risk tags
such as `code_execution` or `network_egress`. The UI displays “not applicable”
instead of inventing a classification.

`execution_lease(operation_id)` returns the current lease binding needed by
the trusted runtime, including `lease_owner`, but never returns private
provider arguments. It returns `None` unless the operation is in
`execution_leased`.

`record_execution_result` accepts only `Completed` or `Failed`, verifies the
same lease id, owner, executing state, and `ExecutionStarted.operation_version`, persists the redacted provider result and
authoritative side-effect state, appends the corresponding event/frame, and
commits atomically.

- [ ] **Step 5: Test expiry, binding change, and one-shot behavior**

Add tests proving:

```rust
assert!(matches!(expired, Err(JournalError::InvalidTransition { .. })));
assert!(matches!(changed_hash, Err(JournalError::Integrity(_))));
assert!(matches!(second_start, Err(JournalError::Conflict { .. })));
```

Run:

```bash
cargo test -p runwarden-state --test approval_lifecycle
cargo test -p runwarden-state --test approval_contention
```

- [ ] **Step 6: Commit the approval state machine**

```bash
git add crates/runwarden-state
git commit -m "feat(state): lease approvals with SQLite CAS"
```

## Task 5: Append Concurrent Story Events Without Sequence Gaps

**Files:**

- Create: `crates/runwarden-state/src/events.rs`
- Test: `crates/runwarden-state/tests/concurrent_events.rs`
- Test: `crates/runwarden-state/tests/event_ordering.rs`

**Interfaces:**

- Produces: `NewStoryEvent`, `append_event`, and `events_after`.
- Guarantee: every committed story has one contiguous sequence and one valid
  hash chain under concurrent writers.
- Produces one Rust `StoryReplayFrame` per committed sequence so replay selects
  authoritative snapshots instead of reducing events in TypeScript.

- [ ] **Step 1: Write the concurrent writer test**

Start eight threads, each with its own `StateStore`, and append 50 events to
one story. After joining, assert:

```rust
let events = store.events_after(story_id, 0, 1_000).unwrap();
assert_eq!(events.len(), 400);
let frames = store.replay_frames(story_id, 0, 1_000).unwrap();
assert_eq!(frames.len(), 400);
for (index, event) in events.iter().enumerate() {
    assert_eq!(event.sequence, index as u64 + 1);
    assert_eq!(frames[index].sequence, event.sequence);
    assert!(event.verify().is_ok());
    if index > 0 {
        assert_eq!(event.previous_hash.as_deref(), Some(events[index - 1].event_hash.as_str()));
    }
}
```

- [ ] **Step 2: Define new event input without sequence/hash fields**

```rust
pub struct NewStoryEvent {
    pub obs_id: ObservationId,
    pub event_id: EventId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub operation_id: Option<OperationId>,
    pub provider: Option<EventCode>,
    pub payload: StoryEventPayload,
    pub recorded_at: OffsetDateTime,
}

pub struct CommittedStoryEvent {
    pub event: StoryEvent,
    pub frame: StoryReplayFrame,
    pub story_version: u64,
}
```

- [ ] **Step 3: Implement atomic sequence allocation**

Within `BEGIN IMMEDIATE`:

1. read the last `(sequence, event_hash)` for the story;
2. create `StoryEvent::seal` with sequence plus one and the typed payload;
3. insert the event;
4. CAS-increment `stories.version`; every snapshot-affecting mutation in this
   crate is required to append through this helper in the same transaction;
5. build a display-safe `SecurityStory` aggregate with `event_count` and
   `final_event_hash`, but without an embedded event history;
6. seal `StoryReplayFrame` against the event hash, new story version, snapshot
   hash, and previous frame hash, then insert all frame hash columns;
7. commit and return `CommittedStoryEvent`.

`append_event_and_frame_tx` is the one private helper used by operation,
policy, approval, execution, recovery, proxy, and finalization transactions.
No code may update a snapshot-visible row without also advancing the story
version and writing exactly one or more matching event/frame pairs. When a
transaction emits multiple events, version and frame sequence advance once per
event in their committed order.

Do not retry a uniqueness failure by inventing a new event id. Return the
database conflict to the caller.

- [ ] **Step 4: Implement resumable reads**

`events_after(story_id, sequence, limit)` enforces `1 <= limit <= 10_000`,
orders by sequence ascending, and returns only committed rows where
`sequence > after_sequence`.

`replay_frames(story_id, sequence, limit)` returns the matching
`StoryReplayFrame` values, verifies the frame chain before returning, and never
selects private operation material. Tests mutate an intermediate snapshot,
event hash, previous frame hash, and story version independently and require
verification failure. Assert snapshots do not contain an `events` field, so
frame storage does not duplicate event history quadratically.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-state --test concurrent_events
cargo test -p runwarden-state --test event_ordering
git add crates/runwarden-state
git commit -m "feat(state): serialize story event chains"
```

## Task 6: Add Crash Recovery And Legacy JSONL Export

**Files:**

- Create: `crates/runwarden-state/src/recovery.rs`
- Create: `crates/runwarden-state/src/legacy_jsonl.rs`
- Test: `crates/runwarden-state/tests/crash_recovery.rs`
- Test: `crates/runwarden-state/tests/legacy_export.rs`
- Create: `docs/reference/operation-journal.md`
- Modify: `docs/reference/authority-and-session.md`
- Modify: `docs/reference/evidence-and-accountability.md`
- Modify: `docs/reference/mcp.md`
- Modify: `docs/README.md`

**Interfaces:**

- Produces: `RecoveryCandidate`, `release_unstarted_lease`,
  `mark_outcome_unknown`, and `export_legacy_jsonl`.

- [ ] **Step 1: Write crash-boundary tests**

Cover both durable boundaries:

```rust
let leased = store.acquire_execution_lease(request).unwrap();
store.release_unstarted_lease(ReleaseLeaseInput {
    operation_id: leased.operation_id,
    expected_operation_version: store.operation(leased.operation_id).unwrap().version,
    lease_id: leased.lease_id,
    now: now_after_expiry,
}).unwrap();
assert_eq!(store.operation(id).unwrap().state, OperationState::Approved);

let started = store.acquire_execution_lease(second_request).unwrap();
let execution = store.mark_execution_started(&started).unwrap();
let candidates = store.recovery_candidates(now_after_expiry).unwrap();
assert!(candidates.iter().any(|candidate| candidate.operation_id == second_id));
store.mark_outcome_unknown(MarkOutcomeUnknownInput {
    operation_id: second_id,
    expected_operation_version: execution.operation_version,
    lease_id: execution.lease_id,
    lease_owner: execution.lease_owner,
    reason_code: "provider_result_not_durable".to_string(),
    now,
}).unwrap();
assert_eq!(store.operation(second_id).unwrap().state, OperationState::OutcomeUnknown);
```

Add a stale-candidate race: commit `record_execution_result` after reading the
candidate, then require `mark_outcome_unknown` with the old version to return
`JournalError::Conflict` and preserve `Completed`.

- [ ] **Step 2: Implement conservative recovery**

- An expired `execution_leased` operation with no start event returns to
  `approved` and its approval returns to `approved` when the lease names an
  approval and that approval is still unexpired. If its approval has expired,
  both become `expired`. A direct-policy lease returns to its persisted
  `pre_lease_state=policy_evaluated` and still has no approval row.
- An `executing` operation never automatically retries. It becomes a
  `RecoveryCandidate`; the runtime may reconcile it in Plan 4, otherwise it is
  marked `outcome_unknown`.
- A denied, completed, failed, expired, or unknown operation is never changed
  by recovery.

Every recovery write uses `ReleaseLeaseInput` or
`MarkOutcomeUnknownInput` and CASes operation state, version, lease id, and,
when execution started, lease owner. A stale recovery candidate therefore
cannot overwrite a concurrently committed provider result.

- [ ] **Step 3: Implement verified JSONL compatibility bytes**

`export_legacy_jsonl` loads ordered events, verifies every event and previous
hash, serializes one `StoryEvent` per line, and returns `Vec<u8>`. It does not
accept a filesystem output path and does not include private arguments.

- [ ] **Step 4: Update reference documentation**

Document table ownership, WAL settings, active-instance rule, private argument
separation, approval lease timing, safe recovery, and JSONL compatibility.
State explicitly that filesystem JSON approvals and `.runwarden/events.jsonl`
are legacy surfaces until Plan 12 removes their authority.

- [ ] **Step 5: Run the complete state gate**

```bash
cargo test -p runwarden-state
cargo test --workspace
bash scripts/pr_fast_gate.sh
```

Expected: all commands pass.

- [ ] **Step 6: Commit the recovery checkpoint**

```bash
git add crates/runwarden-state docs
git commit -m "feat(state): recover journaled operations safely"
```

## Task 7: Verify The Journal Merge Checkpoint

**Files:**

- Verify only; changes are limited to failures found in this plan's files.

**Interfaces:**

- Certifies `StateStore` transaction, contention, privacy, and recovery
  contracts for Plans 4-6.

- [ ] **Step 1: Run state tests repeatedly for contention flakes**

```bash
for run in 1 2 3 4 5; do cargo test -p runwarden-state --test approval_contention --test concurrent_events || exit 1; done
```

Expected: all five runs pass.

- [ ] **Step 2: Run release-level gates**

```bash
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: exit zero. Existing live MCP still uses legacy files until Plan 4,
but the new journal crate is fully tested and ready for integration.

- [ ] **Step 3: Confirm no private material leaks**

```bash
rg -n "private_arguments_json" crates/runwarden-state/src
rg -n "secret-raw-marker" target/runwarden-contest-test artifacts 2>/dev/null
```

Expected: the private column appears only in write/private-load paths and not
in snapshots, events, or compatibility export; generated review artifacts do
not contain the marker.
