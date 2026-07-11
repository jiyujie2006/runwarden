# Story Contracts And Legacy Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze a Rust-owned Security Story v1 contract and convert the five existing demo artifacts into honest, explicitly incomplete story snapshots.

**Architecture:** Add new story, operation, resource, session, and event types beside the legacy provider contracts. The new event envelope hashes only redacted payloads and argument commitments. A Rust `LegacyStoryAdapter` converts current `webui.json` files without claiming that fixture-derived causal evidence is fully verified.

**Tech Stack:** Rust 1.95.0, edition 2024, `serde`, `serde_json`, `schemars`, `sha2`, `time`, `uuid` v7, checked-in JSON Schema.

## Global Constraints

- Rust is the only authority for story status, policy status, resource claims,
  evidence status, and side-effect state.
- `SchemaVersion::current()` writes schema version `1.0.0`; readers accept only
  canonical three-component versions with major version `1`. The JSON wire and
  generated schema remain strings.
- New identifiers serialize as UUID strings and are generated with UUIDv7.
- New event payloads contain redacted values and full-argument hashes only.
- `SideEffectState` is authoritative in new stories; legacy booleans are
  adapter inputs, not a second source of truth.
- Legacy artifacts always produce `EvidenceStatus::Incomplete` and
  `StoryProvenance::LegacyDerived`.
- Existing CLI, MCP, and scenario behavior stays functional through this plan.
- Update `docs/reference/` with every contract change and keep
  `docs/README.md` indexed.
- Final verification includes `cargo test --workspace`,
  `bash scripts/pr_fast_gate.sh`, and `bash scripts/release_gate_local.sh`.

---

## File Responsibility Map

- Create `crates/runwarden-kernel/src/story.rs`: identifiers, story status,
  evidence status, run mode, stage status, and `SecurityStory`.
- Create `crates/runwarden-kernel/src/operation.rs`: durable operation state,
  side-effect state, policy checks, approval view, and `SecurityOperation`.
- Create `crates/runwarden-kernel/src/resource.rs`: typed resource claims,
  classification, execution limits, canonical claim digest.
- Create `crates/runwarden-kernel/src/session.rs`: `AuthoritySnapshot` and
  display-safe authority rules.
- Create `crates/runwarden-kernel/src/trace.rs`: canonical JSON v1,
  `RedactedEventPayload`, and `StoryEvent` sealing/verification.
- Create `crates/runwarden-kernel/src/bundle.rs`: detached-signature bundle
  manifest and safe payload paths.
- Modify `crates/runwarden-kernel/src/authority.rs`: add `Leased` to the
  approval vocabulary without replacing legacy in-memory consumption yet.
- Modify `crates/runwarden-kernel/src/lib.rs`: export the new modules and types.
- Modify `crates/runwarden-kernel/examples/generate_schemas.rs`: generate the
  new checked-in schema files.
- Create `crates/runwarden-cli/src/story/mod.rs`: story module boundary.
- Create `crates/runwarden-cli/src/story/legacy.rs`: legacy artifact adapter.
- Modify `crates/runwarden-cli/src/main.rs`: expose the adapter to static demo
  generation while retaining legacy output files.

### Frozen Interfaces

Later plans consume these exact names:

```rust
pub struct StoryId(uuid::Uuid);
pub struct SessionId(uuid::Uuid);
pub struct OperationId(uuid::Uuid);
pub struct EventId(uuid::Uuid);
pub struct ApprovalId(uuid::Uuid);
pub struct ExecutionLeaseId(uuid::Uuid);
pub struct ObservationId(uuid::Uuid);
pub struct InvocationKey(String);

pub enum RunMode { Live, Deterministic, Recorded }
pub enum EnforcementMode { MonitorOnly, Enforced }
pub enum EvidenceStatus { Pending, Verified, Incomplete, Invalid }
pub enum SideEffectState {
    NotAttempted,
    BlockedBeforeExecution,
    Simulated,
    Completed,
    FailedBeforeSideEffect,
    ExecutedWithError,
    OutcomeUnknown,
}

pub fn canonical_json_v1(value: &serde_json::Value) -> Vec<u8>;
pub fn adapt_legacy_webui(
    input: &serde_json::Value,
    context: LegacyStoryContext,
) -> anyhow::Result<SecurityStory>;
```

## Task 1: Add Typed Identifiers And Authoritative State Enums

**Files:**

- Create: `crates/runwarden-kernel/src/story.rs`
- Create: `crates/runwarden-kernel/src/operation.rs`
- Modify: `crates/runwarden-kernel/src/authority.rs`
- Modify: `crates/runwarden-kernel/src/lib.rs`
- Modify: `crates/runwarden-kernel/Cargo.toml`
- Test: `crates/runwarden-kernel/tests/story_contract.rs`
- Test: `crates/runwarden-kernel/tests/operation_transitions.rs`

**Interfaces:**

- Produces: the identifier and enum names in `Frozen Interfaces`.
- Produces: `OperationState::can_transition_to(&self, next: &Self) -> bool`.
- Preserves: legacy `contracts::OperationStatus` and
  `contracts::ExecutionStatus` until Plan 12.

- [ ] **Step 1: Write failing identifier and serialization tests**

Create `crates/runwarden-kernel/tests/story_contract.rs`:

```rust
use runwarden_kernel::story::{EvidenceStatus, ObservationId, RunMode, StoryId};

#[test]
fn story_ids_are_uuid_v7_strings() {
    let id = StoryId::new();
    assert_eq!(id.as_uuid().get_version_num(), 7);
    let json = serde_json::to_string(&id).expect("story id serializes");
    assert_eq!(json.len(), 38);
    assert!(json.starts_with('"') && json.ends_with('"'));
}

#[test]
fn ids_reject_non_v7_uuid_strings() {
    let v4 = "00000000-0000-4000-8000-000000000000";
    assert!(serde_json::from_str::<StoryId>(&format!("\"{v4}\"")).is_err());
    assert!(serde_json::from_str::<ObservationId>(
        "\"obs_00000000-0000-4000-8000-000000000000\""
    ).is_err());
}

#[test]
fn story_modes_and_evidence_states_use_snake_case() {
    assert_eq!(serde_json::to_value(RunMode::Recorded).unwrap(), "recorded");
    assert_eq!(
        serde_json::to_value(EvidenceStatus::Incomplete).unwrap(),
        "incomplete"
    );
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```bash
cargo test -p runwarden-kernel --test story_contract
```

Expected: compilation fails because `runwarden_kernel::story` does not exist.

- [ ] **Step 3: Add UUID support and the story identifiers**

Add to `crates/runwarden-kernel/Cargo.toml`:

```toml
uuid.workspace = true
```

Create the first part of `crates/runwarden-kernel/src/story.rs`:

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

pub const SECURITY_STORY_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct SchemaVersion(String);

impl SchemaVersion {
    pub fn current() -> Self {
        Self(SECURITY_STORY_SCHEMA_VERSION.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SchemaVersion {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        fn is_canonical_number(component: &str) -> bool {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component == "0" || !component.starts_with('0'))
                && component.parse::<u64>().is_ok()
        }

        let mut components = value.split('.');
        let (Some(major), Some(minor), Some(patch), None) = (
            components.next(), components.next(), components.next(), components.next(),
        ) else {
            return Err("schema version must contain three numeric components".to_string());
        };
        if !is_canonical_number(major)
            || !is_canonical_number(minor)
            || !is_canonical_number(patch)
        {
            return Err(
                "schema version components must be canonical unsigned integers".to_string(),
            );
        }
        if major != "1" {
            return Err("schema version major must be 1".to_string());
        }
        Ok(Self(value))
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

macro_rules! typed_uuid {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            JsonSchema,
        )]
        #[schemars(with = "String")]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = String;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                if value.get_version_num() != 7 {
                    return Err(concat!(stringify!($name), " must be UUIDv7").to_string());
                }
                Ok(Self(value))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                let uuid = Uuid::parse_str(&raw).map_err(serde::de::Error::custom)?;
                Self::try_from(uuid).map_err(serde::de::Error::custom)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

typed_uuid!(StoryId);
typed_uuid!(SessionId);
typed_uuid!(OperationId);
typed_uuid!(EventId);
typed_uuid!(ApprovalId);
typed_uuid!(ExecutionLeaseId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct ObservationId(Uuid);

impl ObservationId {
    pub fn new() -> Self { Self(Uuid::now_v7()) }
}

impl TryFrom<&str> for ObservationId {
    type Error = String;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let uuid = raw
            .strip_prefix("obs_")
            .ok_or_else(|| "observation id must start with obs_".to_string())
            .and_then(|value| Uuid::parse_str(value).map_err(|error| error.to_string()))?;
        if uuid.get_version_num() != 7 {
            return Err("observation id must contain UUIDv7".to_string());
        }
        Ok(Self(uuid))
    }
}

impl Serialize for ObservationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("obs_{}", self.0))
    }
}

impl<'de> Deserialize<'de> for ObservationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw.as_str()).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for ObservationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "obs_{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct InvocationKey(String);

impl InvocationKey {
    pub fn from_hmac_bytes(bytes: [u8; 32]) -> Self {
        Self(format!("inv_{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

// Serialize as the validated string. Custom Deserialize accepts exactly
// `inv_` plus 64 lowercase hexadecimal characters and rejects all other input.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Live,
    Deterministic,
    Recorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    MonitorOnly,
    Enforced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Pending,
    Verified,
    Incomplete,
    Invalid,
}
```

Export modules from `crates/runwarden-kernel/src/lib.rs`:

```rust
pub mod operation;
pub mod story;
```

Only export modules created by this task. Tasks 2-4 add their own module
exports after the corresponding source files exist, so every task checkpoint
can compile independently.

- [ ] **Step 4: Write failing operation transition tests**

Create `crates/runwarden-kernel/tests/operation_transitions.rs`:

```rust
use runwarden_kernel::operation::{OperationState, SideEffectState};

#[test]
fn operation_state_machine_accepts_only_documented_edges() {
    assert!(OperationState::Proposed.can_transition_to(&OperationState::PolicyEvaluated));
    assert!(OperationState::PolicyEvaluated.can_transition_to(&OperationState::Denied));
    assert!(
        OperationState::AwaitingApproval.can_transition_to(&OperationState::Approved)
    );
    assert!(OperationState::Executing.can_transition_to(&OperationState::OutcomeUnknown));
    assert!(!OperationState::Denied.can_transition_to(&OperationState::Executing));
    assert!(!OperationState::Completed.can_transition_to(&OperationState::Proposed));
}

#[test]
fn side_effect_execution_semantics_are_unambiguous() {
    assert!(SideEffectState::Completed.was_executed());
    assert!(SideEffectState::ExecutedWithError.was_executed());
    for state in [
        SideEffectState::NotAttempted,
        SideEffectState::BlockedBeforeExecution,
        SideEffectState::Simulated,
        SideEffectState::FailedBeforeSideEffect,
        SideEffectState::OutcomeUnknown,
    ] {
        assert!(!state.was_executed());
    }
}
```

- [ ] **Step 5: Implement the operation states**

Create the first part of `crates/runwarden-kernel/src/operation.rs`:

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Proposed,
    PolicyEvaluated,
    Denied,
    AwaitingApproval,
    DeniedByReviewer,
    Expired,
    Approved,
    ObservedOnly,
    ExecutionLeased,
    Executing,
    Completed,
    Failed,
    OutcomeUnknown,
}

impl OperationState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        matches!(
            (self, next),
            (Self::Proposed, Self::PolicyEvaluated)
                | (Self::PolicyEvaluated, Self::Denied)
                | (Self::PolicyEvaluated, Self::AwaitingApproval)
                | (Self::PolicyEvaluated, Self::ExecutionLeased)
                | (Self::PolicyEvaluated, Self::ObservedOnly)
                | (Self::AwaitingApproval, Self::DeniedByReviewer)
                | (Self::AwaitingApproval, Self::Expired)
                | (Self::AwaitingApproval, Self::Approved)
                | (Self::Approved, Self::ExecutionLeased)
                | (Self::ExecutionLeased, Self::Executing)
                | (Self::Executing, Self::Completed)
                | (Self::Executing, Self::Failed)
                | (Self::Executing, Self::OutcomeUnknown)
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::DeniedByReviewer
                | Self::Expired
                | Self::Completed
                | Self::Failed
                | Self::ObservedOnly
                | Self::OutcomeUnknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectState {
    NotAttempted,
    BlockedBeforeExecution,
    Simulated,
    Completed,
    FailedBeforeSideEffect,
    ExecutedWithError,
    OutcomeUnknown,
}

impl SideEffectState {
    pub fn was_executed(&self) -> bool {
        matches!(self, Self::Completed | Self::ExecutedWithError)
    }
}
```

`FailedBeforeSideEffect` requires affirmative provider evidence that no side
effect started. `ExecutedWithError` means execution definitely started and
ended with a known error (for example, a sandboxed Python process exited
nonzero). Any partial or unconfirmed external effect is `OutcomeUnknown`.

Add `Leased` to the existing `ApprovalState` in
`crates/runwarden-kernel/src/authority.rs`. Update exhaustive legacy matches so
`Leased` is rejected by the legacy in-memory authority path. Plan 2 owns the
durable SQLite lease transition; Plan 4 only orchestrates that state contract.

- [ ] **Step 6: Run the narrow tests and commit**

Run:

```bash
cargo test -p runwarden-kernel --test story_contract
cargo test -p runwarden-kernel --test operation_transitions
cargo test -p runwarden-kernel --test contract_states
```

Expected: all tests pass.

Commit:

```bash
git add crates/runwarden-kernel
git commit -m "feat(kernel): add security story state contracts"
```

## Task 2: Add Typed Resource, Authority, Operation, And Story Views

**Files:**

- Create: `crates/runwarden-kernel/src/resource.rs`
- Create: `crates/runwarden-kernel/src/session.rs`
- Create: `crates/runwarden-kernel/src/trace.rs` with Canonical JSON v1 only
- Modify: `crates/runwarden-kernel/src/artifact.rs`
- Modify: `crates/runwarden-kernel/src/operation.rs`
- Modify: `crates/runwarden-kernel/src/story.rs`
- Modify: `crates/runwarden-kernel/src/lib.rs`
- Test: `crates/runwarden-kernel/tests/resource_claims.rs`
- Test: `crates/runwarden-kernel/tests/story_contract.rs`
- Create: `crates/runwarden-kernel/tests/canonical_json_v1.rs`

**Interfaces:**

- Produces: `ResourceClaim::digest() -> Sha256Digest`.
- Produces: validated `WorkspaceRelativePath` for artifact and receipt
  contracts.
- Produces: the initial `canonical_json_v1` implementation used by claim
  digests; Task 3 extends the same module with redaction and event sealing.
- Produces: `AuthoritySnapshot`, `PolicyCheck`, `SecurityOperation`, and
  `SecurityStory` with stable JSON field names.
- Consumes: typed ids and states from Task 1.

- [ ] **Step 1: Write failing resource digest tests**

Append to `crates/runwarden-kernel/tests/resource_claims.rs`:

```rust
use runwarden_kernel::artifact::WorkspaceRelativePath;
use runwarden_kernel::resource::{DataClass, FileAccess, ResourceClaim};

#[test]
fn equivalent_file_claims_have_a_stable_digest() {
    let claim = ResourceClaim::File {
        root: "workspace".to_string(),
        path: WorkspaceRelativePath::try_from("reports/q2.md".to_string()).unwrap(),
        access: FileAccess::Read,
        classification: DataClass::Internal,
    };
    assert_eq!(claim.digest(), claim.clone().digest());
    assert!(claim.digest().as_str().starts_with("sha256:"));
}

#[test]
fn changed_resource_changes_the_claim_digest() {
    let first = ResourceClaim::Email {
        recipients: vec!["finance@example.test".to_string()],
        classification: DataClass::Internal,
    };
    let second = ResourceClaim::Email {
        recipients: vec!["attacker@example.test".to_string()],
        classification: DataClass::Internal,
    };
    assert_ne!(first.digest(), second.digest());
}
```

- [ ] **Step 2: Implement Canonical JSON v1 and the typed resource vocabulary**

Create `crates/runwarden-kernel/src/trace.rs` with the complete
`canonical_json_v1` implementation and its recursive UTF-8 byte-order object
key sorting. This is the single canonicalization implementation; resource
digests, event hashes, and later signatures all call it. Create
`crates/runwarden-kernel/tests/canonical_json_v1.rs` with the frozen vector so
this task cannot commit a provisional serializer:

```rust
use runwarden_kernel::trace::canonical_json_v1;
use serde_json::json;

#[test]
fn canonical_json_v1_matches_the_frozen_vector() {
    let material = json!({
        "story_id": "01980a8c-0000-7000-8000-000000000001",
        "session_id": "01980a8c-0000-7000-8000-000000000004",
        "event_id": "01980a8c-0000-7000-8000-000000000003",
        "sequence": 1,
        "operation_id": "01980a8c-0000-7000-8000-000000000002",
        "event_type": "policy_decision",
        "provider": "external.api.request",
        "payload": {"decision": "denied", "argument_hash": "sha256:abc"},
        "previous_hash": null,
        "recorded_at": "2026-07-10T00:00:00Z"
    });
    let digest = runwarden_kernel::evidence::hex_sha256(&canonical_json_v1(&material));
    assert_eq!(
        digest,
        "f263be6bde1a71177e0f9170cf30d22f6fe7aa50ab9c771b4a709b9903bc0ae1"
    );
}
```

Implement the canonicalizer in `trace.rs` exactly once:

```rust
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::evidence::hex_sha256;

pub fn canonical_json_v1(value: &Value) -> Vec<u8> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let sorted = map
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect::<BTreeMap<_, _>>();
                let mut output = Map::new();
                for (key, value) in sorted {
                    output.insert(key, value);
                }
                Value::Object(output)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            primitive => primitive.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).expect("canonical JSON value serializes")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryEventKind {
    OperationProposed,
    PolicyDecision,
    ApprovalLifecycle,
    ProviderExecution,
    ModelCall,
    ToolProposal,
    CausalLink,
    EvidenceVerification,
    InputConsumed,
    SandboxDecision,
    MonitorObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct Sha256Digest(String);

impl TryFrom<String> for Sha256Digest {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let hex = value.strip_prefix("sha256:")
            .ok_or_else(|| "digest must start with sha256:".to_string())?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("digest must contain 64 lowercase hexadecimal characters".to_string());
        }
        Ok(Self(value))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl Sha256Digest {
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex_sha256(bytes)))
    }
    pub(crate) fn zero_for_construction() -> Self {
        Self(format!("sha256:{}", "0".repeat(64)))
    }
}
```

Create `crates/runwarden-kernel/src/resource.rs`:

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::WorkspaceRelativePath;
use crate::story::{OperationId, StoryId};
use crate::trace::Sha256Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl DataClass {
    pub fn is_within(&self, maximum: &Self) -> bool {
        fn rank(value: &DataClass) -> u8 {
            match value {
                DataClass::Public => 0,
                DataClass::Internal => 1,
                DataClass::Confidential => 2,
                DataClass::Restricted => 3,
            }
        }
        rank(self) <= rank(maximum)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess { Read, Write }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccess { Read, Write }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCapability { None, Brokered }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionLimits {
    pub wall_time_ms: u64,
    pub cpu_time_ms: u64,
    pub memory_bytes: u64,
    pub output_bytes: u64,
    pub process_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceClaim {
    File {
        root: String,
        path: WorkspaceRelativePath,
        access: FileAccess,
        classification: DataClass,
    },
    Network {
        method: String,
        origin: String,
        classification: DataClass,
    },
    Email {
        recipients: Vec<String>,
        classification: DataClass,
    },
    Memory {
        namespace: String,
        key: String,
        access: MemoryAccess,
    },
    CodeExecution {
        runtime: String,
        workspace: String,
        network: NetworkCapability,
        limits: ExecutionLimits,
    },
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
    OpaqueLegacy {
        provider: String,
        redacted_summary: String,
    },
}

impl ResourceClaim {
    pub fn digest(&self) -> Sha256Digest {
        let value = serde_json::to_value(self).expect("resource claim serializes");
        let bytes = crate::trace::canonical_json_v1(&value);
        Sha256Digest::from_bytes(&bytes)
    }
}
```

Add `WorkspaceRelativePath` to `artifact.rs` as a private-field string newtype
with `TryFrom<String>` plus validating `Deserialize`. Accept only non-empty,
slash-separated relative components; reject absolute paths, backslashes,
colons, empty/`.`/`..` components, NUL, and platform prefixes. Serialization
returns the normalized string. Add tests that direct deserialization cannot
bypass validation. Filesystem creation still uses stable-root/no-follow APIs
in Plan 6; this type proves lexical safety, not symlink safety.

Freeze its public read-only accessor so bundle sorting compiles without
exposing an unchecked constructor:

```rust
impl WorkspaceRelativePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

- [ ] **Step 3: Add the authority snapshot**

Create `crates/runwarden-kernel/src/session.rs` with these complete public
contracts:

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::artifact::WorkspaceRelativePath;
use crate::resource::{
    DataClass, ExecutionLimits, FileAccess, MemoryAccess, NetworkCapability,
};
use crate::story::{OperationId, SessionId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileAuthority {
    pub root: String,
    pub path_prefix: String,
    pub access: Vec<FileAccess>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NetworkAuthority {
    pub provider: String,
    pub allowed_origins: Vec<String>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EmailAuthority {
    pub allowed_recipients: Vec<String>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoreAuthority {
    pub namespace: String,
    pub key_prefix: String,
    pub access: Vec<MemoryAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CodeAuthority {
    pub allowed_runtimes: Vec<String>,
    pub workspace: String,
    pub network: NetworkCapability,
    pub maximum_limits: ExecutionLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InputAuthority {
    pub allowed_sources: Vec<String>,
    pub maximum_classification: DataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceAuthority {
    pub current_story_only: bool,
    pub allowed_operations: Vec<OperationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactAuthority {
    pub path_prefix: WorkspaceRelativePath,
    pub allowed_formats: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetSnapshot {
    pub max_argument_bytes: u64,
    pub max_file_bytes: u64,
    pub max_network_bytes: u64,
    pub max_calls: u64,
    pub max_wall_time_ms: u64,
    pub max_model_calls: u64,
    pub max_model_input_bytes: u64,
    pub max_model_output_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetCharge {
    pub calls: u64,
    pub file_bytes: u64,
    pub network_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetUsageSnapshot {
    pub version: u64,
    pub calls_reserved: u64,
    pub calls_committed: u64,
    pub file_bytes_reserved: u64,
    pub file_bytes_committed: u64,
    pub network_bytes_reserved: u64,
    pub network_bytes_committed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthoritySnapshot {
    pub session_id: SessionId,
    pub actor_id: String,
    pub authz_id: String,
    pub authz_state: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    pub expires_at: OffsetDateTime,
    pub allowed_providers: Vec<String>,
    pub files: Vec<FileAuthority>,
    pub networks: Vec<NetworkAuthority>,
    pub email: Option<EmailAuthority>,
    pub stores: Vec<StoreAuthority>,
    pub code: Option<CodeAuthority>,
    pub inputs: Vec<InputAuthority>,
    pub evidence: EvidenceAuthority,
    pub artifacts: Vec<ArtifactAuthority>,
    pub budgets: BudgetSnapshot,
    pub policy_snapshot_hash: String,
}
```

`max_argument_bytes` and `max_wall_time_ms` are per-operation ceilings checked
against canonical argument length and the provider/claim execution timeout.
`max_calls`, `max_file_bytes`, and `max_network_bytes` are cumulative session
budgets represented by `BudgetUsageSnapshot` and atomically reserved in Plan 2.
The three `max_model_*` fields are separately reserved by the Plan 5 proxy
before upstream egress. This distinction is schema semantics and is covered by
boundary tests.

- [ ] **Step 4: Add the operation and story aggregate contracts**

After `resource.rs`, `session.rs`, and `trace.rs` exist, export them from
`crates/runwarden-kernel/src/lib.rs`:

```rust
pub mod resource;
pub mod session;
pub mod trace;
```

Extend `crates/runwarden-kernel/src/operation.rs` with:

```rust
use serde_json::Value;

use crate::artifact::WorkspaceRelativePath;
use crate::authority::ApprovalState;
use crate::resource::ResourceClaim;
use crate::story::{
    ApprovalId, ExecutionLeaseId, ObservationId, OperationId, SessionId,
    StoryId,
};
use crate::trace::Sha256Digest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckStatus { Passed, Failed, RequiresReview, NotEvaluated }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyCheck {
    pub check_id: String,
    pub layer: String,
    pub status: PolicyCheckStatus,
    pub reason: String,
    pub observation_ref: Option<ObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalView {
    pub approval_id: ApprovalId,
    pub state: ApprovalState,
    pub binding_digest: String,
    pub reviewer: Option<String>,
    pub reason: Option<String>,
    pub expires_at: Option<String>,
    pub lease_id: Option<ExecutionLeaseId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeArgumentView {
    File { path: WorkspaceRelativePath, content_hash: Option<Sha256Digest> },
    Email { recipients: Vec<String>, subject_hash: Sha256Digest, body_hash: Sha256Digest },
    Network { method: String, origin: String, body_hash: Option<Sha256Digest> },
    Store { namespace: String, key_hash: Sha256Digest, value_hash: Option<Sha256Digest> },
    Input { source: String, content_hash: Sha256Digest },
    Code { runtime: String, script_hash: Sha256Digest },
    Evidence { story_id: StoryId, operation_id: OperationId },
    Artifact { relative_path: WorkspaceRelativePath, format: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeProviderOutput {
    File { bytes: u64, content_hash: Sha256Digest },
    Email { receipt_hash: Sha256Digest },
    Network { status_code: u16, response_hash: Sha256Digest, bytes: u64 },
    Store { key_hash: Sha256Digest, version: u64 },
    Input { content_hash: Sha256Digest, risk_codes: Vec<String> },
    Code {
        exit_code: Option<i32>, stdout_hash: Sha256Digest, stderr_hash: Sha256Digest,
        output_bytes: u64, truncated: bool,
    },
    ExternalMcp { output_hash: Sha256Digest, bytes: u64 },
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderResultView {
    pub execution_status: ProviderExecutionStatus,
    pub output: SafeProviderOutput,
    pub output_hash: Option<Sha256Digest>,
    pub error_kind: Option<String>,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExecutionStatus {
    NotExecuted,
    Running,
    Completed,
    FailedBeforeSideEffect,
    ExecutedWithError,
    OutcomeUnknown,
    Simulated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SecurityOperation {
    pub operation_id: OperationId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub parent_model_call_id: Option<String>,
    pub proposed_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub resource_claim: ResourceClaim,
    pub argument_hash: Sha256Digest,
    pub arguments: SafeArgumentView,
    pub policy_snapshot_hash: Sha256Digest,
    pub state: OperationState,
    pub version: u64,
    pub policy_checks: Vec<PolicyCheck>,
    pub approval: Option<ApprovalView>,
    pub provider_result: Option<ProviderResultView>,
    pub side_effect_state: SideEffectState,
    pub observation_refs: Vec<ObservationId>,
}
```

Extend `crates/runwarden-kernel/src/story.rs` with:

```rust
use serde_json::Value;

use crate::contracts::PolicyDecision;
use crate::evidence::hex_sha256;
use crate::operation::{OperationState, SecurityOperation, SideEffectState};
use crate::session::AuthoritySnapshot;
use crate::trace::{StoryEventKind, canonical_json_v1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryStatus {
    Running,
    AwaitingApproval,
    BlockedBeforeSideEffect,
    CompletedWithControlledSideEffect,
    Failed,
    OutcomeUnknown,
    EvidenceInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryProvenance { Native, LegacyDerived }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryStage {
    Identity,
    Attack,
    Model,
    ProposedTool,
    Policy,
    Approval,
    Execution,
    Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoryStageStatus {
    pub stage: StoryStage,
    pub status: StageStatus,
    pub summary: String,
    pub observation_refs: Vec<ObservationId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus { Pending, Active, Completed, Blocked, Failed, Incomplete }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoryIdentity {
    pub agent_id: String,
    pub model_id: String,
    pub actor_id: String,
    pub reviewer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoryClaim {
    pub claim_id: String,
    pub text: String,
    pub observation_refs: Vec<ObservationId>,
    pub support_expectation: ReportClaimSupport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportClaimSupport {
    pub provider: Option<String>,
    pub event_kind: Option<StoryEventKind>,
    pub policy_decision: Option<PolicyDecision>,
    pub operation_state: Option<OperationState>,
    pub side_effect_state: Option<SideEffectState>,
    pub simulated: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SecurityStory {
    pub schema_version: SchemaVersion,
    pub story_id: StoryId,
    pub title: String,
    pub scenario_id: String,
    pub attack_category: String,
    pub run_mode: RunMode,
    pub enforcement_mode: EnforcementMode,
    pub provenance: StoryProvenance,
    pub status: StoryStatus,
    pub evidence_status: EvidenceStatus,
    pub identity: StoryIdentity,
    pub authority: AuthoritySnapshot,
    pub safe_attack_preview: String,
    pub attack_content_hash: String,
    pub stage_statuses: Vec<StoryStageStatus>,
    pub operations: Vec<SecurityOperation>,
    pub event_count: u64,
    pub report_claims: Vec<StoryClaim>,
    pub final_outcome_summary: String,
    pub final_event_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoryReplayFrame {
    pub sequence: u64,
    pub story_version: u64,
    pub event_hash: String,
    pub snapshot_hash: String,
    pub previous_frame_hash: Option<String>,
    pub frame_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    pub recorded_at: OffsetDateTime,
    pub story: SecurityStory,
}

impl StoryReplayFrame {
    pub fn seal(
        sequence: u64,
        story_version: u64,
        event_hash: String,
        previous_frame_hash: Option<String>,
        recorded_at: OffsetDateTime,
        story: SecurityStory,
    ) -> Result<Self, serde_json::Error> {
        let snapshot_hash = format!(
            "sha256:{}",
            hex_sha256(&canonical_json_v1(&serde_json::to_value(&story)?)),
        );
        let mut frame = Self {
            sequence, story_version, event_hash, snapshot_hash,
            previous_frame_hash, frame_hash: String::new(), recorded_at, story,
        };
        frame.frame_hash = frame.expected_hash()?;
        Ok(frame)
    }

    pub fn verify(&self) -> Result<(), String> {
        let snapshot = serde_json::to_value(&self.story).map_err(|e| e.to_string())?;
        let actual_snapshot = format!("sha256:{}", hex_sha256(&canonical_json_v1(&snapshot)));
        if actual_snapshot != self.snapshot_hash {
            return Err("replay snapshot hash mismatch".to_string());
        }
        if self.expected_hash().map_err(|e| e.to_string())? != self.frame_hash {
            return Err("replay frame hash mismatch".to_string());
        }
        Ok(())
    }

    fn expected_hash(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct FrameMaterial<'a> {
            sequence: u64,
            story_version: u64,
            event_hash: &'a str,
            snapshot_hash: &'a str,
            previous_frame_hash: Option<&'a str>,
            #[serde(with = "time::serde::rfc3339")]
            recorded_at: OffsetDateTime,
        }
        let material = FrameMaterial {
            sequence: self.sequence,
            story_version: self.story_version,
            event_hash: &self.event_hash,
            snapshot_hash: &self.snapshot_hash,
            previous_frame_hash: self.previous_frame_hash.as_deref(),
            recorded_at: self.recorded_at,
        };
        Ok(format!(
            "sha256:{}",
            hex_sha256(&canonical_json_v1(&serde_json::to_value(material)?)),
        ))
    }
}
```

Security Story v1 has no arbitrary `extensions` value and no embedded export
signature. Detached bundle signatures belong only to `manifest.sig`; embedding
one in the story would create a signature cycle and make the final replay frame
different from `story.json`. Apply `#[serde(deny_unknown_fields)]` to native v1
story/view structs so unknown fields cannot become an unreviewed export path.

`SecurityStory::schema_version` is a private-field validated `SchemaVersion`
newtype. Normal Rust writers use `SchemaVersion::current()` and therefore emit
`"1.0.0"`; deserialization and `TryFrom<String>` accept only canonical
three-component major-1 values such as `"1.1.0"`. Its `JsonSchema` and JSON wire
representation remain a string.

`SecurityStory` deliberately does not embed historical events. Events are read
through the ordered event API and exported in `events.jsonl`; each replay frame
contains the current aggregate only, preventing historical events from being
copied into every frame. `StoryReplayFrame::seal` recomputes `snapshot_hash`
from canonical story JSON and `frame_hash` from sequence, story version, event
hash, snapshot hash, previous frame hash, and RFC3339 timestamp.

`ReportClaimSupport` is an expectation, never a caller-supplied verdict. It
must contain at least one field. The assurance verifier resolves every typed
`ObservationId`, compares cited event semantics with every populated
expectation, and computes support; there is no serialized `supported` boolean
to trust.

- [ ] **Step 5: Add construction tests and run them**

Extend `story_contract.rs` with one fully populated `SecurityStory` fixture.
Assert these observable properties:

```rust
assert_eq!(story.schema_version.as_str(), "1.0.0");
assert_eq!(story.operations[0].resource_claim.digest(), claim_digest);
assert_eq!(story.operations[0].side_effect_state, SideEffectState::NotAttempted);
assert_eq!(story.evidence_status, EvidenceStatus::Pending);
assert!(serde_json::to_value(&story).unwrap().get("side_effect_executed").is_none());
```

Run:

```bash
cargo test -p runwarden-kernel --test resource_claims
cargo test -p runwarden-kernel --test story_contract
cargo test -p runwarden-kernel --test canonical_json_v1
```

Expected: all tests pass.

- [ ] **Step 6: Commit the aggregate contracts**

```bash
git add crates/runwarden-kernel
git commit -m "feat(kernel): define security story aggregate"
```

## Task 3: Define Redacted Story Events And Canonical Hash Vectors

**Files:**

- Modify: `crates/runwarden-kernel/src/trace.rs`
- Modify: `crates/runwarden-kernel/src/story.rs`
- Read: `crates/runwarden-kernel/tests/canonical_json_v1.rs`
- Create: `crates/runwarden-kernel/tests/story_hash_vectors.rs`
- Modify: `docs/reference/evidence-and-accountability.md`

**Interfaces:**

- Consumes the Task 2 `canonical_json_v1` implementation and produces
  `StoryEventPayload`, private-field `RedactedEventPayload`,
  `StoryEvent::seal`, and `StoryEvent::verify`.
- Guarantee: the event hash never commits private execution argument bytes
  except through `argument_hash`.

- [ ] **Step 1: Re-run the frozen canonical JSON vector**

Run `cargo test -p runwarden-kernel --test canonical_json_v1` before changing
`trace.rs`. Expected: pass. Do not change the vector or canonicalizer in this
task; this checkpoint only adds redaction and event sealing.

- [ ] **Step 2: Write the typed-payload, time, and chain tests**

Create `crates/runwarden-kernel/tests/story_hash_vectors.rs`:

```rust
use runwarden_kernel::story::{EventId, ObservationId, OperationId, SessionId, StoryId};
use runwarden_kernel::contracts::PolicyDecision;
use runwarden_kernel::trace::{EventCode, Sha256Digest, StoryEvent, StoryEventPayload};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

fn fixed_policy_event() -> StoryEvent {
    StoryEvent::seal(
        ObservationId::try_from("obs_01980a8c-0000-7000-8000-000000000005").unwrap(),
        EventId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000003").unwrap()).unwrap(),
        StoryId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000001").unwrap()).unwrap(),
        SessionId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000004").unwrap()).unwrap(),
        1,
        Some(OperationId::try_from(Uuid::parse_str("01980a8c-0000-7000-8000-000000000002").unwrap()).unwrap()),
        Some(EventCode::try_from("external.api.request".to_string()).unwrap()),
        StoryEventPayload::PolicyDecision {
            decision: PolicyDecision::Denied,
            reason_code: EventCode::try_from("egress_denied".to_string()).unwrap(),
            policy_snapshot_hash: Sha256Digest::try_from(
                format!("sha256:{}", "a".repeat(64))
            ).unwrap(),
        },
        None,
        OffsetDateTime::parse("2026-07-10T00:00:00Z", &Rfc3339).unwrap(),
    )
}

#[test]
fn payload_deserialization_rejects_unknown_or_raw_fields() {
    for invalid in [
        json!({"kind":"policy_decision","decision":"denied","prompt":"secret"}),
        json!({"kind":"policy_decision","decision":"denied","headers":{"x":"secret"}}),
        json!({"kind":"policy_decision","decision":"denied","extra":[{"query":"secret"}]}),
    ] {
        assert!(serde_json::from_value::<StoryEventPayload>(invalid).is_err());
    }
}

#[test]
fn sealed_event_uses_rfc3339_hash_material_and_detects_change() {
    let event = fixed_policy_event();
    assert!(event.verify().is_ok());
    assert_eq!(
        event.event_hash(),
        "sha256:6ef820788694fc3cbf998b9ece8460273c3736db792a703899f2a4c89449a42f"
    );

    let mut changed = serde_json::to_value(&event).unwrap();
    changed["payload"]["decision"] = json!("allowed");
    let changed: StoryEvent = serde_json::from_value(changed).unwrap();
    assert!(changed.verify().is_err());
}
```

Also add a `compile_fail` doctest proving external code cannot construct
`RedactedEventPayload(...)` or mutate its inner payload.

- [ ] **Step 3: Implement allowlisted payloads with no raw JSON constructor**

Extend `crates/runwarden-kernel/src/trace.rs`. Keep the already golden-tested
canonicalizer unchanged. Do not use a secret-key denylist: arbitrary input
objects never enter event payloads.

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::authority::ApprovalState;
use crate::contracts::PolicyDecision;
use crate::evidence::hex_sha256;
use crate::operation::SideEffectState;
use crate::story::{ApprovalId, EvidenceStatus, ObservationId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct EventCode(String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoryEventPayload {
    OperationProposed {
        provider: EventCode, action: EventCode,
        argument_hash: Sha256Digest, resource_claim_hash: Sha256Digest,
    },
    PolicyDecision {
        decision: PolicyDecision, reason_code: EventCode,
        policy_snapshot_hash: Sha256Digest,
    },
    ApprovalLifecycle {
        approval_id: ApprovalId, state: ApprovalState,
        reviewer_id_hash: Option<Sha256Digest>,
    },
    ProviderExecution {
        execution_status: EventCode, side_effect_state: SideEffectState,
        output_hash: Option<Sha256Digest>, receipt_hash: Option<Sha256Digest>,
    },
    ModelCall {
        model_call_id: EventCode, phase: EventCode, model_id: Option<EventCode>,
        content_hash: Sha256Digest, filter_state: Option<EventCode>,
        risk_codes: Vec<EventCode>, forwarded: Option<bool>,
        content_bytes: u64, proposal_count: Option<u64>,
    },
    ToolProposal {
        proposal_id: EventCode, upstream_tool_call_id: Option<EventCode>,
        provider: EventCode, action: EventCode, argument_hash: Sha256Digest,
    },
    CausalLink {
        proposal_id: Option<EventCode>, status: EventCode,
        reason_code: Option<EventCode>, candidate_count: u64,
    },
    EvidenceVerification {
        status: EvidenceStatus,
        error_codes: Vec<EventCode>,
        claim_count: u64,
        candidate_chain_head: Sha256Digest,
        candidate_story_version: u64,
        verifier_version: EventCode,
        event_chain_verified: bool,
        report_claims_verified: bool,
    },
    InputConsumed { asset_id: EventCode, content_hash: Sha256Digest },
    SandboxDecision {
        profile_hash: Sha256Digest, isolation_state: EventCode,
        reason_code: Option<EventCode>,
    },
    MonitorObservation {
        shadow_decision: PolicyDecision,
        baseline_disposition: EventCode,
        simulated_effect_hash: Option<Sha256Digest>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RedactedEventPayload(StoryEventPayload);
```

`EventCode::try_from` accepts only 1-128 ASCII letters, digits, dot, colon,
slash, at-sign, underscore, and hyphen. `Sha256Digest::try_from` accepts exactly
`sha256:` plus 64 lowercase hexadecimal characters. Both inner fields are
private and custom `Deserialize` calls the same validator. The typed payload
enum has no `serde_json::Value`, content/body/prompt/query/header field, or
free-form reviewer reason. `RedactedEventPayload::from_typed` is crate-visible
to the event constructor; there is no public raw-value constructor.

- [ ] **Step 4: Implement the complete story event envelope**

Append to `trace.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryEvent {
    pub obs_id: ObservationId,
    pub event_id: EventId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub sequence: u64,
    pub operation_id: Option<OperationId>,
    pub event_type: StoryEventKind,
    pub provider: Option<EventCode>,
    payload: RedactedEventPayload,
    pub previous_hash: Option<Sha256Digest>,
    event_hash: Sha256Digest,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    pub recorded_at: OffsetDateTime,
}

impl StoryEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        obs_id: ObservationId,
        event_id: EventId,
        story_id: StoryId,
        session_id: SessionId,
        sequence: u64,
        operation_id: Option<OperationId>,
        provider: Option<EventCode>,
        payload: StoryEventPayload,
        previous_hash: Option<Sha256Digest>,
        recorded_at: OffsetDateTime,
    ) -> Self {
        let mut event = Self {
            obs_id,
            event_id,
            story_id,
            session_id,
            sequence,
            operation_id,
            event_type: payload.kind(),
            provider,
            payload: RedactedEventPayload(payload),
            previous_hash,
            event_hash: Sha256Digest::zero_for_construction(),
            recorded_at,
        };
        event.event_hash = event.expected_hash();
        event
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.event_type != self.payload.0.kind() {
            Err("event type does not match typed payload kind".to_string())
        } else if self.event_hash == self.expected_hash() {
            Ok(())
        } else {
            Err("event hash does not match canonical event material".to_string())
        }
    }

    pub fn event_hash(&self) -> &str { self.event_hash.as_str() }
    pub fn payload(&self) -> &StoryEventPayload { &self.payload.0 }

    fn expected_hash(&self) -> Sha256Digest {
        #[derive(Serialize)]
        struct CanonicalEventMaterial<'a> {
            obs_id: &'a ObservationId,
            event_id: &'a EventId,
            story_id: &'a StoryId,
            session_id: &'a SessionId,
            sequence: u64,
            operation_id: Option<&'a OperationId>,
            event_type: StoryEventKind,
            provider: Option<&'a EventCode>,
            payload: &'a RedactedEventPayload,
            previous_hash: Option<&'a Sha256Digest>,
            #[serde(with = "time::serde::rfc3339")]
            recorded_at: OffsetDateTime,
        }
        let material = CanonicalEventMaterial {
            obs_id: &self.obs_id, event_id: &self.event_id,
            story_id: &self.story_id, session_id: &self.session_id,
            sequence: self.sequence, operation_id: self.operation_id.as_ref(),
            event_type: self.event_type, provider: self.provider.as_ref(),
            payload: &self.payload, previous_hash: self.previous_hash.as_ref(),
            recorded_at: self.recorded_at,
        };
        Sha256Digest::from_bytes(&canonical_json_v1(
            &serde_json::to_value(material).expect("event material serializes")
        ))
    }
}
```

Implement `StoryEventPayload::kind` as an exhaustive match. The dedicated
`CanonicalEventMaterial` is the only hash input and its RFC3339 field adapter
guarantees the hash bytes match exported JSON regardless of `time` crate
human-readable feature flags. `zero_for_construction` is `pub(crate)` and the
event replaces it before returning; deserialization still validates ordinary
digests. The event envelope rejects unknown fields, and `verify` rejects an
`event_type` that differs from the exhaustive typed payload kind even when a
caller has recomputed a matching canonical hash.

Add the shared evidence transfer model to `story.rs` after `StoryEvent` exists:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryEvidenceView {
    pub story: SecurityStory,
    pub events: Vec<StoryEvent>,
    pub replay_frames: Vec<StoryReplayFrame>,
}
```

`StoryEvidenceView::verify_structure` requires matching story/session ids,
contiguous event and frame sequences, one frame per event, matching event/frame
hashes, a valid event chain and frame chain, `story.event_count` equality, each
frame aggregate's `story.event_count` equal to its frame sequence, each frame
aggregate's `final_event_hash` equal to that frame's event hash, and the final
frame story exactly equal to `story`. It also requires
`story.final_event_hash=None` for an empty chain and an exact match to the last
sealed event hash for a non-empty chain. Assurance, bundles, scenario
evaluation, API bootstrap, and WebUI sources consume this view instead of
putting events back inside every snapshot.

- [ ] **Step 5: Run tests and document the evidence boundary**

Run:

```bash
cargo test -p runwarden-kernel --test story_hash_vectors
```

Expected: all tests pass.

Update `docs/reference/evidence-and-accountability.md` to state that full
arguments are private operation material, story events are redacted before
hashing, and export verifies the same unmodified event hashes.

- [ ] **Step 6: Commit the event contract**

```bash
git add crates/runwarden-kernel docs/reference/evidence-and-accountability.md
git commit -m "feat(kernel): seal redacted story events"
```

## Task 4: Generate And Drift-Test Story Schemas

**Files:**

- Modify: `crates/runwarden-kernel/examples/generate_schemas.rs`
- Modify: `crates/runwarden-kernel/tests/contract_schemas.rs`
- Create: `schemas/security-story.schema.json`
- Create: `schemas/security-operation.schema.json`
- Create: `schemas/story-event.schema.json`
- Create: `schemas/resource-claim.schema.json`
- Create: `schemas/authority-snapshot.schema.json`
- Create: `schemas/story-bundle-manifest.schema.json`
- Create: `schemas/story-replay-frame.schema.json`
- Create: `schemas/story-evidence-view.schema.json`
- Create: `crates/runwarden-kernel/src/bundle.rs`
- Modify: `docs/reference/json-contracts.md`

**Interfaces:**

- Produces checked-in schemas consumed by Plan 7's TypeScript generator and
  the frozen bundle manifest consumed by Plan 6.
- Preserves the existing schema generation command.

- [ ] **Step 1: Write failing schema drift assertions**

Add imports and assertions in `contract_schemas.rs`:

```rust
use runwarden_kernel::operation::SecurityOperation;
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::session::AuthoritySnapshot;
use runwarden_kernel::story::SecurityStory;
use runwarden_kernel::trace::StoryEvent;
use runwarden_kernel::bundle::StoryBundleManifest;
use runwarden_kernel::story::StoryReplayFrame;
use runwarden_kernel::story::StoryEvidenceView;

assert_schema_file_matches(
    &root,
    "security-story.schema.json",
    serde_json::to_value(schema_for!(SecurityStory)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "security-operation.schema.json",
    serde_json::to_value(schema_for!(SecurityOperation)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "story-event.schema.json",
    serde_json::to_value(schema_for!(StoryEvent)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "resource-claim.schema.json",
    serde_json::to_value(schema_for!(ResourceClaim)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "authority-snapshot.schema.json",
    serde_json::to_value(schema_for!(AuthoritySnapshot)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "story-bundle-manifest.schema.json",
    serde_json::to_value(schema_for!(StoryBundleManifest)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "story-replay-frame.schema.json",
    serde_json::to_value(schema_for!(StoryReplayFrame)).unwrap(),
);
assert_schema_file_matches(
    &root,
    "story-evidence-view.schema.json",
    serde_json::to_value(schema_for!(StoryEvidenceView)).unwrap(),
);
```

- [ ] **Step 2: Verify the schema test fails**

```bash
cargo test -p runwarden-kernel --test contract_schemas checked_in_schema_artifacts_match_rust_contracts
```

Expected: failure reports the first missing story or bundle schema.

- [ ] **Step 3: Freeze the detached-signature manifest**

Create `bundle.rs` with `BundleFileDigest`, `BundleVerificationSummary`, and
`StoryBundleManifest`. The manifest fields are schema version, bundle/story id,
story version, run mode, scenario, created time, git SHA/dirty state, chain
head, signature algorithm, key id, sorted payload files, and verification
summary. `signature_material()` sorts files by relative path and returns
Runwarden Canonical JSON v1 bytes. Payload paths reject absolute paths, parent
traversal, empty components, and platform prefixes.

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::WorkspaceRelativePath;
use crate::story::{EvidenceStatus, RunMode, StoryId};
use crate::trace::{Sha256Digest, canonical_json_v1};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BundleFileDigest {
    relative_path: WorkspaceRelativePath,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}

impl BundleFileDigest {
    pub fn new(
        relative_path: impl Into<String>,
        bytes: u64,
        sha256: impl Into<String>,
    ) -> Result<Self, String> {
        let relative_path = WorkspaceRelativePath::try_from(relative_path.into())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            relative_path,
            bytes,
            sha256: Sha256Digest::try_from(sha256.into())?,
        })
    }

    pub fn relative_path(&self) -> &WorkspaceRelativePath { &self.relative_path }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BundleVerificationSummary {
    pub event_chain_verified: bool,
    pub report_claims_verified: bool,
    pub scenario_assertions_verified: Option<bool>,
    pub evidence_status: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoryBundleManifest {
    pub schema_version: String,
    pub bundle_id: String,
    pub story_id: StoryId,
    pub story_version: u64,
    pub run_mode: RunMode,
    pub scenario_id: String,
    pub created_at: String,
    pub git_sha: String,
    pub source_dirty: bool,
    pub chain_head: Sha256Digest,
    pub final_frame_hash: Sha256Digest,
    pub signature_algorithm: String,
    pub key_id: String,
    pub files: Vec<BundleFileDigest>,
    pub verification: BundleVerificationSummary,
}

impl StoryBundleManifest {
    pub fn signature_material(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut normalized = self.clone();
        normalized
            .files
            .sort_by(|left, right| left.relative_path.as_str().cmp(right.relative_path.as_str()));
        let value = serde_json::to_value(normalized)?;
        Ok(canonical_json_v1(&value))
    }
}
```

`scenario_assertions_verified` is `None` for a story-only bundle. It may be
`Some(true)` only when the signed scenario assertion, evaluation, and input
manifest extensions exist and a Rust verifier recomputes them; Plan 8 adds
that verifier. `Some(false)` is never exportable as verified evidence.

Export the module from `lib.rs` with `pub mod bundle;`.

- [ ] **Step 4: Extend the generator and regenerate**

Add seven `write_schema` calls to `generate_schemas.rs` using the exact file
names above, then run:

```bash
cargo run -p runwarden-kernel --example generate_schemas
cargo test -p runwarden-kernel --test contract_schemas
```

Expected: schema files are generated and the drift test passes.

- [ ] **Step 5: Document and commit the schema surface**

Update `docs/reference/json-contracts.md` with schema version `1.0.0`, accepted
major version `1`, and the seven generated files.

```bash
git add crates/runwarden-kernel schemas docs/reference/json-contracts.md
git commit -m "feat(contracts): publish security story schemas"
```

## Task 5: Add The Honest Legacy Story Adapter

**Files:**

- Create: `crates/runwarden-cli/src/story/mod.rs`
- Create: `crates/runwarden-cli/src/story/legacy.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Test: `crates/runwarden-cli/tests/legacy_story_adapter.rs`
- Create: `docs/reference/security-story.md`
- Modify: `docs/reference/webui-review-console.md`
- Modify: `docs/reference/authority-and-session.md`
- Modify: `docs/README.md`

**Interfaces:**

- Produces: `LegacyStoryContext` and `adapt_legacy_webui`.
- Guarantee: legacy conversion never emits `EvidenceStatus::Verified`.
- Guarantee: legacy provider arguments are redacted before entering a
  `StoryEvent` or `SecurityOperation` view.

- [ ] **Step 1: Write a failing five-scenario adapter test**

Create `legacy_story_adapter.rs`. Loop over the existing five scenario ids,
load `artifacts` through the same fixture-building helper used by the demo,
and assert:

```rust
assert_eq!(story.schema_version.as_str(), "1.0.0");
assert_eq!(story.provenance, StoryProvenance::LegacyDerived);
assert_eq!(story.evidence_status, EvidenceStatus::Incomplete);
assert!(!story.operations.is_empty());
assert_eq!(story.stage_statuses.len(), 8);
assert!(!serde_json::to_string(&story).unwrap().contains("secret-raw-marker"));
```

Also assert that `prompt-injection-file-exfil` includes an attack preview and
at least one blocked or review-held operation.

- [ ] **Step 2: Run the test and verify it fails**

```bash
cargo test -p runwarden-cli --test legacy_story_adapter
```

Expected: compilation fails because the story adapter module does not exist.

- [ ] **Step 3: Implement the adapter context and conversion rules**

Create `crates/runwarden-cli/src/story/mod.rs`:

```rust
mod legacy;

pub use legacy::{LegacyStoryContext, adapt_legacy_webui};
```

Create `legacy.rs` with this public context:

```rust
use anyhow::{Context, Result};
use runwarden_kernel::operation::{
    OperationState, SecurityOperation, SideEffectState,
};
use runwarden_kernel::resource::ResourceClaim;
use runwarden_kernel::session::AuthoritySnapshot;
use runwarden_kernel::story::{
    EnforcementMode, EvidenceStatus, RunMode, SchemaVersion, SecurityStory,
    StoryId, StoryProvenance, StoryStatus,
};
use serde_json::Value;

pub struct LegacyStoryContext {
    pub title: String,
    pub scenario_id: String,
    pub attack_category: String,
    pub safe_attack_preview: String,
    pub attack_content_hash: String,
    pub authority: AuthoritySnapshot,
}

pub fn adapt_legacy_webui(
    input: &Value,
    context: LegacyStoryContext,
) -> Result<SecurityStory> {
    let calls = input
        .get("provider_calls")
        .and_then(Value::as_array)
        .context("legacy webui provider_calls must be an array")?;
    let story_id = StoryId::new();
    let operations = calls
        .iter()
        .map(|call| adapt_operation(story_id, context.authority.session_id, call))
        .collect::<Result<Vec<_>>>()?;
    let status = derive_story_status(&operations);
    Ok(SecurityStory {
        schema_version: SchemaVersion::current(),
        story_id,
        title: context.title,
        scenario_id: context.scenario_id,
        attack_category: context.attack_category,
        run_mode: RunMode::Recorded,
        enforcement_mode: EnforcementMode::Enforced,
        provenance: StoryProvenance::LegacyDerived,
        status,
        evidence_status: EvidenceStatus::Incomplete,
        identity: legacy_identity(input),
        authority: context.authority,
        safe_attack_preview: context.safe_attack_preview,
        attack_content_hash: context.attack_content_hash,
        stage_statuses: legacy_stage_statuses(input, &operations),
        operations,
        event_count: 0,
        report_claims: legacy_report_claims(input),
        final_outcome_summary: legacy_outcome_summary(input),
        final_event_hash: None,
    })
}
```

The adapter does not manufacture native `StoryEvent` or `ObservationId`
records from fixture JSON. Legacy status summaries and claims remain visibly
incomplete and carry no support refs; only the native journal can mint
hash-chained observations.

Implement the private helpers named above in the same file. `adapt_operation`
must map `decision=denied` to `OperationState::Denied` and
`SideEffectState::BlockedBeforeExecution`, map `requires_review` to
`OperationState::AwaitingApproval` and `NotAttempted`, and map a genuinely
completed legacy local side effect to `Completed`. Every resource is
`ResourceClaim::OpaqueLegacy`; later execution paths reject that variant.

- [ ] **Step 4: Route static demo story output through the adapter**

Add `mod story;` in `main.rs`. After the current `webui.json` is generated,
build `LegacyStoryContext`, call `adapt_legacy_webui`, and write a sibling
`story.json`. Keep the old files through Plan 12.

Use `resolve_workspace_relative_path` for the output directory. Do not add an
agent-facing tool or accept authority fields from scenario provider arguments.

- [ ] **Step 5: Run adapter and regression tests**

```bash
cargo test -p runwarden-cli --test legacy_story_adapter
cargo test -p runwarden-cli --test contest_workflow
cargo test -p runwarden-kernel --test contract_schemas
```

Expected: all tests pass and each generated scenario directory contains both
`webui.json` and `story.json`.

- [ ] **Step 6: Update references and commit**

Create `docs/reference/security-story.md` documenting:

- schema version and compatibility;
- authoritative enums;
- redacted event/private argument split;
- `Native` versus `LegacyDerived` provenance;
- why legacy stories remain `Incomplete`.

Update the other listed reference pages and add Security Story to
`docs/README.md`.

```bash
git add crates/runwarden-cli docs
git commit -m "feat(cli): adapt legacy demos into security stories"
```

## Task 6: Run The Plan-Wide Contract Gate

**Files:**

- Verify only; fix failures in files changed by Tasks 1-5.

**Interfaces:**

- Certifies the contract freeze required by every later plan.

- [ ] **Step 1: Regenerate schemas and require a clean diff**

```bash
cargo run -p runwarden-kernel --example generate_schemas
git diff --exit-code -- schemas
```

Expected: no diff.

- [ ] **Step 2: Run all repository gates**

```bash
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all commands exit zero.

- [ ] **Step 3: Inspect the contract-only diff**

```bash
git status --short
git diff --stat HEAD~5..HEAD
```

Expected: changes are limited to the new Rust story contract, schemas, legacy
adapter, tests, and matching documentation. No MCP/provider behavior or WebUI
framework is introduced in this plan.

- [ ] **Step 4: Record the merge checkpoint**

Tag or record the merge commit as the only allowed base for Plans 2, 3, 5,
6, and the static portion of Plan 7. Any incompatible contract edit after this
point requires a schema-major-version review.
