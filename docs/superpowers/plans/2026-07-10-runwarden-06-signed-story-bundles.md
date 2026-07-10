# Signed Story Bundles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export one portable, redacted story snapshot whose files, event chain, report claims, provenance, and signing key identity are verified by Rust before replay.

**Architecture:** The exporter reads one versioned terminal story snapshot, verifies event/report semantics, writes only an allowlisted relative-path bundle, signs canonical `manifest.json` with an owner-only workspace Ed25519 key, and writes detached `manifest.sig`. The verifier rejects path tricks, missing/extra files, checksum changes, signature changes, chain failures, unsupported schemas, and unsupported report claims before returning a replay model.

**Tech Stack:** Rust 1.95.0, `ed25519-dalek` 3.0.0, SHA-256, PKCS#8/PEM, Runwarden Canonical JSON v1, existing assurance report lint.

**Prerequisite:** Plans 1-5 are merged. In particular, model/MCP transcript
views are produced by Plan 5; this plan does not invent empty transcript
evidence to run early.

## Global Constraints

- Signing protects export integrity/provenance after finalization; it does not
  claim protection when the host and signing key are compromised.
- The private key is generated once per contest workspace, stored outside
  exported artifacts, and mode `0600` on Unix.
- Bundle paths are relative, normalized, allowlisted, and free of symlinks.
- `manifest.json` never lists itself, `manifest.sig`, `public-key.pem`, or
  `SHA256SUMS` as payload entries. `SHA256SUMS` covers every file except itself.
- `manifest.sig` signs the exact canonical bytes of `manifest.json`.
- The story event chain is exported unchanged; redaction happened before event
  hashing in Plan 1.
- Full arguments, state database, WAL files, private transcripts, reviewer
  nonce, active-instance token, and signing key are never exported.
- Verification failure yields a read-only `EvidenceStatus::Invalid` result,
  not a partially trusted story.

---

## File Responsibility Map

- Plan 1 creates `runwarden-kernel/src/bundle.rs` and the manifest schema.
- Create `runwarden-assurance/src/story_verify.rs`: event/story/report semantic
  verification.
- Create `runwarden-assurance/src/bundle.rs`: pure bundle verification model.
- Create `runwarden-cli/src/export/{mod,keys,manifest,story_bundle,verify}.rs`.
- Create `runwarden-cli/src/commands/bundle.rs`: `bundle export` and
  `bundle verify` CLI surfaces.
- Extend Plan 4 reviewer API with versioned story export POST.

### Frozen Bundle Layout

```text
story.json
events.jsonl
replay-frames.jsonl
report.json
report.md
model-transcript.jsonl
mcp-transcript.jsonl
environment-manifest.json
public-key.pem
manifest.json
manifest.sig
SHA256SUMS
```

This is the required base layout. The path allowlist reserves these optional
extensions for later plans: `reviewer-console.html` (Plan 7), and
`scenario-inputs-manifest.json`, `scenario-assertions.json`, and
`scenario-evaluation.json` (Plan 8). Unknown files remain forbidden. The base
export in this plan writes none of the optional extensions.

## Task 1: Lock The Plan 1 Bundle Contract With Signature Vectors

**Files:**

- Read: `crates/runwarden-kernel/src/bundle.rs`
- Read: `schemas/story-bundle-manifest.schema.json`
- Test: `crates/runwarden-kernel/tests/bundle_contract.rs`
- Modify: `docs/reference/json-contracts.md`

**Interfaces:**

- Consumes the Plan 1 `StoryBundleManifest`, `BundleFileDigest`,
  `BundleVerificationSummary`, and `signature_material()` without redefining
  them.

- [ ] **Step 1: Write failing manifest canonicalization tests**

Assert that payload file order does not change signature material and that
unsafe paths are rejected:

```rust
let first = manifest_fixture(vec![file("story.json"), file("events.jsonl")]);
let second = manifest_fixture(vec![file("events.jsonl"), file("story.json")]);
assert_eq!(first.signature_material().unwrap(), second.signature_material().unwrap());
let valid_digest = format!("sha256:{}", "0".repeat(64));
assert!(BundleFileDigest::new("../secret", 1, valid_digest.clone()).is_err());
assert!(BundleFileDigest::new("/tmp/story.json", 1, valid_digest).is_err());
```

- [ ] **Step 2: Verify the frozen manifest fields**

Do not copy the structs into this plan or crate. Import them from
`runwarden_kernel::bundle` and construct a compile-time fixture that includes
Plan 1's private-field `WorkspaceRelativePath`, typed SHA-256 digests,
`final_frame_hash`, and optional scenario verification field. Deserialize
unsafe paths and malformed digests through the real public types and require
failure. Assert `signature_material()` sorts through the validated path
accessor and includes every frozen field. If this test stops compiling, resolve
the Plan 1 schema-version conflict instead of introducing a local DTO.

This plan's story-only exporter sets `scenario_assertions_verified=None`.
Until Plan 8 installs the scenario extension verifier, the bundle verifier
rejects `Some(true)` and rejects any of the three scenario extension files;
it never trusts the summary flag by itself.

- [ ] **Step 3: Drift-test the existing schema**

```bash
cargo run -p runwarden-kernel --example generate_schemas
cargo test -p runwarden-kernel --test bundle_contract
cargo test -p runwarden-kernel --test contract_schemas
```

Expected: all pass and the checked-in Plan 1 schema is stable.

- [ ] **Step 4: Commit the contract**

```bash
git add crates/runwarden-kernel/tests/bundle_contract.rs docs/reference/json-contracts.md
git commit -m "test(contracts): lock story bundle signature material"
```

## Task 2: Verify Native Story And Report Semantics Before Export

**Files:**

- Create: `crates/runwarden-assurance/src/story_verify.rs`
- Create: `crates/runwarden-kernel/src/evidence_payload.rs`
- Create: `schemas/model-transcript-record.schema.json`
- Create: `schemas/mcp-transcript-record.schema.json`
- Create: `schemas/environment-manifest.schema.json`
- Modify: `crates/runwarden-assurance/src/lib.rs`
- Modify: `crates/runwarden-state/src/stories.rs`
- Modify: `crates/runwarden-state/src/snapshots.rs`
- Modify: `crates/runwarden-state/Cargo.toml`
- Test: `crates/runwarden-assurance/tests/story_verify.rs`

**Interfaces:**

- Produces: `verify_story_evidence(&StoryEvidenceView, VerificationMode) -> StoryVerification`.
- Consumes: existing claim-to-`obs_*` support logic.

- [ ] **Step 1: Write failing evidence-gap tests**

Cover valid chain, missing sequence, changed previous hash, unsupported claim,
favorable terminal status with incomplete evidence, and `OutcomeUnknown`
misreported as blocked. Assert:

```rust
assert!(valid.verified);
assert!(!missing_event.verified);
assert!(missing_event.errors.iter().any(|error| error.code == "event_sequence_gap"));
assert!(!unknown_claim.verified);
```

- [ ] **Step 2: Define verification output**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    CandidateFinalization,
    Final,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoryVerificationError {
    pub code: String,
    pub message: String,
    pub observation_refs: Vec<ObservationId>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoryVerification {
    pub verified: bool,
    pub event_chain_verified: bool,
    pub report_claims_verified: bool,
    pub errors: Vec<StoryVerificationError>,
    pub chain_head: Option<Sha256Digest>,
    pub final_frame_hash: Option<Sha256Digest>,
}
```

`CandidateFinalization` requires a terminal story with
`EvidenceStatus::Pending`, verifies all evidence/claims through the current
chain head, and does not require an `EvidenceVerification` event.
`Final` requires `EvidenceStatus::Verified` and a final
`EvidenceVerification` event whose payload commits the candidate chain head,
candidate story version, verifier version, and successful claim/chain results.
No other difference is permitted between the modes.

- [ ] **Step 3: Implement complete verification**

Verify schema major, story/event ids, contiguous sequence, story/session
consistency, previous/event hashes, operation observation references, terminal
state/side-effect consistency, evidence status, and every report claim against
the cited event semantics. A legacy-derived story may be integrity-valid but
its overall `verified` stays false because evidence is incomplete.

Define deny-unknown, no-raw-content Rust payloads for
`RedactedModelTranscriptRecord`, `RedactedMcpTranscriptRecord`, and
`EnvironmentManifest`. They contain typed ids, `ObservationId` refs, provider/
model codes, statuses, counts, versions, and SHA-256 commitments only—never
prompt/completion/argument/output text. Verify each transcript row maps to a
matching typed story event and each environment input digest maps to an
`InputConsumed` event. Generate and drift-test all three schemas.

P6 owns the redacted payload types and snapshot builders. In the same SQLite
read transaction as `StoryEvidenceView`, `StateStore::story_export_payloads`
derives the model transcript from P5 model/proposal rows plus typed events, the
MCP transcript from P4 operations/causal links plus typed events, and the
environment manifest from session/policy/catalog/input commitments. It returns
one `StoryExportPayloads { evidence, report, model_transcript,
mcp_transcript, environment, story_version }`. P4/P5 provide authoritative
rows; neither fabricates or separately serializes an export transcript.

Add `StateStore::verify_and_finalize_story(story_id, expected_version)`. The
state crate depends one-way on `runwarden-assurance` in this plan. Inside one
`BEGIN IMMEDIATE` transaction it loads `StoryEvidenceView`, runs candidate
verification with `VerificationMode::CandidateFinalization`, appends a typed
`EvidenceVerification` event committing the candidate result, updates
`EvidenceStatus::Verified`, advances story version/frame, reruns final
verification with `VerificationMode::Final` over the resulting view, and
commits only when final verification passes. No exporter can set `Verified`
directly. Version conflict or any
semantic error rolls back the status and event.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-assurance --test story_verify
git add crates/runwarden-assurance
git commit -m "feat(assurance): verify complete security stories"
```

## Task 3: Generate And Protect The Workspace Signing Key

**Files:**

- Modify: `Cargo.toml`
- Modify: `crates/runwarden-cli/Cargo.toml`
- Create: `crates/runwarden-cli/src/export/keys.rs`
- Test: `crates/runwarden-cli/tests/signing_key.rs`

**Interfaces:**

- Produces: `WorkspaceSigningKey::load_or_generate` and public key id.

- [ ] **Step 1: Add exact cryptographic dependencies**

Add workspace dependencies:

```toml
ed25519-dalek = { version = "3.0.0", features = ["pkcs8", "pem", "signature"] }
getrandom = "0.4.3"
cap-std = "4.0.2"
cap-fs-ext = "4.0.2"
rustix = "1.1.4"
```

Add all to `runwarden-cli`, with `rustix` features/platform gating sufficient
for no-follow metadata, advisory file locking, fsync, and no-replace rename.
Task 3 owns this capability-filesystem dependency checkpoint; Task 4 reuses it.

- [ ] **Step 2: Write key lifecycle tests**

Assert first load creates one key, second load returns the same key id, public
PEM parses, and on Unix `keys/story-signing.pk8` is mode `0600`. Assert no key
file is created inside an export directory. Spawn 32 processes against one
empty state root and require one final key id with no partial reads. Inject a
crash after temp-file fsync and before publish, then require the next process to
recover safely. Reject final/temp symlinks, hardlinks, non-regular files,
wrong-owner files, permissive modes, oversized PEM, and malformed keys.

- [ ] **Step 3: Implement generation without RNG trait-version coupling**

Fill a `[u8; 32]` with `getrandom::fill`, construct
`ed25519_dalek::SigningKey::from_bytes`, encode private PKCS#8 PEM, create the
file with owner-only permissions, fsync, and zero the seed buffer after use.
Calculate `key_id` as the first 32 lowercase hexadecimal characters of
SHA-256 over the exact 32 `verifying_key().to_bytes()` bytes. Freeze:

```rust
assert_eq!(
    derive_key_id(&[0_u8; 32]),
    "66687aadf862bd776c8fc18b8e9f8e20"
);
```

Also assert length 32, lowercase encoding, and that changing one public-key
byte changes the id. `getrandom::fill(&mut [u8; 32])` failure aborts key
creation; no weak fallback exists.

Open trusted state/keys directories through capability handles and acquire an
exclusive cross-process `story-signing.lock` before inspecting or creating the
key. Under the lock, load the final file with no-follow, require one link,
regular-file/current-owner/mode-0600/size bounds, and parse it before use. For a
missing key, write a random-name mode-0600 `create_new` temp in the same
directory, fsync the file, publish with no-replace rename, and fsync the
directory. If another valid final key won the race, securely discard the temp
and load the winner; never overwrite or rotate automatically. On startup, the
lock holder may remove only validated stale temp names after no-follow
inspection. A crash can leave a temp file but can never expose a partial final
key.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-cli --test signing_key
git add Cargo.toml Cargo.lock crates/runwarden-cli
git commit -m "feat(export): manage workspace Ed25519 keys"
```

## Task 4: Export An Allowlisted Story Bundle

**Files:**

- Create: `crates/runwarden-cli/src/export/mod.rs`
- Create: `crates/runwarden-cli/src/export/manifest.rs`
- Create: `crates/runwarden-cli/src/export/story_bundle.rs`
- Create: `crates/runwarden-cli/src/commands/bundle.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Modify: `crates/runwarden-state/src/snapshots.rs`
- Test: `crates/runwarden-cli/tests/story_bundle.rs`
- Test: `crates/runwarden-cli/tests/bundle_path_safety.rs`

**Interfaces:**

- Produces: `runwarden bundle export --story-id --output --expected-version`.
- Requires terminal story and an atomic snapshot at the expected version.

Reuse the capability and platform dependencies added by Task 3 in the CLI
export implementation; do not add a second filesystem abstraction.

- [ ] **Step 1: Write a bundle layout and leak test**

Export a native story containing private marker `secret-raw-marker`. Assert the
exact base layout exists, no extra path exists, every manifest path is safe,
and recursive file search finds no marker. Add concurrent symlink-swap,
hardlink, special-file, existing-target, and root-replacement attackers; all
must fail without writing outside the capability root or replacing a target.

- [ ] **Step 2: Implement a versioned export snapshot**

First call `verify_and_finalize_story`, then open a SQLite read transaction,
verify the new story version and terminal state, and call the single
`story_export_payloads` builder frozen in Task 2. Run
`verify_story_evidence(&payloads.evidence, VerificationMode::Final)` and verify
every transcript/environment cross-reference. Require manifest chain head and
final frame hash to equal that same transaction's view. Abort before filesystem writes on version conflict
or verification failure, except an explicit
`--allow-incomplete-legacy` development flag that still marks evidence
incomplete.

- [ ] **Step 3: Write payloads into a private staging directory**

Open the trusted workspace root once as `cap_std::fs::Dir`; after this boundary
never call ambient `std::fs` or path `canonicalize`. Validate
`WorkspaceRelativePath`, walk parents with
`cap_fs_ext::DirExt::open_dir_nofollow`, create a random sibling staging
directory mode `0700`, and create every file with capability-relative
`OpenOptions::create_new`. Reject symlink/hardlink/special-file entries. Use
compact JSONL for events/transcripts and rendered Markdown from the verified
report object.

- [ ] **Step 4: Build manifest, sign, checksums, and atomically publish**

1. insert an `exports.state=preparing` row with output/staging names and
   expected story version before filesystem writes;
2. hash and size payload files;
3. create sorted `StoryBundleManifest`;
4. write exact canonical bytes as `manifest.json`;
5. sign those bytes into base64 `manifest.sig`;
6. write `public-key.pem`;
7. hash every file except `SHA256SUMS` and write sorted checksum lines;
8. fsync each file and staging directory, then transactionally mark the export
   `ready_to_publish` with manifest/chain/frame hashes;
9. publish without replacement: Linux uses descriptor-relative
   `renameat2(RENAME_NOREPLACE)`, macOS uses `renamex_np(RENAME_EXCL)`, and
   Windows uses a no-replace move. Unsupported semantics fail closed;
10. fsync the parent directory and mark the row `finalized`.

Startup recovery inspects non-final rows. It deletes incomplete private staging
for `preparing`; for `ready_to_publish`, it either completes a verified
published directory, retries no-replace publish, or marks failed/quarantines a
mismatch. It never overwrites an existing destination. This journal protocol
handles the unavoidable SQLite/filesystem crash gap explicitly.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-cli --test story_bundle
cargo test -p runwarden-cli --test bundle_path_safety
git add crates/runwarden-cli crates/runwarden-state
git commit -m "feat(export): create signed story bundles"
```

## Task 5: Implement Rust Bundle Verification And Tamper Tests

**Files:**

- Create: `crates/runwarden-assurance/src/bundle.rs`
- Create: `crates/runwarden-cli/src/export/verify.rs`
- Test: `crates/runwarden-assurance/tests/story_bundle_verify.rs`
- Test: `crates/runwarden-cli/tests/bundle_tamper.rs`

**Interfaces:**

- Produces: `verify_story_bundle(path, expected_key_id)` and CLI
  `runwarden bundle verify`.

- [ ] **Step 1: Write a tamper matrix**

Generate one valid bundle, copy it for each mutation, and independently change:

- one story byte;
- one event payload;
- event order;
- report observation ref;
- manifest file digest;
- detached signature;
- public key;
- schema major;
- environment digest;
- non-canonical whitespace or key order in `manifest.json` with recomputed
  `SHA256SUMS`;
- `report.md` without changing `report.json`;
- transcript row/event-reference mismatch;
- intermediate replay frame or manifest final-frame hash;
- add an unlisted file;
- replace a payload with a symlink, hardlink, or special file;
- exceed file-count, per-file, total-byte, JSON-depth, or JSONL-line limits.

Every case must fail with a stable error code.

- [ ] **Step 2: Define verification results**

```rust
pub struct VerifiedStoryBundle {
    pub manifest: StoryBundleManifest,
    pub evidence: StoryEvidenceView,
    pub report: ReportDraft,
    pub model_transcript: Vec<RedactedModelTranscriptRecord>,
    pub mcp_transcript: Vec<RedactedMcpTranscriptRecord>,
    pub environment: EnvironmentManifest,
    pub verification: StoryVerification,
    pub trust: BundleTrust,
}

pub enum BundleTrust {
    TrustedWorkspaceKey { key_id: String },
    SelfConsistentUnknownKey { key_id: String },
}

pub struct InvalidStoryBundle {
    pub safe_story: Option<SecurityStory>,
    pub errors: Vec<BundleVerificationError>,
    pub evidence_status: EvidenceStatus,
}
```

The invalid type exposes no transcripts, report approval, or write controls.
Omitting `expected_key_id` may prove internal integrity only and returns
`SelfConsistentUnknownKey`; it never claims trusted workspace provenance.

- [ ] **Step 3: Implement verification order**

1. open the bundle root through the same capability/no-follow abstraction as
   export; reject root symlink, nested symlink, hardlink, special file, unknown
   entry, more than 32 files, any file over 16 MiB, or total over 64 MiB;
2. verify `SHA256SUMS` has exactly one sorted entry for every file except
   itself, with no duplicates;
3. read raw `manifest.json` under a 1 MiB cap, parse supported schema under
   JSON depth 64, compute `signature_material()`, and require raw bytes exactly
   equal those canonical bytes;
4. parse the public key, derive the exact 32-hex key id, compare expected key id
   when supplied, and call Ed25519 `verify_strict` over the raw manifest bytes;
5. verify manifest allowlisted payload list, typed paths, sizes and hashes, plus
   chain head/final frame hash anchors;
6. parse story/events/replay frames into `StoryEvidenceView` with a 1 MiB JSONL
   line cap, then run structural and full semantic verification;
7. parse `report.json`, require its claims exactly equal story claims, render it
   with the Rust renderer, and require exact `report.md` bytes;
8. parse typed model/MCP/environment payloads and verify every observation/input
   commitment against the evidence view;
9. require scenario verification `None` and no scenario extension in this plan
   (Plan 8 installs the extension verifier);
10. return verified with explicit trust status, or invalid.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-assurance --test story_bundle_verify
cargo test -p runwarden-cli --test bundle_tamper
git add crates/runwarden-assurance crates/runwarden-cli
git commit -m "feat(assurance): verify signed story bundles"
```

## Task 6: Add A Shared Signed Evidence Artifact Envelope

**Files:**

- Create: `crates/runwarden-kernel/src/evidence_artifact.rs`
- Create: `schemas/evidence-artifact-manifest.schema.json`
- Create: `crates/runwarden-assurance/src/evidence_artifact.rs`
- Create: `crates/runwarden-cli/src/export/evidence_artifact.rs`
- Test: `crates/runwarden-kernel/tests/evidence_artifact_contract.rs`
- Test: `crates/runwarden-cli/tests/evidence_artifact_tamper.rs`
- Modify: `docs/reference/json-contracts.md`

**Interfaces:**

- Produces the only non-story signed artifact envelope used by Plans 10-12.
- Reuses the workspace key, validated paths, exact canonical bytes, capability
  filesystem, prepared/finalized publish journal, and trust status from Tasks
  3-5; it does not clone their implementation.

- [ ] **Step 1: Freeze the generic manifest**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceArtifactKind {
    EvaluationInputSet,
    ProposalSet,
    LabelSidecar,
    EvaluationRun,
    PerformanceRun,
    ContestSubmission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInputDigest {
    pub role: String,
    pub artifact_id: String,
    pub sha256: Sha256Digest,
    pub required_for_full_verification: bool,
    pub redistributable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactManifest {
    pub schema_version: String,
    pub artifact_kind: EvidenceArtifactKind,
    pub artifact_id: String,
    pub created_at: String,
    pub producer_version: String,
    pub git_sha: String,
    pub source_dirty: bool,
    pub target_triple: Option<String>,
    pub signature_algorithm: String,
    pub key_id: String,
    pub inputs: Vec<ArtifactInputDigest>,
    pub files: Vec<BundleFileDigest>,
}
```

`signature_material` sorts inputs by `(role, artifact_id)` and files by
validated relative path, then returns Canonical JSON v1. Root
`manifest.json`, `manifest.sig`, `public-key.pem`, and `SHA256SUMS` are
not in `files`; checksums cover all files except themselves.

- [ ] **Step 2: Implement one exporter and verifier**

The exporter accepts an artifact kind, typed input receipts, and an explicit
allowlist of payload paths supplied by the kind-specific Plan 10/11/12 builder.
It uses the Task 4 prepared/finalized publish protocol. The verifier first
applies Task 5 structural/signature checks, then calls the kind-specific Rust
semantic verifier. Nested story bundles are ordinary outer payloads and are
fully covered by outer hashes.

- [ ] **Step 3: Add tamper and cross-kind tests**

Mutate input order/digest, payload, summary, manifest bytes, signature, key,
unknown file, symlink, and artifact kind. Require stable error codes. Prove a
PerformanceRun verifier rejects an EvaluationRun layout and that no caller can
mark a non-redistributable input as embedded when its payload is absent.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-kernel --test evidence_artifact_contract
cargo test -p runwarden-cli --test evidence_artifact_tamper
git add crates/runwarden-kernel crates/runwarden-assurance crates/runwarden-cli schemas docs/reference
git commit -m "feat(evidence): sign reusable evaluation artifacts"
```

## Task 7: Add Protected Story Export API

**Prerequisite:** Plan 4 reviewer API and Plan 5 evidence capture are merged.

**Files:**

- Modify: `crates/runwarden-cli/src/web_server/api.rs`
- Test: `crates/runwarden-cli/tests/story_export_api.rs`
- Modify: `docs/reference/reviewer-http-sse-api.md`

**Interfaces:**

- Implements: `POST /api/stories/{story_id}/export` from the approved design.

- [ ] **Step 1: Write nonce/version/path tests**

Assert success requires accepted origin, valid reviewer nonce, expected story
version, and a relative workspace output path. Test stale version, traversal,
absolute path, symlink escape, foreign origin, and invalid nonce.

- [ ] **Step 2: Define the body and response**

```rust
#[derive(serde::Deserialize)]
struct StoryExportBody {
    expected_story_version: u64,
    output: String,
}

#[derive(serde::Serialize)]
struct StoryExportResponse {
    export_id: String,
    relative_path: String,
    manifest_hash: String,
    key_id: String,
    evidence_status: EvidenceStatus,
}
```

- [ ] **Step 3: Call the same exporter as CLI**

Do not duplicate signing or path policy in the route. Map version conflicts to
409, invalid path/body to 422, verification failure to 409, and storage errors
to 503.

In the same checkpoint replace Plan 4's structural-only
`GET /api/stories/{story_id}/evidence/verify` handler with
`verify_story_evidence(..., VerificationMode::Final)`. Return the typed full
verification and explicit trusted/untrusted provenance fields; the route still
cannot mutate evidence status (only `verify_and_finalize_story` can).

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-cli --test story_export_api
git add crates/runwarden-cli docs/reference/reviewer-http-sse-api.md
git commit -m "feat(api): export versioned signed stories"
```

## Task 8: Document And Verify The Bundle Boundary

**Files:**

- Modify: `docs/reference/artifact-manifest.md`
- Modify: `docs/reference/contest-review-outputs.md`
- Modify: `docs/reference/evidence-and-accountability.md`
- Modify: `docs/reference/cli.md`
- Modify: `docs/README.md`

**Interfaces:**

- Certifies the detached-signature bundle layout and Rust verification API for
  Plan 7 replay and Plan 12 packaging.

- [ ] **Step 1: Document exact trust semantics and layout**

State the signature algorithm, key id, signature bytes, checksum coverage,
expected-key-id option, private-key location, redaction boundary, invalid
bundle behavior, and limitation under host compromise.

- [ ] **Step 2: Verify a round trip from a clean temp directory**

```bash
target/debug/runwarden bundle export --story-id "$STORY_ID" --output target/bundle-roundtrip --expected-version "$STORY_VERSION" --json
target/debug/runwarden bundle verify --bundle target/bundle-roundtrip --expected-key-id "$KEY_ID" --json
```

Expected: `verified=true`, matching story id/version/chain head/key id.

- [ ] **Step 3: Run all gates**

```bash
cargo test -p runwarden-assurance
cargo test -p runwarden-cli --test story_bundle --test bundle_tamper --test story_export_api
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all commands exit zero.

- [ ] **Step 4: Commit the merge checkpoint**

```bash
git add docs
git commit -m "docs(export): define signed bundle verification"
```
