# LLM Proxy Story Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put model requests, filter decisions, responses, and proposed tool calls into the same authoritative story and causally link proposals to durable provider operations.

**Architecture:** The LLM proxy loads the single active demo context from `runwarden-state` at startup. Before forwarding, it commits a redacted model-call intent. After response inspection, it commits response and tool-proposal events. A small causal-link table stores provider/action/canonical-argument commitments; the runtime links by upstream tool-call id first, then by a unique exact commitment, and otherwise emits an explicit unresolved event. Time proximity is never authoritative.

**Tech Stack:** Rust 1.95.0, existing OpenAI-compatible proxy, `runwarden-state`, shared canonical JSON/SHA-256 helpers, SQLite migration v2.

**Prerequisite:** Plans 1-4 are merged. This plan is not implemented in
parallel with the runtime crate it modifies.

## Global Constraints

- Input/output filter policy remains Rust-owned.
- Full prompt, completion, tool arguments, authorization headers, and API keys
  never enter `StoryEvent` payloads.
- Model forwarding does not start if the request-intent event cannot commit.
- Upstream tool-call ids are evidence inputs, not authorization inputs.
- Causal matching requires exact story, session, provider, action, and argument
  hash. Multiple exact candidates are unresolved.
- Time windows may order display events but cannot prove a causal link.
- Legacy JSONL trace output is produced from the journal, not written by a
  second live writer.

---

## File Responsibility Map

- Create `runwarden-state/migrations/0002_model_proposals.sql` and
  `runwarden-state/src/proposals.rs`.
- Split proxy responsibilities into `server.rs`, `filter.rs`, `upstream.rs`,
  `story_events.rs`, and `causal_link.rs` only as touched.
- After Plan 4 exists, modify `runwarden-runtime/src/operation.rs` to create an
  operation and claim its proposal in one state transaction.
- Preserve `runwarden-llm-proxy/src/lib.rs` as the public facade.

### Frozen Interfaces

```rust
pub struct ModelCallIntent {
    pub model_call_id: String,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub endpoint_kind: String,
    pub model_id: String,
    pub prompt_hash: Sha256Digest,
}

pub struct ProposedToolCall {
    pub proposal_id: String,
    pub model_call_id: String,
    pub upstream_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
    pub redacted_arguments: SafeArgumentView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalGapReason {
    MissingUpstreamId,
    NoMatchingProposal,
    AmbiguousCommitment,
    ProposalAlreadyClaimed,
}

pub enum CausalLinkResult {
    Linked { proposal_id: String, model_call_id: String },
    Unresolved { reason: CausalGapReason, candidate_count: u64 },
}

pub struct ProposalLinkQuery {
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub upstream_tool_call_id: Option<String>,
    pub provider: String,
    pub action: String,
    pub argument_hash: Sha256Digest,
}
```

## Task 1: Persist Model Calls And Proposal Commitments

**Files:**

- Create: `crates/runwarden-state/migrations/0002_model_proposals.sql`
- Create: `crates/runwarden-state/src/proposals.rs`
- Modify: `crates/runwarden-state/src/store.rs`
- Modify: `crates/runwarden-state/src/lib.rs`
- Test: `crates/runwarden-state/tests/proposal_links.rs`

**Interfaces:**

- Produces: `record_model_call`, `record_tool_proposal`, and
  `create_operation_with_proposal(NewOperation, ProposalLinkQuery)`.

- [ ] **Step 1: Write failing exact-match and ambiguity tests**

Record one proposal and create an operation with the same upstream id. Record
two unlinked proposals with the same commitment and create another operation
without an upstream id.
Assert:

```rust
assert!(matches!(by_id, CausalLinkResult::Linked { .. }));
assert!(matches!(ambiguous, CausalLinkResult::Unresolved {
    candidate_count: 2,
    ..
}));
```

Also prove a proposal from another session is never a candidate.

- [ ] **Step 2: Add migration v2**

```sql
PRAGMA user_version = 2;

CREATE TABLE model_calls (
    model_call_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    endpoint_kind TEXT NOT NULL,
    model_id TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    response_hash TEXT,
    input_filter_state TEXT NOT NULL,
    output_filter_state TEXT,
    output_risk_codes_json TEXT,
    response_forwarded INTEGER CHECK(response_forwarded IN (0, 1)),
    output_bytes INTEGER,
    proposal_count INTEGER,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(story_id, model_call_id),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(output_risk_codes_json IS NULL OR json_valid(output_risk_codes_json))
) STRICT;

CREATE TABLE model_usage (
    story_id TEXT NOT NULL,
    session_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0,
    calls_committed INTEGER NOT NULL DEFAULT 0,
    input_bytes_committed INTEGER NOT NULL DEFAULT 0,
    output_bytes_committed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id)
) STRICT;

CREATE TABLE tool_proposals (
    proposal_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    model_call_id TEXT NOT NULL,
    upstream_tool_call_id TEXT,
    provider TEXT NOT NULL,
    action TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    redacted_arguments_json TEXT NOT NULL,
    linked_operation_id TEXT UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    FOREIGN KEY(story_id, model_call_id)
      REFERENCES model_calls(story_id, model_call_id) ON DELETE CASCADE,
    FOREIGN KEY(story_id, linked_operation_id)
      REFERENCES operations(story_id, operation_id),
    CHECK(json_valid(redacted_arguments_json))
) STRICT;

CREATE INDEX tool_proposals_commitment_idx
ON tool_proposals(story_id, session_id, provider, action, argument_hash);

CREATE UNIQUE INDEX tool_proposals_upstream_id_idx
ON tool_proposals(model_call_id, upstream_tool_call_id)
WHERE upstream_tool_call_id IS NOT NULL;
```

Update migration execution to apply versions in order and reject a database
newer than the binary supports.

- [ ] **Step 3: Implement atomic operation creation and proposal linking**

`create_operation_with_proposal` runs in one immediate transaction:

1. if upstream id is present, select all unlinked exact-id/exact-commitment
   rows and link only when count is exactly one;
2. otherwise select all unlinked exact-commitment rows;
3. choose a link only when the result count is one;
4. insert the operation and resource claim, placing the chosen proposal/model
   ids into the safe operation view, or leaving both empty when unresolved;
5. after the operation row exists, update `linked_operation_id` with an
   `IS NULL` CAS so the foreign key is satisfiable;
6. append `operation_proposed` plus either `causal_link_resolved` or
   `causal_link_unresolved`, then commit and return both operation and result.

Any insert, CAS, or event failure rolls back the operation and proposal link.
There is no transaction state in which a proposal references an operation row
that has not been inserted, and no committed operation claims a link the
proposal table did not also commit.

The partial unique index rejects duplicate non-null upstream ids within a model
call. The resolver still counts instead of using `LIMIT 1`, so a legacy or
corrupt database with duplicates produces `Unresolved`, never an arbitrary
link. Tests attempt duplicate ids and ambiguous exact commitments.

It does not use timestamps.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-state --test proposal_links
git add crates/runwarden-state
git commit -m "feat(state): persist model tool proposals"
```

## Task 2: Make The Proxy Use The Active Story Journal

**Files:**

- Create: `crates/runwarden-llm-proxy/src/story_events.rs`
- Modify: `crates/runwarden-llm-proxy/src/lib.rs`
- Modify: `crates/runwarden-llm-proxy/src/main.rs`
- Modify: `crates/runwarden-llm-proxy/Cargo.toml`
- Test: `crates/runwarden-llm-proxy/tests/story_events.rs`

**Interfaces:**

- Produces: `StoryEventSink` and `JournalStoryEventSink`.
- Replaces live direct JSONL appends.

- [ ] **Step 1: Write a no-forward-on-journal-failure test**

Use a fake upstream counter and a failing sink. Send a benign request and
assert HTTP 503 plus:

```rust
assert_eq!(upstream.request_count(), 0);
assert!(response.body.contains("story_journal_unavailable"));
```

- [ ] **Step 2: Add state dependencies and trusted startup fields**

Extend proxy `Cli` with a required production `state_dir: PathBuf` and a
deprecated optional `trace_export: Option<PathBuf>`. Read
`RUNWARDEN_INSTANCE_TOKEN` only from trusted inherited environment, hash it,
open the store, load the exact active story/session/instance binding, and fail
before binding the socket if validation fails. The token is never a CLI flag,
HTTP field, agent config, event, or log value.

- [ ] **Step 3: Define the event sink**

```rust
pub trait StoryEventSink: Send + Sync {
    fn begin_model_call(
        &self,
        intent: ModelCallIntent,
        input_filter: FilterDecisionEvent,
    ) -> Result<(), String>;
    fn complete_model_call(
        &self,
        input: ModelCallCompletion,
        proposals: Vec<ProposedToolCall>,
    ) -> Result<(), String>;
    fn mark_evidence_invalid(&self, reason: &str) -> Result<(), String>;
}
```

`begin_model_call` writes the model row with a concrete input filter state,
reserves one model call plus input bytes, and appends typed intent/filter
events/frames in one immediate transaction. `complete_model_call` atomically
updates output hash/filter/risk/forwarded/count, commits output-byte usage,
inserts all proposal rows, and appends typed completion/proposal events/frames.
Inject failure at every table/event/frame write and prove complete rollback.

- [ ] **Step 4: Commit intent before upstream forwarding**

For both `/v1/chat/completions` and `/v1/responses`:

1. calculate prompt hash from the complete normalized request content;
2. inspect input without persisting raw text;
3. in the same pre-forward transaction re-read active instance/token/session,
   require session unexpired, validate configured upstream origin against
   `NetworkAuthority`, and CAS model call/input-byte budget;
4. commit `model_request_received` and filter decision;
5. return 403 when blocked or forward only after successful commits.

This per-call transaction is authoritative. A context cached at startup cannot
forward after demo deactivation, token replacement, session expiry, egress
revocation, or model budget exhaustion.

- [ ] **Step 5: Handle post-upstream journal failure honestly**

If the upstream response arrived but completion evidence cannot commit, attempt
to mark the story `EvidenceStatus::Invalid`, return HTTP 503, and log only model
call id and error category. Do not return an untraced completion to the agent.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-llm-proxy --test story_events
cargo test -p runwarden-llm-proxy --test proxy_flow
git add crates/runwarden-llm-proxy
git commit -m "feat(proxy): journal model calls in the active story"
```

## Task 3: Extract And Record Tool Proposals

**Files:**

- Create: `crates/runwarden-llm-proxy/src/causal_link.rs`
- Modify: `crates/runwarden-llm-proxy/src/lib.rs`
- Test: `crates/runwarden-llm-proxy/tests/tool_proposals.rs`

**Interfaces:**

- Produces: parsers for Chat Completions and Responses tool-call shapes.
- Uses the same provider action and argument-hash helpers as the runtime.

- [ ] **Step 1: Write response-shape tests**

Cover:

- `choices[].message.tool_calls[].function`;
- Responses API function-call output items;
- buffered SSE tool-call deltas assembled into one call;
- malformed function arguments;
- non-Runwarden function names.

For a valid flat `runwarden.provider.call`, assert provider is removed before
hashing and the resulting hash equals the runtime's hash for the MCP call.

- [ ] **Step 2: Add one shared canonical argument helper**

Move argument hashing into a kernel function:

```rust
pub fn canonical_argument_hash(arguments: &serde_json::Value) -> Sha256Digest {
    Sha256Digest::from_bytes(&crate::trace::canonical_json_v1(arguments))
}
```

Both proxy and runtime call this function.

- [ ] **Step 3: Implement proposal extraction**

Accept only tool name `runwarden.provider.call`. Parse its JSON argument
object, remove `provider`, reject reserved policy fields, obtain action from
the Rust provider catalog, calculate canonical argument hash, redact the view,
and persist a `ProposedToolCall`. Malformed calls generate
`proposed_tool_call_invalid` events and are not link candidates.

- [ ] **Step 4: Record output-filter states**

For safe, flagged, and blocked outputs, store response hash, typed risk codes,
forwarded boolean, output byte count, and tool-proposal count. Do not persist a
prompt/response preview in model rows or event payloads. Never store raw model
reasoning or credentials.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-llm-proxy --test tool_proposals
cargo test -p runwarden-llm-proxy --test proxy_flow
git add crates/runwarden-kernel crates/runwarden-llm-proxy
git commit -m "feat(proxy): record proposed Runwarden tool calls"
```

## Task 4: Link Runtime Operations Or Emit Explicit Gaps

**Prerequisite:** Plan 4's `runwarden-runtime` crate is merged. Tasks 1-3 of
this plan may proceed in parallel with Plan 4; this integration task may not.

**Files:**

- Modify: `crates/runwarden-runtime/src/operation.rs`
- Modify: `crates/runwarden-runtime/src/lib.rs`
- Test: `crates/runwarden-runtime/tests/causal_linking.rs`
- Test: `crates/runwarden-runtime/tests/causal_ambiguity.rs`

**Interfaces:**

- Adds `upstream_tool_call_id: Option<String>` as trusted runtime metadata,
  not an MCP provider argument.
- Produces linked ids in `SecurityOperation` or an unresolved story event.

- [ ] **Step 1: Write exact-id, unique-hash, and ambiguity tests**

Assert precedence:

```rust
assert_eq!(linked_by_id.proposed_tool_call_id.as_deref(), Some("call_upstream_1"));
assert!(linked_by_hash.parent_model_call_id.is_some());
assert!(ambiguous.proposed_tool_call_id.is_none());
assert!(events.iter().any(|event| {
    event.event_type == StoryEventKind::CausalLink
        && matches!(event.payload(), StoryEventPayload::CausalLink {
            status, ..
        } if status.as_str() == "unresolved")
}));
```

- [ ] **Step 2: Create and link in the journal's single transaction**

After claim extraction and argument hashing, call
`create_operation_with_proposal(NewOperation, ProposalLinkQuery)`. Consume the
returned operation and link result; do not pre-write link ids and do not append
a second unresolved event in the runtime because the state transaction already
did so.

- [ ] **Step 3: Prevent cross-session and reused-proposal links**

A linked proposal cannot link again. A candidate from another story/session,
provider, action, or hash is ignored even when its timestamp is adjacent.

Add a fixture captured from pinned OpenCode 1.17.13 through the real MCP JSON-
RPC shape. If the client preserves an upstream call id in transport metadata,
map it into `ProposalLinkQuery`; if it does not, set `None` and exercise the
unique exact-commitment fallback. Two same-commitment proposals must remain
explicitly unresolved. The adapter never copies a model-controlled id from
provider arguments into trusted metadata.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-runtime --test causal_linking
cargo test -p runwarden-runtime --test causal_ambiguity
git add crates/runwarden-runtime
git commit -m "feat(runtime): link model proposals to operations"
```

## Task 5: Preserve Verified JSONL Compatibility And Update References

**Files:**

- Modify: `crates/runwarden-llm-proxy/src/main.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Modify: `docs/reference/evidence-and-accountability.md`
- Modify: `docs/reference/agent-integration.md`
- Modify: `docs/reference/cli.md`
- Modify: `docs/reference/contest-review-outputs.md`
- Modify: `docs/reference/mcp.md`

**Interfaces:**

- Keeps current probes usable while SQLite is authoritative.

- [ ] **Step 1: Export proxy JSONL from story events**

When `--trace-export` is provided, export verified model-related StoryEvents
after a call or at orderly shutdown. Do not append independently. Label the
file a compatibility view in metadata.

- [ ] **Step 2: Update launch wiring**

`runwarden demo` passes the same state directory to MCP and proxy. Remove
assumptions that model and provider traces live in unrelated files. Existing
probe scripts may request explicit compatibility exports.

- [ ] **Step 3: Update reference semantics**

Document model intent fail-closed behavior, redacted prompt/response material,
tool-proposal extraction, link precedence, and explicit unresolved links.

- [ ] **Step 4: Run the complete proxy/story gate**

```bash
cargo test -p runwarden-state --test proposal_links
cargo test -p runwarden-llm-proxy
cargo test -p runwarden-runtime --test causal_linking --test causal_ambiguity
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all commands pass.

- [ ] **Step 5: Commit the merge checkpoint**

```bash
git add crates docs
git commit -m "docs(proxy): define unified model and tool evidence"
```

## Task 6: Verify Privacy And Causal Integrity

**Files:**

- Verify only.

**Interfaces:**

- Certifies redacted model events and authoritative causal-link/gap semantics.

- [ ] **Step 1: Run a secret-bearing proxy fixture**

Use a prompt, completion, and tool argument containing three distinct secret
markers. Query the story API, SQLite event rows, JSONL compatibility export,
and generated report inputs.

Expected: no marker appears in any display/export surface; the private model
transcript location, when enabled, is owner-only and is not queried by the
story API.

- [ ] **Step 2: Verify every operation's causal state**

Query a test story containing exact, unique-hash, and ambiguous proposals.
Expected: linked operations point to real model/proposal ids; unlinked
operations have a `causal_link_unresolved` observation and are never displayed
as proven model causality.

- [ ] **Step 3: Run final gates**

```bash
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: exit zero.
