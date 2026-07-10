# Runwarden Contest Security Story Workbench Design

**Status:** Approved design

**Date:** 2026-07-10

**Scope:** Contest-focused refactor of Runwarden's security execution path,
scenario evidence, approval workflow, and reviewer WebUI.

## 1. Executive Summary

Runwarden will remain a contest-sized agent security prototype rather than grow
into a general multi-tenant security platform. The refactor concentrates effort
on two outcomes:

1. every contest claim comes from a real, traceable attack-to-defense execution
   path; and
2. the reviewer WebUI communicates that path as one complete security story,
   including identity, authority, policy gates, approval, execution, evidence,
   and report claims.

The central product object becomes a Rust-owned `SecurityStory`. Model calls,
tool proposals, provider calls, policy decisions, approvals, executions, trace
events, and report claims are correlated under the same story and operation
identifiers. Live OpenCode demonstrations and deterministic offline replay use
the same contract and the same WebUI.

The refactor adds a small SQLite-backed operation journal for durable approval
and event ordering, but explicitly excludes general SaaS, organization, billing,
distributed messaging, and remote policy-management features.

## 2. Problem Statement

The existing contest edition has strong individual mechanisms but a fragmented
story:

- the deterministic demo is driven by expected provider-call fixtures rather
  than the checked-in attack input;
- the LLM proxy and MCP provider path write separate traces without a common
  causal identifier;
- the live MCP path uses a fixed inline session and file-backed approval state;
- approval consumption, side effects, and trace persistence are not a durable
  transaction;
- the static console embeds provider events but does not present the complete
  model-to-tool-to-report chain;
- current filter evaluation is mostly derived from a small, co-authored corpus;
- the final contest bundle is evidence-oriented but not independently runnable.

The result is technically substantial but difficult for a reviewer to validate
as one end-to-end system. This design fixes that evidence and presentation gap
without expanding Runwarden into a production platform.

## 3. Goals

The refactor must produce these observable outcomes:

- A reviewer can understand the complete security narrative within ten seconds
  of opening the WebUI.
- The first screen shows who is acting, current authority, attack intent, tool
  request, policy gates, approval state, side-effect truth, evidence state, and
  final outcome.
- Every formal scenario consumes its real attack and environment inputs.
- Scenario assertions validate events produced by execution; expected events do
  not drive the execution.
- Live OpenCode runs and deterministic runs produce the same versioned
  `SecurityStory` contract.
- A live tool request can pause for approval and continue as the same operation
  after an authorized reviewer decision.
- An approval is one-shot, argument-bound, resource-bound, expiring, and safe
  against concurrent consumption.
- Model and tool events share story, session, and causal identifiers.
- A report claim is accepted only when its cited, verified event supports the
  exact claim semantics.
- A signed offline story bundle renders in the same WebUI as a live run.
- The submission package works on a clean supported machine using included
  source or release binaries, fixed configuration, and a documented preflight.
- The system demonstrates supervised tool use, file access, network access,
  memory/knowledge access, email/API use, and bounded code execution.

## 4. Non-Goals

The following are deliberately excluded:

- general multi-tenant SaaS;
- organization and account administration;
- billing, subscription, or usage metering;
- Kubernetes deployment;
- distributed queues, consensus, or remote database clusters;
- a remote policy authoring and distribution service;
- a general-purpose SOC query language;
- arbitrary third-party plugin marketplaces;
- browser- or TypeScript-owned allow/deny logic;
- production SMTP or unrestricted external API side effects;
- full operating-system parity for the Linux code-execution sandbox.

The macOS and Windows contest builds may run the deterministic scenarios and
WebUI, but the strongest code-execution isolation demonstration is explicitly a
Linux capability.

## 5. Design Principles

### 5.1 Rust Owns Security Semantics

Rust types and code own authority, policy, resource claims, state transitions,
approval binding, evidence verification, and report semantics. TypeScript is a
presentation consumer of generated contracts.

### 5.2 Evidence Before Narrative

The UI never infers a favorable security outcome from missing data. It displays
Rust-produced status fields and marks incomplete or unverifiable evidence as an
error state.

### 5.3 One Story, Two Delivery Modes

Live and replay modes differ only in event source:

- live mode reads a committed snapshot and incrementally receives events;
- replay mode reads a signed exported snapshot and advances through recorded
  events.

Both modes render the same components and use the same semantics.

### 5.4 Approval Is Not Permission Mutation

Approval grants one execution lease for one frozen operation. It never expands
the agent's standing provider, filesystem, network, memory, or data authority.

### 5.5 Fail Closed Before Side Effects

If the session, policy, operation intent, approval lease, or evidence-intent
write cannot be persisted, provider execution does not start.

### 5.6 Honest Unknown States

If a provider may have executed but completion cannot be durably recorded, the
operation becomes `outcome_unknown`. It is never described as denied, safe, or
completed.

## 6. Chosen Architecture

```text
OpenCode
  |- model request -> runwarden-llm-proxy --------------------+
  `- tool call ----> runwarden-mcp -> KernelEnforcer ---------|
                                                              v
                                                   Operation Journal
                                                   SQLite WAL + Rust
                                                              |
                         +------------------------------------+-------------+
                         v                                    v             v
                    Live SSE                           Offline export   Assurance
                    Reviewer UI                       story bundle     report lint
```

### 6.1 Component Responsibilities

`runwarden-kernel` owns:

- session and authority contracts;
- provider-specific resource claims;
- ordered policy checks;
- operation and approval state-transition rules;
- policy decisions and side-effect state vocabulary;
- trace event contracts and hash material.

`runwarden-state` is a new crate that owns:

- SQLite migrations;
- transactional story, session, operation, approval, and event persistence;
- atomic execution-lease acquisition;
- per-story event sequence allocation;
- snapshot and incremental event reads;
- crash recovery queries;
- legacy JSONL export where compatibility is required.

`runwarden-mcp` owns:

- the only agent-visible MCP surface;
- conversion of provider calls into typed resource claims;
- invoking the Rust kernel with server-owned session context;
- durable pending-operation creation;
- approval wait and resume;
- `runwarden.operation.status` and `runwarden.operation.resume` for reconnecting
  clients; resume accepts only an operation identifier and reloads the frozen
  server-owned request;
- provider execution through the single executor interface;
- returning structured operation results to the MCP client.

`runwarden-llm-proxy` owns:

- model request and response interception;
- bounded input and output inspection;
- extracting tool proposals when the upstream schema exposes them;
- model-call and proposed-tool-call events;
- linking those events to the active story and session;
- forwarding or blocking upstream requests according to Rust filter output.

`runwarden-providers` owns:

- provider catalog and manifests;
- typed resource extraction for each provider;
- local contest business tools;
- the single external MCP adapter entry point;
- bounded code-execution worker integration;
- truthful execution result and side-effect reporting.

`runwarden-assurance` owns:

- story and trace verification;
- claim-to-observation semantic validation;
- scenario assertion evaluation;
- contest metrics;
- Markdown, JSON, HTML, and SARIF report rendering.

`runwarden-cli` owns:

- scenario preparation and execution;
- live demo orchestration;
- isolated OpenCode launch and preflight;
- reviewer HTTP/SSE server;
- story recording and replay;
- signed bundle export;
- contest bundle construction.

The new `webui` package owns presentation only.

## 7. Domain Model

### 7.1 SecurityStory

A `SecurityStory` is the complete reviewer-facing security narrative. It
contains:

- schema version;
- story identifier and display title;
- scenario and attack category;
- run mode: `live`, `deterministic`, or `recorded`;
- story status and evidence status;
- agent, model, actor, reviewer, and session identities;
- authority snapshot;
- safe attack preview and attack-content hash;
- ordered operations and events;
- report claims and observation references;
- final outcome summary;
- final trace-chain head and optional export signature.

The top-level story status is emitted by Rust and is one of:

- `running`;
- `awaiting_approval`;
- `blocked_before_side_effect`;
- `completed_with_controlled_side_effect`;
- `failed`;
- `outcome_unknown`;
- `evidence_invalid`.

### 7.2 SecurityOperation

Each security-relevant action is a `SecurityOperation` with:

- UUIDv7 operation identifier;
- story and session identifiers;
- optional parent model-call and proposed-tool-call identifiers;
- provider, action, and canonical resource claim;
- original argument hash and redacted argument view;
- policy snapshot hash;
- current operation state and monotonically increasing version;
- policy checks;
- optional approval;
- optional execution lease;
- optional provider result;
- side-effect state;
- associated `obs_*` references.

### 7.3 AuthoritySnapshot

The authority snapshot contains:

- actor and authz state;
- session expiry;
- allowed provider identifiers;
- file roots and path/resource constraints;
- provider-specific allowed origins;
- email recipient constraints;
- memory and knowledge namespaces;
- data-classification rules;
- argument, file-byte, network-byte, call-count, and wall-time budgets;
- policy snapshot hash.

The WebUI receives this exact structure. It does not reconstruct permissions
from provider names or error messages.

### 7.4 ResourceClaim

Every executable provider defines a typed resource extractor. The minimum
contract is:

```rust
enum ResourceClaim {
    File {
        root: String,
        path: String,
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
}
```

Provider policy no longer depends on globally scanning arbitrary argument keys
for names containing `path` or `url`.

## 8. Operation and Approval State Machines

### 8.1 Operation States

```text
proposed
  -> policy_evaluated
       -> denied
       -> awaiting_approval
            -> denied_by_reviewer
            -> expired
            -> approved
                 -> execution_leased
       -> execution_leased
            -> executing
                 -> completed
                 -> failed
                 -> outcome_unknown
```

Illegal transitions are rejected by `runwarden-kernel` before persistence.

Required invariants:

- denied operations never acquire a lease;
- an approved operation cannot execute without atomically acquiring the lease;
- an operation cannot complete without a prior execution-start intent;
- a changed argument or resource claim creates a new operation;
- completion, failure, and unknown are terminal states;
- only `completed` may claim a successfully executed side effect;
- only a verified denial before `executing` may claim a blocked side effect.

### 8.2 Approval States

```text
pending
  -> approved -> leased -> consumed
  -> denied
  -> expired
```

An approval binds:

- story and session;
- actor;
- provider and action;
- canonical resource claim;
- complete argument hash;
- data classification;
- policy snapshot hash;
- reviewer;
- expiry;
- maximum consumption count of one.

Lease acquisition is a conditional SQLite update. Exactly one concurrent
consumer can transition an approved record to leased.

### 8.3 Approval Wait Behavior

An MCP provider call waits for a configurable approval window. During the wait:

- the pending operation is visible in the reviewer WebUI;
- approval resumes the same operation;
- denial returns a structured rejection;
- expiry returns `approval_expired`;
- connection loss does not silently re-execute the operation;
- a reconnecting client can query final status by operation identifier.

The agent-visible recovery surface is `runwarden.operation.status` and
`runwarden.operation.resume`. Neither tool accepts replacement provider
arguments, session policy, or approval material.

The default contest approval window is 120 seconds.

## 9. Durable Journal

SQLite uses WAL mode and contains these logical tables:

- `stories`;
- `sessions`;
- `operations`;
- `resource_claims`;
- `policy_checks`;
- `approvals`;
- `events`;
- `report_claims`;
- `exports`.

The state directory is created with owner-only permissions on Unix, and the
database, WAL, signing-key, and transcript files are not copied into a contest
bundle. Windows uses the current user's private application-data directory.

Each story event has:

- UUIDv7 event identifier;
- story-local sequence number;
- event type;
- provider and operation identifiers when applicable;
- structured payload;
- prior event hash;
- event hash;
- recorded timestamp.

Before starting a provider, Runwarden must durably store:

1. the proposed operation;
2. the kernel policy result and every displayed policy check;
3. the approval result when required;
4. the execution lease;
5. the execution-start intent event.

If one of these writes fails, no provider runs.

Contest-local side-effect providers use the operation identifier as an
idempotency key. If the process fails after a possible side effect but before
completion persistence, recovery marks the operation `outcome_unknown` unless
the provider can prove the idempotent result. It never automatically repeats an
unknown side effect.

## 10. Causal Linking

The active story and session are created by `runwarden demo prepare` or the
scenario runner. The LLM proxy and MCP server read the same server-owned active
session record from the configured Runwarden state directory.

Linking precedence is:

1. upstream tool-call identifier when present;
2. exact provider, action, and canonical argument hash within the session;
3. no link.

Time proximity alone is never sufficient for an authoritative causal link. If
the first two strategies fail, the event is marked `causal_link_unresolved` and
the WebUI displays that limitation.

The intended complete chain is:

```text
attack_input
  -> model_call
  -> proposed_tool_call
  -> actual_provider_call
  -> policy_decision
  -> approval_decision
  -> provider_execution
  -> report_claim
```

## 11. Reviewer WebUI

### 11.1 Technology

The WebUI uses React, TypeScript, and Vite. It has no external CDN or runtime
asset dependency. Rust JSON schemas generate TypeScript contracts. The browser
does not contain policy, approval-validity, evidence-validity, or report-support
logic.

The UI supports:

- 1920x1080 as the primary presentation resolution;
- 1366x768 as the minimum fully usable resolution;
- Chinese-first copy with English technical identifiers;
- keyboard navigation and non-color status indicators;
- a strict content security policy;
- safe text rendering for attack and tool content;
- live and offline builds from the same source.

### 11.2 First-Screen Information Architecture

```text
+----------------------------------------------------------------------------+
| Runwarden | Scenario | LIVE/REPLAY | Trace Verified | Final Outcome        |
+--------------+------------------------------------------+------------------+
| Scenario Nav | Security Story Rail                      | Authority        |
|              | identity -> attack -> model -> tool      | actor/authz      |
|              | -> policy -> approval -> execution       | providers/roots  |
|              | -> evidence/report                       | egress/budget    |
+--------------+------------------------------------------+------------------+
| Event timeline and selected-stage evidence details                         |
+----------------------------------------------------------------------------+
```

The header prioritizes outcome, not event counts. Rust supplies these display
states:

- `BLOCKED BEFORE SIDE EFFECT`;
- `HELD FOR REVIEW`;
- `APPROVED AND EXECUTED`;
- `OUTCOME UNKNOWN`;
- `EVIDENCE VERIFIED`;
- `EVIDENCE INVALID`.

### 11.3 Security Story Rail

The fixed stages are:

1. identity and authority;
2. attack input;
3. model behavior;
4. proposed tool action;
5. kernel policy decision;
6. reviewer approval;
7. controlled execution;
8. evidence and report.

Each stage displays a Rust-provided status. Selecting a stage opens its event,
safe parameter preview, policy checks, reason, side-effect state, observation
reference, and event hash.

### 11.4 Authority Panel

The authority panel continuously displays:

- agent, model, actor, session, and authz;
- provider allowlist;
- roots and resource constraints;
- allowed origins and recipients;
- budgets and expiry;
- policy snapshot hash;
- approved, denied, leased, and consumed operations.

When an operation is selected, it contrasts standing authority with the
requested resource. The comparison is produced by Rust as structured data.

### 11.5 Approval Drawer

The approval drawer shows:

- requester identity;
- provider and action;
- target resource;
- data source and classification;
- argument hash;
- policy reason;
- expiry and one-shot semantics;
- exact bound fields;
- the statement that approval does not expand standing permission.

The actions are `approve this execution` and `deny with reason`. After a
decision, the same space displays reviewer identity, decision time, lease and
consumption state, and observation references.

### 11.6 Modes

Presentation mode emphasizes the story rail, current operation, outcome, and
approval. It uses larger type and automatic event following.

Analyst mode exposes policy checks, redacted arguments, structured events,
hashes, causal links, scenario assertions, and report references.

Live mode receives committed events over SSE. Replay mode loads a verified
story bundle and selects Rust-produced `StoryReplayFrame` snapshots keyed by
committed event sequence. It provides play, pause, step, speed, and restart
controls without reducing events into policy state in TypeScript. Replay is
always visibly labeled `RECORDED REPLAY`.

The live server follows cross-process SQLite writers by querying committed
events after the last published story sequence at a 100 ms interval. SSE
reconnect sends the browser's last sequence so missed events are replayed before
new events are followed.

Offline export produces a self-contained `reviewer-console.html`. It embeds only
the redacted story snapshot as escaped `application/json`; it never fetches
local files and never embeds full execution arguments. JavaScript and CSS are
locally bundled, and the generated CSP contains their build hashes.

### 11.7 Frontend Security Rules

- no `dangerouslySetInnerHTML`;
- no raw secret values in the browser bootstrap payload;
- no frontend-generated approval binding;
- no frontend-computed overall evidence status;
- no executable content from a story bundle;
- all POST requests require a Rust-issued reviewer nonce and accepted loopback
  origin;
- offline mode exposes no write controls.

## 12. HTTP and SSE Contract

The live reviewer server exposes:

```text
GET  /api/bootstrap
GET  /api/stories
GET  /api/stories/{story_id}
GET  /api/stories/{story_id}/events?after_seq={sequence}
GET  /api/stories/{story_id}/operations/{operation_id}
GET  /api/stories/{story_id}/report
GET  /api/stories/{story_id}/evidence/verify
GET  /events?story_id={story_id}
POST /api/approvals/{approval_id}/decision
POST /api/stories/{story_id}/export
```

Approval decisions contain:

- decision;
- non-empty reviewer reason;
- reviewer nonce;
- expected operation version.

Version mismatch, expired approval, changed arguments, changed resource claims,
changed policy snapshot, invalid nonce, or invalid origin causes a rejection.
Story export is also a privileged POST and requires the same reviewer nonce and
expected story version.

## 13. Scenario System

### 13.1 Scenario Layout

Each formal scenario has:

```text
scenarios/{id}/
  scenario.toml
  session.toml
  task.md
  attack/
  environment/
  driver/
  assertions.json
```

The driver never consumes assertions. Assertions describe security properties,
not exact generated calls or observation identifiers.

### 13.2 Formal Scenarios

The contest suite contains six scenarios:

1. prompt injection and file exfiltration;
2. tool hijacking across email and API;
3. memory and knowledge poisoning;
4. local/private environment and SSRF;
5. filesystem path escape;
6. code-execution sandbox abuse.

### 13.3 Hero Story

The prompt-injection scenario is the primary complete narrative:

1. the user requests a quarterly report and finance email;
2. the agent reads an allowed public report;
3. the report contains an indirect injection;
4. the model proposes reading a confidential environment file;
5. the kernel holds the read for review;
6. the reviewer denies the confidential read;
7. a hidden callback request is denied by provider/egress policy;
8. the agent returns to the legitimate task;
9. the finance email is held for review;
10. the reviewer approves the exact recipient and content hash;
11. the local email provider executes exactly once;
12. the verified report cites the same story observations.

This one story demonstrates allow, deny, review, reviewer denial, reviewer
approval, single-use consumption, true and false side-effect states, authority,
and evidence-backed reporting.

### 13.4 Execution Drivers

The deterministic driver reads the real task, attack, and environment but uses
a fixed agent behavior implementation. It traverses the same kernel, journal,
approval, provider, trace, and assurance path as a live run. It is used for CI,
offline evidence, and fallback replay.

The OpenCode driver launches a fixed OpenCode version with isolated XDG state,
only `runwarden-mcp`, a bounded model/step budget, and a complete transcript. It
uses the real LLM proxy and produces the same story schema.

Each formal scenario ships with at least one verified deterministic story and
one recorded OpenCode story. The live demo may use a currently available model,
but replay never depends on model availability.

## 14. Provider Execution and Code Sandbox

All production and contest provider execution goes through one typed
`ProviderExecutor` interface. The current mediated external MCP adapter is
wired into that entry point rather than remaining a test-only path.

Contest tools remain:

- sandboxed file read/write;
- local mbox email;
- simulated API and browser;
- local memory and knowledge store;
- bounded code execution.

The Linux code-execution demo uses a low-privilege worker with:

- a dedicated user or user namespace;
- mount namespace and read-only base filesystem;
- workspace-only writable mount;
- `no_new_privs`;
- seccomp filtering;
- Landlock filesystem restrictions when available;
- cgroup CPU and memory limits;
- wall-time and output limits;
- no direct network capability;
- process-tree cleanup.

Network access, when a code scenario explicitly permits it, must go through a
Runwarden-controlled broker rather than a direct worker socket.

## 15. Evidence, Privacy, and Export

The live database may retain full arguments required for execution, but the Web
API and exported story use only redacted argument views plus hashes. Secret
values never appear in static HTML.

Full arguments are stored as private operation material, separate from the
event table. A story event is redacted before its initial hash is calculated;
export therefore verifies the original event chain without rewriting payloads.

A story export contains:

```text
story.json
events.jsonl
report.json
report.md
model-transcript.jsonl
mcp-transcript.jsonl
environment-manifest.json
public-key.pem
manifest.json
SHA256SUMS
```

Export verifies the event chain, report claims, and scenario assertions before
writing the final manifest. It signs the final story-chain head and manifest.
The Rust bundle verifier checks checksums and signature before regenerating an
offline console or upgrading a bundle's verification result.

The signing key is generated for a contest workspace, stored outside exported
artifacts with owner-only permissions, and never included in the bundle. The
public key and key identifier are exported. Static HTML displays `VERIFIED AT
EXPORT` rather than claiming it has re-verified itself. Fresh verification is
performed by the included Rust `runwarden bundle verify` command; live mode
displays the current Rust API verification result.

## 16. Evaluation

The evaluation report includes:

- attack success rate;
- benign task completion rate;
- malicious-sample recall;
- benign false-positive rate;
- approval correctness;
- policy-decision correctness;
- side-effect truth accuracy;
- trace completeness;
- report citation accuracy;
- kernel decision latency;
- proxy end-to-end p50 and p95 latency;
- exact PASS, FAIL, ERROR, and SKIP counts.

Filter evaluation separates a frozen development corpus from a held-out test
corpus. The test corpus includes English and Chinese paraphrases, Unicode and
spacing mutations, short and nested encodings, long-context injections, and
hard benign security-analysis requests. A documented subset of public agent
security benchmarks supplements the local scenarios.

Every imported benchmark subset records source revision, license, selection
rule, transformation script version, and corpus digest. Unredistributable
samples are represented by a reproducible fetch/transform manifest rather than
copied into the submission package.

The isolated contest environment supports two comparison modes:

- `monitor-only`, which records the simulated side effect that an unprotected
  path would attempt; and
- `enforced`, which applies Runwarden policy.

The WebUI may present an A/B comparison in analyst mode, but the primary live
story remains the enforced path.

## 17. Error Handling and Recovery

- Journal failure before execution: do not execute and return a structured
  state-store error. A later health event may record the outage interval, but
  Runwarden does not invent an operation event that was never durably accepted.
- Approval timeout: expire the approval and return a structured error.
- Provider failure with proven no side effect: terminal `failed`.
- Possible side effect with missing durable result: terminal
  `outcome_unknown`.
- Invalid trace or export signature: read-only `evidence_invalid` mode.
- Unresolved model-to-tool causality: display and report as unresolved; never
  infer a link.
- Replay schema incompatibility: reject with the supported schema range.
- SSE disconnect: reconnect using the last committed story sequence.
- Frontend failure: the Rust API and exported evidence remain authoritative.

## 18. Target Repository Structure

```text
crates/runwarden-kernel/src/
  authority.rs
  operation.rs
  policy.rs
  resource.rs
  session.rs
  trace.rs

crates/runwarden-state/src/
  migrations.rs
  store.rs
  operations.rs
  approvals.rs
  events.rs

crates/runwarden-runtime/src/
  context.rs
  operation.rs
  approval.rs
  errors.rs

crates/runwarden-mcp/src/
  server.rs
  tools.rs
  provider_call.rs
  approval_wait.rs
  config.rs

crates/runwarden-providers/src/
  catalog/
  input/
  runtime/
  adapters/
  demo_tools/

crates/runwarden-cli/src/
  commands/
  scenario/
  web_server/
  export/

webui/src/
  contracts/generated.ts
  api/
  app/
  features/story/
  features/authority/
  features/approval/
  features/evidence/
  features/replay/
  components/
  styles/
```

Large existing Rust files are split only while their affected behavior is
migrated. Unrelated code is not reorganized merely to match this target tree.

## 19. Migration Strategy

### Milestone A: Story Contract and WebUI Foundation

- define Rust story contracts and generated schemas;
- add a Rust `LegacyStoryAdapter` for current demo artifacts;
- create the React application shell and design system;
- implement story rail, authority panel, approval record view, evidence view,
  presentation mode, and analyst mode;
- replace the existing static console output without changing enforcement.

Exit criterion: the new WebUI fully renders all existing five scenario
artifacts in static mode at 1366x768 and 1920x1080.

### Milestone B: Journal and State Machines

- add `runwarden-state` and migrations;
- persist stories, sessions, operations, approvals, and events;
- implement atomic state versions and approval leases;
- make MCP and LLM proxy write the same active story;
- retain JSONL export as a compatibility surface.

Exit criterion: concurrent consumers cannot double-spend approval, and a story
trace remains ordered and verifiable.

### Milestone C: Live Authority and Approval

- expose authority snapshots and policy checks;
- add live WebUI APIs and SSE resume;
- make MCP wait for reviewer decisions;
- resume the same operation after approval;
- implement expiry, denial, disconnect, and unknown-outcome behavior;
- demonstrate exactly-once local email execution.

Exit criterion: OpenCode request, review, approval, execution, consumption, and
report citation complete as one operation without manual command repetition.

### Milestone D: Real Scenario Runner

- migrate the hero story first;
- make scenario execution consume attack and environment inputs;
- separate driver inputs from assertions;
- add deterministic and OpenCode drivers;
- migrate the remaining existing scenarios;
- add the code-execution scenario;
- record signed story bundles.

Exit criterion: no formal scenario derives execution from expected provider
calls, and all six validate actual generated events.

### Milestone E: Provider and Sandbox Integration

- introduce the unique provider-executor path;
- connect the external MCP adapters;
- enforce typed resource claims;
- add bounded code execution and Linux isolation;
- add idempotency and crash tests for contest providers.

Exit criterion: legitimate code runs while out-of-root file, direct network,
child-process, and resource-exhaustion attacks are blocked and visible.

### Milestone F: Evaluation

- split development and held-out corpora;
- add public benchmark subsets and mutation cases;
- implement monitor-only and enforced runs;
- calculate security, utility, correctness, and latency metrics;
- connect aggregate metrics to run and corpus hashes.

Exit criterion: every displayed metric can be reproduced from a named run,
corpus digest, command, and story set.

### Milestone G: Submission Hardening

- build release binaries and WebUI assets;
- pin OpenCode and all dependencies;
- add preflight and demo commands;
- include live and fallback instructions;
- include source or release executables in the contest package;
- verify the package from a clean directory;
- remove stale docs and unreferenced misleading images;
- align version and license metadata.

Exit criterion: a clean supported machine can run the live demo or open a
verified replay using only the submission instructions and included artifacts.

## 20. Verification Strategy

The final gate includes:

```bash
cargo test --workspace
cargo test --workspace -- --ignored
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
bash scripts/contest_bundle.sh
pnpm --dir webui lint
pnpm --dir webui test
pnpm --dir webui build
pnpm --dir webui test:e2e
```

Required new test classes are:

- legal and illegal operation transitions;
- two-process approval contention;
- crash points before lease, after lease, after effect, and before completion;
- event sequence and chain integrity under concurrent writers;
- server-owned session and authority enforcement;
- model/tool causal linking and explicit unresolved links;
- parameter changes invalidating approval;
- provider-specific resource extraction;
- secret redaction in API, HTML, report, and bundle;
- live and replay semantic equivalence;
- WebUI layout at minimum and presentation resolutions;
- keyboard and non-color approval access;
- all six scenario property assertions;
- clean-directory contest package reproduction.

## 21. Delivery Estimate and Parallel Work

The conservative single-team estimate is eighteen to twenty-two engineering
weeks. Twelve to sixteen weeks is an aggressive calendar only when independent
streams can run in parallel after the story schema is stable:

- Rust journal/runtime stream;
- WebUI stream;
- scenario/evaluation stream.

The primary usable checkpoints are:

1. Milestone A: materially improved presentation;
2. Milestone C: real approval narrative;
3. Milestone D: non-circular contest evidence;
4. Milestone G: submission readiness.

## 22. Key Risks and Mitigations

### Frontend Work Delays Security Work

Mitigation: Milestone A uses a legacy adapter, allowing the WebUI and Rust
journal work to proceed independently after the contract is frozen.

### Live Model Behavior Is Unstable

Mitigation: deterministic and recorded modes use the same runtime and UI.
Preflight always verifies a signed fallback story before a live presentation.

### SQLite Becomes Unnecessary Platform Scope

Mitigation: the database is local, embedded, and limited to the contest story,
approval, and trace lifecycle. It does not model organizations or remote state.

### Approval Wait Is Incompatible With a Client

Mitigation: the canonical operation remains queryable by ID. A client that
cannot hold the call receives the pending operation ID and can poll or resume
without creating a second operation.

### Code Sandbox Consumes Too Much Time

Mitigation: code execution is isolated as Milestone E. The rest of the contest
story remains shippable, but final compliance with the code-execution portion
requires the Linux scenario to pass before Milestone G.

### Signed Export Is Mistaken for Host Compromise Protection

Mitigation: documentation states that signing protects exported evidence
integrity and provenance after finalization. It does not claim to protect a host
where the signer and state directory are already compromised.

## 23. Final Acceptance Criteria

The refactor is accepted only when all of the following are true:

- the hero story demonstrates allow, deny, reviewer deny, reviewer approve,
  one-shot execution, side-effect truth, evidence verification, and cited
  reporting;
- the WebUI first screen exposes the entire security story and authority state;
- live and recorded stories render through the same components;
- all six formal scenarios consume their attacks and validate generated events;
- no formal scenario is driven by expected provider-call output;
- approval survives concurrency without double execution;
- model and provider evidence share an authoritative story and session;
- evidence gaps remain visible and prevent favorable report claims;
- the Linux code-execution scenario proves bounded allowed execution and denied
  escape attempts;
- held-out evaluation reports both security and benign utility;
- all Rust, Python, WebUI, scenario, release, and bundle gates pass;
- a clean-machine reviewer can complete the documented eight-minute live or
  replay demonstration.
