# Runwarden Contest Refactor Plan Index

This index turns the approved [Security Story Workbench design](../specs/2026-07-10-runwarden-contest-security-story-workbench-design.md)
into twelve implementation plans. The plans are deliberately smaller than the
design milestones: each one ends at a merge checkpoint with independently
testable behavior.

## Outcome

Runwarden will remain a contest-sized Rust security kernel while gaining one
clear, reviewable story:

```text
attack -> model -> proposed tool -> typed resource -> Rust policy
       -> reviewer decision -> one-shot execution -> verified evidence/report
```

The React WebUI presents that story in live and replay modes. It never owns
allow, deny, approval-validity, evidence-validity, or report-support logic.

## Frozen Implementation Decisions

These decisions remove ambiguities that would otherwise make the plans define
incompatible contracts.

1. New story contracts use schema version `1.0.0`. During this refactor,
   readers accept `1.x` and reject every other major version.
2. New identifiers are UUIDv7 strings wrapped by Rust newtypes:
   `StoryId`, `SessionId`, `OperationId`, `EventId`, `ApprovalId`, and
   `ExecutionLeaseId`. `ObservationId` serializes as `obs_<UUIDv7>`. All
   newtype fields are private and deserialization rejects non-v7 UUIDs.
3. `StoryStatus`, `EvidenceStatus`, `SideEffectState`, `RunMode`, and
   `EnforcementMode` are distinct enums. The existing
   `OperationStatus`, `ExecutionStatus`, and `side_effect_executed` fields
   remain legacy compatibility surfaces until Plan 12.
4. Story events are born redacted. Their hash material contains a redacted
   payload and the full-argument SHA-256 commitment, never full arguments.
   Private execution arguments live in a separate non-exported operation
   column. Export never rewrites a hashed event.
5. Replay consumes Rust-produced `StoryReplayFrame` snapshots keyed by committed
   event sequence. TypeScript selects frames; it never reduces events into
   security state.
6. Runwarden Canonical JSON v1 recursively sorts object keys by UTF-8 byte
   order and uses compact `serde_json` encoding. Golden vectors lock this
   algorithm before any database or signature work starts.
7. Bundle signatures use Ed25519. `manifest.sig` signs the canonical bytes of
   `manifest.json`; `key_id` is the first 32 hexadecimal characters of the
   SHA-256 digest of the public-key bytes. `SHA256SUMS` covers every bundle
   file except itself.
8. One state directory has at most one active demo instance. MCP and the LLM
   proxy cache the server-owned active story, session, and instance token at
   startup. A second live demo against that directory fails closed.
9. Reviewer nonces are random 256-bit values scoped to one server process.
   They are returned only by loopback bootstrap, required in the
   `X-Runwarden-Reviewer-Nonce` header, and invalid after server restart.
10. Approval becomes `leased` when a CAS reserves it. It becomes `consumed` in
   the same durable transaction that writes the execution-start intent,
   before the provider runs. A crash after that transaction recovers as
   `outcome_unknown`, never as retryable approval.
11. MCP adds `runwarden.operation.status` and
    `runwarden.operation.resume`. Resume loads the private frozen request by
    operation id and never accepts replacement provider arguments.
12. Local contest email uses one immutable receipt file per operation id. A
    mailbox view is derived from receipts, so retry and reconciliation cannot
    append duplicate messages.
13. A/B evaluation forks the same recorded proposal set. Monitor-only runs
    stop before approval/lease/execution-start, use a non-executor observer,
    record `simulated_would_execute`, and never call a side-effecting executor.

## Plan Set

| Order | Plan | Primary merge checkpoint | Estimate |
| ---: | --- | --- | ---: |
| 1 | [Story contracts and legacy adapter](2026-07-10-runwarden-01-story-contracts-legacy-adapter.md) | Stable Rust/JSON story v1 | 1.5 weeks |
| 2 | [SQLite operation journal](2026-07-10-runwarden-02-sqlite-operation-journal.md) | Durable ordered state and CAS | 2 weeks |
| 3 | [Typed claims and ProviderExecutor](2026-07-10-runwarden-03-typed-claims-provider-executor.md) | One pre-side-effect executor boundary | 1.5 weeks |
| 4 | [Durable MCP and reviewer API](2026-07-10-runwarden-04-durable-mcp-reviewer-api.md) | Same-operation approval and resumable SSE | 2 weeks |
| 5 | [LLM proxy story events](2026-07-10-runwarden-05-llm-proxy-story-events.md) | Model and tool causal evidence | 1 week |
| 6 | [Signed story bundles](2026-07-10-runwarden-06-signed-story-bundles.md) | Rust-verified portable replay input | 1 week |
| 7 | [Reviewer WebUI](2026-07-10-runwarden-07-reviewer-webui.md) | First-screen live/replay security story | 2.5 weeks |
| 8 | [Non-circular scenario runner](2026-07-10-runwarden-08-non-circular-scenario-runner.md) | Hero plus five migrated scenarios | 2 weeks |
| 9 | [Linux sandbox and sixth scenario](2026-07-10-runwarden-09-linux-sandbox-code-scenario.md) | Bounded code execution evidence | 1.5 weeks |
| 10 | [Held-out evaluation and A/B](2026-07-10-runwarden-10-heldout-evaluation-ab.md) | Reproducible security/utility metrics | 1.5 weeks |
| 11 | [Performance evidence](2026-07-10-runwarden-11-performance-evidence.md) | Reproducible latency/throughput report | 1.5 weeks |
| 12 | [Release and submission hardening](2026-07-10-runwarden-12-release-submission-hardening.md) | Clean-room eight-minute submission | 2 weeks |

The serial total is approximately twenty weeks including review and
stabilization. With the parallel waves below, the aggressive calendar is
twelve to sixteen weeks; the conservative single-team range is eighteen to
twenty-two weeks and is the safer competition commitment.

## Dependency Graph

```text
P1 Contracts
|- P2 Journal --------+-- P4 MCP/API -> P5 Proxy -> P6 Bundles
|- P3 Claims/Executor +-- P4                         |
|- P7 WebUI static

P4 + P6 + P7 ------> P7 WebUI live
P3 + P4 + P5 + P6 -> P8 Scenario runner
P2 + P3 -----------> P9 sandbox core
P8 Tasks 1-3 + P9 -> P9 deterministic sixth-scenario integration
P8 Task 5 + P9 deterministic scenario -> P9 OpenCode recording/checkpoint
P6 + P8 + P9 ------> P10 Evaluation (UI task also requires P7)
P2 + P3 + P4 + P5 + P6 -> P11 Performance
P1 through P11 ----> P12 Release
```

## Parallel Waves

- Wave 0: Plan 1 contract freeze only.
- Wave 1: Plans 2 and 3 plus Plan 7 static foundation in parallel.
- Wave 2: Plan 4; Plan 9 sandbox core may run independently after Plans 2-3.
- Wave 3: Plan 5, then Plan 6. Plan 7 static work continues in parallel.
- Wave 4: Plan 7 live mode and Plan 8 Tasks 1-3, then Plan 8 Task 5 before the
  Plan 9 OpenCode recording/checkpoint; deterministic Plan 9 scenario work and
  remaining Plan 8 migrations may proceed meanwhile.
- Wave 5: Plans 10 and 11 after their explicit prerequisites.
- Wave 6: Plan 12 only; feature work is frozen.

No parallel branch may invent a local copy of a Plan 1 contract. Contract
changes after Wave 0 require a schema-version decision and a cross-plan review.

Plans 4, 5, and 6 are intentionally serialized. This removes the prior
runtime/API/verifier cycle: Plan 4 provides structural evidence APIs, Plan 5
adds model/proposal evidence, and Plan 6 then installs full semantic
verification, transcripts, export, and protected export routes. The Plan 5
foreign-key link and operation insert commit in one state transaction.

## Uniform Global Gates

Every merge checkpoint runs the narrow tests named by its plan and then:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo deny check
cargo test --workspace --locked
python3 redteam/validate_corpora.py redteam/corpora/*.jsonl
python3 -m unittest discover
pnpm --dir webui lint
pnpm --dir webui typecheck
pnpm --dir webui test
pnpm --dir webui build
```

Before Plan 7 exists, the four `pnpm` commands are skipped by an explicit
`test -f webui/package.json` guard. After Plan 7 checkpoint 1, absence of the
package is an error.

The repository-level required gates remain:

```bash
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
cargo test --workspace
```

Plan 12 additionally requires `bash scripts/contest_bundle.sh` and a
clean-directory bundle verification.

## Evaluation And Performance Release Thresholds

These are contest release thresholds, not promises about production security:

- held-out coverage: at least 500 attack samples and 500 benign samples;
- independent inference units: at least 50 attack lineages, 50 benign
  lineages, and 10 lineages in every required category, keyed by
  `(source_id, lineage_id)`;
- attack-lineage recall lower bound of the 95% Wilson interval: at least
  `0.85`;
- benign-lineage false-positive upper bound of the 95% Wilson interval: at
  most `0.05`;
- tool mediation and approval correctness: `1.00` on formal scenarios;
- benign task-completion degradation from full enforcement: at most ten
  percentage points;
- kernel decision p95: under 2 ms on the fixed benchmark runner;
- journal propose/evaluate transaction p95: under 10 ms;
- total Runwarden policy-and-journal overhead p95: under 50 ms, excluding
  model and provider latency;
- committed event visible through SSE p95: under 500 ms.

Raw counts, denominators, confidence intervals, hardware, target triple,
corpus hash, git SHA, and command are always emitted. `ERROR`, `SKIP`, and
`outcome_unknown` never count as a successful security decision. Sample rates
are descriptive coverage metrics; only lineage-cluster Wilson intervals enter
the release decision.

## Supported Delivery Targets

- `x86_64-unknown-linux-gnu`: full live demo, OpenCode integration, and Linux
  code sandbox; primary contest target.
- Other architectures and operating systems may open the static HTML viewer,
  but this contest release does not claim native replay verification, live
  integration, or sandbox support on them. This is an intentional scope limit,
  not an inferred portability guarantee.

The Linux sandbox pins bubblewrap `0.11.0`, uses a Rust worker with
`no_new_privs`, seccomp-bpf, and Landlock, and requires delegated cgroup v2 for
the formal sandbox gate. Unsupported or degraded isolation returns an explicit
`sandbox_unavailable` result; it never executes unsandboxed code.

OpenCode recordings pin version `1.17.13`. The model id, provider, upstream
endpoint class, transcript digest, and recording time are captured. A
recording refresh is an explicit command and never occurs during an ordinary
release gate.

## Reviewer Ten-Second Rubric

At 1366x768 and 1920x1080, without scrolling, a reviewer must identify:

1. which scenario and attack are active;
2. which tool/resource was requested;
3. whether Rust allowed, denied, or held it;
4. whether a reviewer acted and whether a side effect occurred;
5. whether the evidence/report is verified.

Playwright enforces viewport presence for those five facts. Axe checks must
report no serious or critical issue, and every approval action must be
keyboard-operable with a visible focus indicator and a non-color status label.

## Legal Release Gate

The repository currently uses `LicenseRef-Runwarden-Proprietary`. Plan 12 may
prepare an Apache-2.0/MIT recommendation, but changing the license requires an
explicit owner decision. Until then, submission text must not call Runwarden
itself open source; it may accurately state that Runwarden integrates the
open-source OpenCode application.
