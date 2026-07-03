# Repository Review

Review date: 2026-07-01

This snapshot covers the contest-edition refactor. It is a repository and
documentation review oriented around the red-team range workflow.

## Scope

Reviewed surfaces:

- Rust crates under `crates/`.
- The Rust-served reviewer console.
- Scenario golden corpora, schemas, scripts, GitHub workflows, and maintained
  docs.

## Architecture Findings

Runwarden keeps the public workflow centered on:

- Rust-owned security decisions through `runwarden-kernel`,
  `runwarden-providers`, `runwarden-assurance`, `runwarden-cli`, and
  `runwarden-mcp`.
- A narrow agent-facing MCP boundary that exposes only Runwarden tools.
- Five deterministic attack scenarios under `scenarios/`.
- Trace-backed report lint/render and static WebUI presentation.

The code and tests support the maintained invariants:

- Provider calls are checked against registry and session allowlists before
  side effects.
- Scoped roots, egress, budgets, active assessment, authz, and approval gates
  are enforced by the Rust kernel.
- High-risk approvals are bound to session, provider, action, argument hash,
  authz, and actor, and are single-use.
- Trace export and report rendering are evidence-gated.
- Demo/report/UI output paths reject absolute paths, parent traversal, and
  symlink escapes.
- Agents see Runwarden MCP, not raw shell, filesystem, browser, HTTP, or
  downstream MCP tools.

## Verification Cadence

For normal changes:

```bash
bash scripts/pr_fast_gate.sh
```

For contest evidence changes:

```bash
bash scripts/release_gate_local.sh
```

For focused local checks:

```bash
cargo test --workspace
target/debug/runwarden check --strict --json
target/debug/runwarden demo --all --output artifacts/demo --json
```

## Ponytail Cleanup Review

This cleanup pass focused only on confirmed over-engineering: unused
dependencies, dead helper APIs, duplicated fixtures, and hand-written helpers
that standard library or existing local patterns already cover. The security
path was kept explicit.

Outcome:

- Removed unused direct dependencies from provider, kernel, CLI, anomaly, and
  assurance crates, then refreshed `Cargo.lock`.
- Deleted unused kernel helper constructors and trace/artifact accessors that
  had no call sites and were not part of generated schema contracts.
- Collapsed repeated external MCP stdio test manifest setup behind one typed
  fixture helper while preserving command allowlist, trusted-root, no-shell,
  bounded-output, timeout, cleanup, and private-host denial coverage.
- Replaced small custom helpers with native behavior in CLI, MCP, proxy, and
  WebUI code where tests proved equivalent semantics.
- Consolidated duplicate WebUI contract tests while keeping focused coverage
  that trace verification comes only from Rust-produced
  `trace_verification.verified`, not from trace presence or lint success.
- Kept `scripts/release_gate_local.sh` explicit because `check --strict`
  intentionally validates literal demo-run commands. Only the safe
  `contest_bundle.sh` red-team manifest duplication was removed.

Net branch shape for the cleanup: 21 tracked files changed, 125 insertions,
680 deletions.

Modification plan used:

1. Remove unused manifest dependencies and verify the workspace still builds.
2. Remove dead kernel helpers only after confirming no call sites or schema
   surface dependency.
3. Shrink provider adapter fixtures without weakening external MCP adapter
   invariants.
4. Shrink small CLI, MCP, and proxy helper code with standard library behavior
   and retain targeted regression tests.
5. Merge duplicate WebUI tests into the renderer test and preserve the
   Rust-owned policy boundary in fixtures.
6. Shrink gate/bundle scripts only where local strict checks and generated
   artifact behavior remain unchanged.
7. Run project gates and an independent full-branch review before integration.

Required verification for this class of cleanup remains:

```bash
cargo fmt --check
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

## Residual Risks

- Real LLM adapters are out of scope for the default demo path; adding one must
  keep provider policy in Rust.
- Full verification depends on local Rust, Python, and `cargo-deny`
  availability.
