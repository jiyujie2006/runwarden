# Repository Review

Review date: 2026-06-29

This snapshot covers the contest-edition refactor. It is a repository and
documentation review oriented around the red-team range workflow.

## Scope

Reviewed surfaces:

- Rust crates under `crates/`.
- The active TypeScript package `packages/webui`.
- Scenario golden corpora, schemas, scripts, GitHub workflows, and maintained
  docs.

## Architecture Findings

Runwarden keeps the public workflow centered on:

- Rust-owned security decisions through `runwarden-kernel`,
  `runwarden-providers`, `runwarden-assurance`, `runwarden-cli`, and
  `runwarden-mcp`.
- A narrow agent-facing MCP boundary that exposes only Runwarden tools.
- Four deterministic attack scenarios under `scenarios/`.
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
pnpm test
pnpm build
target/debug/runwarden eval scenarios --json
```

## Residual Risks

- Real LLM adapters are out of scope for the default demo path; adding one must
  keep provider policy in Rust.
- Full verification depends on local Rust, pnpm, Node, and `cargo-deny`
  availability.
