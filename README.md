# Runwarden Enterprise

Runwarden is an agent-native security kernel. Agents see only Runwarden, every
tool becomes a kernel-managed provider, and Rust owns all enforcement decisions.

Core commitments:

- Agent default exposure is only Runwarden skill plus `runwarden-mcp`.
- Every provider call goes through the Rust kernel enforcement path.
- TypeScript makes the control plane usable but never owns allow/deny logic.
- CLI and WebUI are human control planes for setup, approval, audit, review, and release.
- Reports must cite verified `obs_*` observations.

Current implementation status: enterprise v1 implementation with local release
gate coverage.

## What Shipped

- Rust security kernel contracts for provider calls, outcomes, operation
  results, approval records, trace events, sessions, manifests, and artifacts.
- Kernel enforcement gates for provider registry, allowlist, scoped roots,
  private egress, budgets, active assessments, authz, and single-use approvals.
- Append-only `obs_*` trace verification and cited-report enforcement.
- First-party provider surface for input, evidence, trace, report, audit,
  accountability, cert, eval, and bench workflows.
- MCP adapter exposing only `runwarden.*` tools with MCP `structuredContent`,
  `isError`, and protocol/tool-error separation.
- Human control plane CLI for session, provider, trace, report, eval, cert,
  bench, approval, artifact submission/verification, release smoke, and UI
  launch checks.
- Local API security primitives for launch-token, Host/Origin, approval
  mutation, approval queue, one-time artifact download tokens, relative
  workspace artifact roots, and reviewer-console HTML escaping.
- TypeScript SDK, config tools, MCP helpers, and a dependency-free reviewer
  console renderer.
- Hardened external MCP adapters for trusted stdio roots, exact command
  allowlists, DNS-rebinding-resistant egress checks, bounded frames/output, and
  process-tree cleanup.
- CI/release evidence gates with schema drift checks, cert, bench, artifact
  leak scanning, and release smoke coverage.

## Quick Checks

```bash
scripts/dev_gate.sh
scripts/release_gate_local.sh
target/debug/runwarden check --strict
target/debug/runwarden cert all --json
target/debug/runwarden eval agent-native --json
target/debug/runwarden bench run --json
target/debug/runwarden artifact submission --full --output artifacts --json
target/debug/runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json
```

## Agent Boundary

Agents should receive only the Runwarden skill and `runwarden-mcp`. Raw shell,
filesystem, browser, HTTP, and downstream MCP tools are not exposed by default.
Use `runwarden.provider.call` or the narrower Runwarden MCP tools for mediated
work.
