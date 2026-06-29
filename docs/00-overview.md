# Overview

Runwarden is a contest-focused red-team range for agent tool-use security. It
routes agent actions through a Rust enforcement kernel, records the resulting
`obs_*` evidence, and renders trace-backed reports and a static reviewer
console.

## Problem

Agents can be induced to read files, call APIs, send messages, open pages, or
trust poisoned memory. Prompt-only guardrails do not prove:

- which tools the agent could see
- which provider calls were denied before side effects
- which calls required approval
- which `obs_*` events support each report claim
- whether localhost, private network, or metadata-service egress was blocked

Runwarden makes those answers reproducible from checked-in scenarios.

## Workspace Components

- `runwarden-kernel`: Rust source of truth for sessions, provider policy,
  approvals, trace events, path safety, and contract types.
- `runwarden-providers`: first-party providers plus mediated demo/external
  provider catalog.
- `runwarden-assurance`: scenario evaluation plus report lint/render helpers.
- `runwarden-cli`: contest control plane for sessions, providers, traces,
  reports, scenarios, deterministic demos, and static UI output.
- `runwarden-mcp`: the only MCP boundary exposed to agents.
- `packages/webui`: presentation-only static reviewer console renderer.

## Proof Loop

1. Create a manifest-backed session.
2. Let the deterministic demo agent propose provider calls.
3. Evaluate every call through Rust kernel/provider policy.
4. Record allowed, denied, and review-blocked outcomes as `obs_*` trace events.
5. Verify the trace hash chain before export or report use.
6. Lint report claims against verified observation references.
7. Render a suite report and static reviewer console from demo JSON.

## Local Gates

```bash
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

The release-style local gate runs fast Rust/TypeScript checks, strict repository
validation, scenario evaluation, deterministic demo generation, contest report
rendering, and static reviewer-console build.

## Reading Path

- Operators should read [CLI Reference](reference/cli.md) and
  [Reviewer Console Guide](guides/reviewer-console.md).
- Agent integrators should read [MCP Reference](reference/mcp.md) and
  [Agent Integration](reference/agent-integration.md).
- Security reviewers should read [Agent Security Kernel](01-agent-security-kernel.md),
  [Threat Model](reference/threat-model.md), and
  [Evidence and Accountability](reference/evidence-and-accountability.md).
