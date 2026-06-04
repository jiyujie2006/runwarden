# Overview

Runwarden is an agent-native security runtime for MCP and Skill-driven agents.
It routes agent tool use through a Rust enforcement kernel so every meaningful
decision can be approved, audited, cited, and reproduced.

## Problem

Enterprise agents can read files, open web pages, call APIs, run tools, load
skills, and produce reports. Prompt-only guardrails do not reliably answer these
questions:

- Which tools was the agent allowed to see?
- Which provider calls were denied before side effects?
- Which reviewer approved a high-risk action?
- Which `obs_*` events support a report claim?
- Which artifacts were sealed, redacted, and verified?

Runwarden makes those questions first-class runtime contracts.

## Workspace Components

- `runwarden-kernel`: Rust source of truth for manifests, sessions, provider
  outcomes, policy gates, approvals, trace events, and artifact primitives.
- `runwarden-providers`: first-party provider catalog plus mediated external
  provider adapter contracts.
- `runwarden-assurance`: report lint/render/scaffold, eval, cert, bench, audit,
  accountability, artifact sealing, and artifact verification.
- `runwarden-cli`: human control plane for local review, release evidence, and
  repository checks.
- `runwarden-mcp`: agent-facing MCP boundary that exposes only `runwarden.*`
  tools.
- `runwarden-api`: token-protected Local API used by the Reviewer Console and
  SDK.
- `packages/agent-sdk`: TypeScript client and generated Rust contract
  declarations.
- `packages/webui`: dependency-free static Reviewer Console renderer.
- `packages/config-tools`: TypeScript helper for invoking Rust-owned
  agent-config certification.

## Proof Loop

Runwarden's proof loop is:

1. Create a manifest-backed session.
2. List kernel-managed providers for that session.
3. Evaluate every provider call through the kernel.
4. Record allowed, denied, failed, and review decisions as `obs_*` trace events.
5. Verify the trace hash chain before export or report use.
6. Lint report claims against verified observation references.
7. Seal artifacts with hashes and redaction sidecars.
8. Run eval, cert, bench, and release gates.

## Local Gates

Fast development and PR checks use:

```bash
bash scripts/dev_gate.sh
bash scripts/pr_fast_gate.sh
```

The release-style local gate uses:

```bash
bash scripts/release_gate_local.sh
```

It adds `runwarden check --strict`, cert, eval, scenario golden-corpus eval,
agent-native eval, bench, release smoke, artifact submission, artifact
verification, and leak scan.

## Reading Path

- New reviewers should start with [Repository Review](repository-review.md).
- Operators should read [CLI Reference](reference/cli.md) and
  [Reviewer Console Guide](guides/reviewer-console.md).
- Agent integrators should read [MCP Reference](reference/mcp.md) and
  [Agent Integration](reference/agent-integration.md).
- Security reviewers should read [Agent Security Kernel](01-agent-security-kernel.md),
  [Threat Model](reference/threat-model.md), and
  [Evidence and Accountability](reference/evidence-and-accountability.md).
