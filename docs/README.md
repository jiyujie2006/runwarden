# Runwarden Docs

This index is the canonical map for Runwarden documentation. Keep it grouped by
reader task so reviewers, contributors, and agent integrators can find the
right page without reading the whole repository.

## Start Here

- [Overview](00-overview.md): product scope, workspace components, and proof loop.
- [Repository Review](repository-review.md): current architecture, quality, docs,
  and verification review.
- [Agent Security Kernel](01-agent-security-kernel.md): kernel-owned enforcement
  path and invariants.
- [Evaluation Results](03-evaluation-results.md): assurance metrics and expected
  release baselines.
- [XA-202620 Submission Map](02-xa-202620-submission-map.md): competition or
  review package mapping.

## Operate Runwarden

- [CLI Reference](reference/cli.md): command surface for sessions, providers,
  approvals, reports, artifacts, eval, cert, bench, UI, and API.
- [MCP Reference](reference/mcp.md): agent-facing MCP tools and JSON-RPC
  behavior.
- [Agent Integration](reference/agent-integration.md): Runwarden-only agent
  config rules and TypeScript helper boundaries.
- [Reviewer Console Guide](guides/reviewer-console.md): local WebUI review
  workflow.
- [WebUI Review Console](reference/webui-review-console.md): static console
  contract and presentation-only rules.

## Security Model

- [Agent Tool Boundary](concepts/agent-tool-boundary.md): why agents receive
  Runwarden instead of raw tools.
- [Threat Model](reference/threat-model.md): adversarial assumptions and
  mitigations.
- [Authority and Session](reference/authority-and-session.md): session-derived
  policy, actor-bound authz, and approval records.
- [Provider Model](reference/provider-model.md): first-party and external
  provider roles.
- [Provider Integration](reference/provider-integration.md): mediated adapter
  requirements for external providers.
- [Evidence and Accountability](reference/evidence-and-accountability.md):
  `obs_*` trace semantics, report citations, and responsibility chain.

## Contracts and Manifests

- [Rust Kernel and TypeScript Interaction](reference/rust-kernel-ts-interaction.md):
  Rust-owned schema generation and TypeScript contract consumption.
- [JSON Contracts](reference/json-contracts.md): checked schema inventory.
- [Kernel Manifest](reference/kernel-manifest.md): policy envelope at runtime.
- [Assessment Manifest](reference/assessment-manifest.md): assessment TOML
  inputs.
- [Provider Manifest](reference/provider-manifest.md): external provider
  identity, transport, permissions, and schema pins.
- [Provider Contract](reference/provider-contract.md): manifest-derived
  enforcement contract.
- [Artifact Manifest](reference/artifact-manifest.md): sealed artifact and
  redaction sidecar verification.

## Build, Release, and Governance

- [CI](reference/ci.md): pull request, manual full, and release gate behavior.
- [Release Process](development/release-process.md): local and GitHub release
  evidence flow.
- [Release Installation](reference/release-installation.md): named binaries and
  release artifacts.
- [Roadmap](reference/roadmap.md): completed scope and next depth.

## Examples and Scenarios

- [First Scenario](reference/first-scenario.md): scenario folder contract.
- [Scenario Examples](../examples/scenarios/README.md): checked-in scenario
  corpus overview.
- [Provider Examples](../examples/providers/README.md): provider manifest and
  catalog examples.
- [Report Examples](../examples/reports/README.md): report citation examples.
- [Enterprise Agent Security Scenario](../scenarios/enterprise-agent-security/README.md)
- [Offline Evidence Scenario](../scenarios/offline-evidence/README.md)
- [Local Web Risk Scenario](../scenarios/local-web-risk/README.md)
- [Knowledge Retrieval QA Scenario](../scenarios/knowledge-retrieval-qa/README.md)
- [Ops Collaboration Agent Scenario](../scenarios/ops-collaboration-agent/README.md)
- [Government Office Assistant Scenario](../scenarios/government-office-assistant/README.md)
- [Workflow Processing Agent Scenario](../scenarios/workflow-processing-agent/README.md)

## Maintenance Rules

- Keep security decisions in Rust crates. TypeScript may present, validate, or
  call Rust-owned contracts, but must not duplicate allow/deny policy.
- Before changing provider, report, artifact, approval, MCP, Local API, or
  Reviewer Console behavior, update the matching reference page in this index.
- Keep executable commands aligned with `scripts/dev_gate.sh`,
  `scripts/pr_fast_gate.sh`, and `scripts/release_gate_local.sh`.
- Do not remove reference pages listed here without also updating
  `runwarden check --strict` expectations.
