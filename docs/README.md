# Runwarden Docs

This index is the canonical map for the contest edition.

## Start Here

- [Overview](00-overview.md): contest scope and proof loop.
- [Agent Security Kernel](01-agent-security-kernel.md): Rust-owned enforcement path.
- [Submission Map](02-xa-202620-submission-map.md): reviewer package map.
- [Evaluation Results](03-evaluation-results.md): scenario metrics and evidence.
- [Contest Submission](contest/README.md): scorecard, reproduction, demo script, artifacts, and limitations.
- [Red-Team Results](contest/redteam-results.md): deterministic proxy/output probe coverage and result artifacts.

## Operate The Demo

- [CLI Reference](reference/cli.md): demo, trace, report, and check commands.
- [CI](reference/ci.md): local and GitHub gate commands.
- [Contest Review Outputs](reference/contest-review-outputs.md): generated evidence artifacts.
- [MCP Reference](reference/mcp.md): exact agent-facing MCP tools and provider-call replay evidence.
- [Reviewer Console](reference/webui-review-console.md): Rust-served interactive and static console contract.
- [Reviewer Console Guide](guides/reviewer-console.md): operator walkthrough.
- [Agent Integration](reference/agent-integration.md): Runwarden-only MCP config shape and OpenCode fixture.
- [First Scenario](reference/first-scenario.md): scenario folder contract.

## Security Model

- [Threat Model](reference/threat-model.md): adversarial assumptions and mitigations.
- [Security Risk Analysis Report](security-risk-analysis-report.md): LLM application attack analysis, red-team evidence, and Runwarden supervision prototype notes.
- [Agent Tool Boundary](concepts/agent-tool-boundary.md): why agents receive Runwarden instead of raw tools.
- [Authority and Session](reference/authority-and-session.md): session allowlists and approval records.
- [Provider Model](reference/provider-model.md): first-party and demo/external providers.
- [Provider Integration](reference/provider-integration.md): mediated external adapter requirements.
- [Provider Contract](reference/provider-contract.md): manifest-derived enforcement contract.
- [Evidence and Accountability](reference/evidence-and-accountability.md): `obs_*` semantics and report citations.

## Contracts

- [JSON Contracts](reference/json-contracts.md): Rust schema artifacts,
  including security-story and detached-signature bundle contracts.
- [Rust Kernel and TypeScript Interaction](reference/rust-kernel-ts-interaction.md): Rust-owned policy with no active TypeScript policy surface.
- [Kernel Manifest](reference/kernel-manifest.md)
- [Assessment Manifest](reference/assessment-manifest.md)
- [Provider Manifest](reference/provider-manifest.md)
- [Artifact Manifest](reference/artifact-manifest.md)

## Development

- [Contest Verification](development/contest-verification.md)
- [Repository Review](repository-review.md)
- [Roadmap](reference/roadmap.md)
- [Approved Security Story Workbench Design](superpowers/specs/2026-07-10-runwarden-contest-security-story-workbench-design.md)
- [Long-Term Refactor Plan Index](superpowers/plans/2026-07-10-runwarden-contest-refactor-plan-index.md)

## Examples And Red-Team

- [Provider Examples](../examples/providers/README.md)
- [Report Examples](../examples/reports/README.md)
- [Scenario Examples](../examples/scenarios/README.md)
- [Supplemental Anomaly Scenario](../examples/scenarios/anomalous-provider-sequence/README.md)
- [Red-Team Harness](../redteam/README.md)

## Scenario Fixtures

- [Prompt Injection File Exfiltration](../scenarios/prompt-injection-file-exfil/README.md)
- [Tool Hijack Email API](../scenarios/tool-hijack-email-api/README.md)
- [Memory Knowledge Poisoning](../scenarios/memory-knowledge-poisoning/README.md)
- [Environment Local Web Risk](../scenarios/environment-local-web-risk/README.md)
- [Path Escape File Boundary](../scenarios/path-escape-file-boundary/README.md)

## Maintenance Rules

- Security decisions stay in Rust crates.
- Browser code, and any future TypeScript, may present Rust-produced demo state but must not reimplement allow/deny policy.
- Keep this index aligned with CLI, MCP, provider, report, approval, and WebUI behavior.
