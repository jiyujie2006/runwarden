# Runwarden Docs

This index is the canonical map for the contest edition.

## Start Here

- [Overview](00-overview.md): contest scope and proof loop.
- [Agent Security Kernel](01-agent-security-kernel.md): Rust-owned enforcement path.
- [Submission Map](02-xa-202620-submission-map.md): reviewer package map.
- [Evaluation Results](03-evaluation-results.md): scenario metrics and evidence.

## Operate The Demo

- [CLI Reference](reference/cli.md): sessions, providers, trace, reports, scenarios, demo runner, and static/live UI.
- [CI](reference/ci.md): local and GitHub gate commands.
- [Contest Review Outputs](reference/contest-review-outputs.md): generated evidence artifacts.
- [MCP Reference](reference/mcp.md): exact agent-facing MCP tools and provider-call replay evidence.
- [Reviewer Console](reference/webui-review-console.md): static and live demo console contract.
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

- [JSON Contracts](reference/json-contracts.md): Rust schema artifacts.
- [Rust Kernel and TypeScript Interaction](reference/rust-kernel-ts-interaction.md): Rust-owned policy with presentation-only TypeScript.
- [Kernel Manifest](reference/kernel-manifest.md)
- [Assessment Manifest](reference/assessment-manifest.md)
- [Provider Manifest](reference/provider-manifest.md)
- [Artifact Manifest](reference/artifact-manifest.md)

## Development

- [Contest Verification](development/contest-verification.md)
- [Repository Review](repository-review.md)
- [Roadmap](reference/roadmap.md)

## Examples And Red-Team

- [Provider Examples](../examples/providers/README.md)
- [Report Examples](../examples/reports/README.md)
- [Scenario Examples](../examples/scenarios/README.md)
- [Red-Team Harness](../redteam/README.md)

## Scenario Fixtures

- [Prompt Injection File Exfiltration](../scenarios/prompt-injection-file-exfil/README.md)
- [Tool Hijack Email API](../scenarios/tool-hijack-email-api/README.md)
- [Memory Knowledge Poisoning](../scenarios/memory-knowledge-poisoning/README.md)
- [Environment Local Web Risk](../scenarios/environment-local-web-risk/README.md)

## Maintenance Rules

- Security decisions stay in Rust crates.
- TypeScript presents Rust-produced demo state and must not reimplement allow/deny policy.
- Keep this index aligned with CLI, MCP, provider, report, approval, and WebUI behavior.
