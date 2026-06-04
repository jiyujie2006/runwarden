# Changelog

All notable changes to Runwarden are documented in this file.

## [Unreleased]

### Changed

- Reworked repository documentation around a concise top-level README, grouped
  docs index, persistent repository review, expanded reference pages, and
  scenario/example README guidance.
- Redesigned the Reviewer Console WebUI around an assurance operations
  workspace with evidence mapping, timeline context, and searchable approval
  review controls.

### Fixed

- Fixed Windows workspace test failures by escaping manifest fixture paths,
  preserving scoped-root evidence paths relative to their configured root, and
  making provider runtime assertions platform-aware.
- Fixed Reviewer Console launch bundles to use file `launch_url` values, reject
  artifact path escapes, render pending approval state, and submit browser
  approve/deny decisions through the token-protected Local API.
- Preserved EOF-terminated multiline raw JSON support in `runwarden-mcp` while
  keeping bounded stdio frame reads.
- Aligned Rust and CLI agent-config certification with TypeScript config tools
  for malformed `args` and `transport` override rejection.
- Verified CLI-bound file digests before persisting consumed approval state.
- Clarified completed report-claim semantics so negated denial text does not
  require a denial observation.

## [0.1.0.0] - 2026-05-28

### Added

- Added the Runwarden enterprise Rust workspace with kernel enforcement, provider contracts, authority approvals, trace evidence, artifact sealing, assurance checks, CLI, MCP, and Local API crates.
- Added mediated provider surfaces for input, evidence, trace, report, audit, accountability, certification, eval, benchmark, and external-provider handoff paths.
- Added Local API and MCP boundaries that expose only Runwarden-managed operations, preserve side-effect state, require control-plane authorization, and route provider calls through kernel decisions.
- Added Reviewer Console view-model and static rendering packages, TypeScript SDK helpers, MCP helper utilities, and config safety tools.
- Added scenario fixtures, schema artifacts, security assessment skill packaging, CI gates, release evidence workflow, release smoke checks, and generated artifact verification.
- Added real external MCP stdio, HTTP, and SSE adapter execution contracts behind provider manifest allowlists and origin checks.
- Added dedicated `runwarden authority create` and `runwarden authority inspect` commands for bound approval records.
- Added complete scenario golden corpora, split reference documentation, generated TypeScript contract checks, `runwarden-kernel` binary, and WebUI responsive/accessibility gates.

### Fixed

- Prevented approval replay by persisting consumed approval state after Local API provider calls.
- Bound provider policy outcomes to deterministic `obs_*` IDs and trace event labels before side effects.
- Ensured MCP `runwarden.provider.call` respects kernel session allowlists before executing inline providers.
- Reported external providers without an adapter as incomplete instead of completed.
- Closed the recorded follow-up gaps from the initial plan completion audit.
- Hardened external MCP stdio execution, DNS rebinding/private egress checks, MCP stdio frame bounds, CLI approval file-digest binding, actor-bound authz, artifact/UI output path containment, reviewer-console HTML escaping, semantic redaction sidecar verification, and semantic report citation linting.

### Changed

- Documented the Runwarden security model, design system, CLI, MCP, reviewer console, release process, and enterprise submission map.
- Wired `runwarden eval scenarios --json` and generated TypeScript declaration drift checks into local and CI gates.
