# Changelog

All notable changes to Runwarden are documented in this file.

## [Unreleased]

### Changed

- Refocused Runwarden around the contest red-team range workflow: deterministic
  scenarios, Rust-owned provider mediation, trace-backed reports, and a static
  reviewer console.
- Narrowed the active CLI, MCP, provider, docs, and TypeScript surfaces to the
  contest demo path.
- Reworked local and CI gates to validate the four scenario corpus, demo
  artifacts, report rendering, and static WebUI build.
- Simplified `runwarden-assurance` to report lint/render and scenario
  evaluation support.

### Added

- Added four reproducible attack scenarios:
  `prompt-injection-file-exfil`, `tool-hijack-email-api`,
  `memory-knowledge-poisoning`, and `environment-local-web-risk`.
- Added deterministic demo generation through `runwarden demo run`.
- Added scenario-suite report rendering through
  `runwarden report render --scenario-suite scenarios`.

### Removed

- Removed non-contest delivery surfaces from the active workspace and public
  command set.
- Removed legacy scenario corpora so `scenarios/` contains only the four main
  contest scenarios.

## [0.1.0.0] - 2026-05-28

### Added

- Added the Rust security kernel, provider mediation, MCP boundary, CLI,
  trace evidence, report citation linting, approval records, schema artifacts,
  WebUI rendering package, and scenario fixture foundation.

### Fixed

- Bound provider policy outcomes to deterministic `obs_*` IDs and trace event
  labels before side effects.
- Ensured MCP `runwarden.provider.call` respects kernel session allowlists
  before executing providers.
- Hardened external MCP adapter execution, private egress checks, stdio frame
  bounds, CLI approval binding, actor-bound authz, output path containment, and
  semantic report citation linting.
