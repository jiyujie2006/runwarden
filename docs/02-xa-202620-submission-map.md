# XA-202620 Submission Map

This document maps Runwarden deliverables to the competition submission package.

## Release Evidence

- `scripts/release_gate_local.sh`: complete local release gate.
- `target/debug/runwarden cert all --json`: certifies schemas, release scripts,
  scenario evidence, runwarden-only agent config, release workflow, and tiered CI.
- `target/debug/runwarden bench run --json`: reports scenario count,
  expected-denial cases, provider mediation rate, and policy-denial correctness.
- `target/debug/runwarden eval agent-native --json`: proves runwarden-only
  agent exposure passes and raw shell/filesystem configs are blocked.
- `target/debug/runwarden artifact submission --full --output artifacts
  --json`: generates the release evidence bundle, including SBOM and
  provenance contract files.
- `target/debug/runwarden artifact verify --artifacts <dir> --manifest <file>
  --json`: verifies artifact hashes, containment, symlink safety, and redaction
  sidecars.

## Submission Artifacts

- JSON schemas in `schemas/`.
- Example runwarden-only and unsafe agent configs in `examples/agent-configs/`.
- Enterprise agent security scenario fixtures in
  `scenarios/enterprise-agent-security/`.
- First-party provider catalog documentation in `examples/providers/README.md`.
- Reviewer console renderer in `packages/webui`.
- Generated `artifacts/artifact-manifest.json`, `release/sbom.spdx.json`, and
  `release/provenance.json` from the artifact submission command.
