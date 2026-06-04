# XA-202620 Submission Map

This page maps Runwarden repository deliverables to a review or competition
submission package. It is intentionally evidence-oriented: each listed item
should be reproducible from the checked-out repository.

## Release Evidence

| Evidence | Command or path | Purpose |
| --- | --- | --- |
| Local release gate | `bash scripts/release_gate_local.sh` | Runs fast checks plus strict, cert, eval, bench, release smoke, artifact, and leak gates. |
| Strict repository check | `target/debug/runwarden check --strict` | Verifies required paths, reference docs, schema artifacts, provider catalog, gates, and release surfaces. |
| Certification | `target/debug/runwarden cert all --json` | Certifies schemas, release scripts, scenarios, agent config, workflows, package surfaces, and artifacts. |
| Benchmark | `target/debug/runwarden bench run --json` | Reports scenario count, denial cases, provider mediation rate, and policy-denial correctness. |
| Agent-native eval | `target/debug/runwarden eval agent-native --json` | Proves Runwarden-only configs pass and raw shell/filesystem configs fail. |
| Scenario eval | `target/debug/runwarden eval scenarios --json` | Validates checked-in scenario golden corpora. |
| Artifact submission | `target/debug/runwarden artifact submission --full --output artifacts --json` | Generates release evidence, SBOM, provenance, and artifact manifest. |
| Artifact verification | `target/debug/runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json` | Verifies hashes, containment, symlink safety, and redaction sidecars. |

## Submission Artifacts

- JSON schemas in `schemas/`.
- Generated TypeScript declarations in
  `packages/agent-sdk/src/generated/contracts.ts`.
- Runwarden-only and unsafe agent configs in `examples/agent-configs/`.
- Provider examples in `examples/providers/`.
- Scenario golden corpora in `scenarios/`.
- Reviewer Console renderer in `packages/webui`.
- Security assessment skill in `skills/runwarden-security-assessment/`.
- Generated artifact bundle under `artifacts/` when the artifact submission
  command runs.

## Review Narrative

A submission should explain the end-to-end chain:

1. The agent sees only the Runwarden MCP boundary.
2. Provider calls are mediated by Rust kernel policy.
3. High-risk side effects require bound reviewer approval.
4. Decisions produce `obs_*` evidence.
5. Reports must cite verified observations.
6. Artifacts are sealed, verified, and scanned for leakage.
