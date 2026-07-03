# XA-202620 Submission Map

This page maps Runwarden contest deliverables to reviewer evidence. Each item is
reproducible from the checked-out repository.

## Evidence Commands

| Evidence | Command or path | Purpose |
| --- | --- | --- |
| Fast gate | `bash scripts/pr_fast_gate.sh` | Runs cargo fmt, cargo clippy `-D warnings`, cargo-deny, corpus checks, Python harness tests, and workspace Rust tests. |
| Local contest gate | `bash scripts/release_gate_local.sh` | Adds strict check, scenario eval, deterministic demos, suite report rendering, and static console build. |
| Strict repository check | `target/debug/runwarden check --strict` | Verifies required contest docs, scenarios, providers, and gate scripts. |
| Scenario eval | `target/debug/runwarden check --strict --json` | Validates the five checked-in golden corpora. |
| Demo run | `target/debug/runwarden demo --scenario <id> --output artifacts/demo/<id> --json` | Generates trace, provider calls, denials, metrics, report input, and WebUI JSON. |
| Contest report | `target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json` | Produces the trace-backed submission report. |
| Reviewer console | `target/debug/runwarden demo --all --output artifacts/demo --json` | Builds static reviewer HTML from demo JSON. |

## Submission Artifacts

- JSON schemas in `schemas/`.
- Scenario golden corpora in `scenarios/`.
- Provider examples in `examples/providers/`.
- Red-team harness and adversarial corpora in `redteam/run.py` and
  `redteam/corpora/*.jsonl`.
- Rust-served reviewer console renderer.
- Generated demo artifacts under `artifacts/demo/` when demo commands run.
- Generated contest report under `artifacts/reports/` when report render runs.

## Review Narrative

1. The agent sees only the Runwarden MCP boundary.
2. Provider calls are mediated by Rust kernel policy.
3. High-risk side effects require bound reviewer approval.
4. Decisions produce `obs_*` evidence.
5. Reports must cite verified observations.
6. The static reviewer console displays Rust-produced demo state.
