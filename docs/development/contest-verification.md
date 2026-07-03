# Contest Verification

Run the local contest gate before publishing or submitting review evidence.

```bash
bash scripts/release_gate_local.sh
```

## Local Gate Contents

The gate runs:

1. `cargo fmt --check`.
2. `cargo clippy --workspace -- -D warnings`.
3. `cargo deny check` (requires `cargo-deny`; the script fails with an install hint when missing).
4. Python red-team corpus and harness checks.
5. `cargo test --workspace`.
6. `target/debug/runwarden check --strict --json`.
7. `target/debug/runwarden demo --all --output artifacts/demo --json`.
8. `target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json`.

Install `cargo-deny` before running gates locally:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

## CI Tiers

- Pull requests and pushes to `main` run `scripts/pr_fast_gate.sh`.
- Manual CI workflow dispatch runs `scripts/nightly_full_gate.sh`.
- Scheduled CI is disabled.

## Workflow Pinning

Workflows pin external `uses:` actions to immutable commit SHAs. Each pinned
action keeps a nearby comment naming the upstream action and tag or branch, so
action updates require intentionally resolving and reviewing a new SHA.

## Schema Drift

Generated schemas are checked against Rust contract types by:

```bash
cargo test -p runwarden-kernel --test contract_schemas
```
