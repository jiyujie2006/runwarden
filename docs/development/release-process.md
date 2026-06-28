# Contest Verification Process

Run the local contest gate before publishing or submitting review evidence.

```bash
bash scripts/release_gate_local.sh
```

## Local Gate Contents

The gate runs:

1. `cargo fmt --check`.
2. `cargo clippy --workspace -- -D warnings`.
3. `cargo deny check` when installed or required by the environment.
4. `cargo test --workspace`.
5. `pnpm test`.
6. `pnpm build`.
7. `target/debug/runwarden check --strict`.
8. `target/debug/runwarden eval scenarios --json`.
9. Four deterministic `target/debug/runwarden demo run ...` commands.
10. `target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json`.
11. `target/debug/runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json`.

Install `cargo-deny` before running gates locally when the script requires it:

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
