# CI

Runwarden uses tiered contest gates. Pull requests and pushes run the fast gate;
the local full gate exercises the contest demo workflow end to end.

## Fast Gate

`scripts/pr_fast_gate.sh` runs:

- `cargo fmt --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo deny check` (requires `cargo-deny`; scripts fail with an install hint)
- `cargo test --workspace`
- `pnpm test`
- `pnpm build`

`scripts/dev_gate.sh` currently runs the same checks.

## Contest Gate

`scripts/release_gate_local.sh` adds:

- `target/debug/runwarden check --strict`
- `target/debug/runwarden eval scenarios --json`
- one deterministic `runwarden demo run` for each main scenario
- `target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json`
- `target/debug/runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json`

## Tooling

Local gate scripts require `cargo-deny` and fail with an installation hint when
it is missing:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

GitHub Actions installs `cargo-deny@0.19.6`, `pnpm@11.4.0`, and Node before
running gate scripts. `pnpm/action-setup` runs before `actions/setup-node`
enables `cache: pnpm` because setup-node shells out to `pnpm`.

Workspace crates inherit `publish = false` and a proprietary `LicenseRef-*`
identifier. `cargo-deny` treats them as private for license checks; third-party
crates remain subject to the allowlist in `deny.toml`.

## Workflow Pinning

Workflow actions are pinned to immutable commit SHAs. Each pinned `uses:` entry
keeps a nearby comment with the upstream action and tag or branch for human
readability. Update both the SHA and comment deliberately when bumping actions.
