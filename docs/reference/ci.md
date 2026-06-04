# CI

Runwarden uses tiered gates. Pull requests and pushes to `main` run the fast
gate. Manual workflow dispatch runs the full gate. Release evidence runs on
tags and manual dispatch.

## Fast Gate

`scripts/pr_fast_gate.sh` runs:

- `cargo fmt --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo deny check`
- `cargo test --workspace`
- `scripts/check_ts_contracts.sh`
- `pnpm test`
- `pnpm build`

`scripts/dev_gate.sh` currently runs the same local checks.

## Full and Release Gates

`scripts/release_gate_local.sh` adds:

- `target/debug/runwarden check --strict`
- `target/debug/runwarden cert all --json`
- `target/debug/runwarden eval all --json`
- `target/debug/runwarden eval scenarios --json`
- `target/debug/runwarden eval agent-native --json`
- `target/debug/runwarden bench run --json`
- `target/debug/runwarden release smoke --json`
- artifact submission and verification
- artifact leak scan

Composite gates such as manual full CI and release evidence set
`RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1` before calling the release gate, then run
`scripts/generate_artifacts.sh` and `scripts/artifact_leak_scan.sh` once so
artifact generation is not duplicated.

## Tooling

Local gate scripts require `cargo-deny` and fail with an installation hint when
it is missing:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

GitHub Actions installs `cargo-deny@0.19.6`, `pnpm@11.4.0`, and Node before
running gate scripts. `pnpm/action-setup` runs before `actions/setup-node`
enables `cache: pnpm` because setup-node shells out to `pnpm`.

The artifact leak scan prefers `rg` and falls back to recursive `grep`.

Workspace crates inherit `publish = false` and a proprietary `LicenseRef-*`
identifier. `cargo-deny` treats them as private for license checks; third-party
crates remain subject to the allowlist in `deny.toml`.

## Workflow Pinning

Workflow actions are pinned to immutable commit SHAs. Each pinned `uses:` entry
keeps a nearby comment with the upstream action and tag or branch for human
readability. Update both the SHA and comment deliberately when bumping actions.
