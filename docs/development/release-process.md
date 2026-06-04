# Release Process

Run the local release gate before tagging or publishing release evidence.

```bash
bash scripts/release_gate_local.sh
```

## Local Gate Contents

The release gate runs:

1. `cargo fmt --check`.
2. `cargo clippy --workspace -- -D warnings`.
3. `cargo deny check`.
4. `cargo test --workspace`.
5. `scripts/check_ts_contracts.sh`.
6. `pnpm test`.
7. `pnpm build`.
8. `target/debug/runwarden check --strict`.
9. `target/debug/runwarden cert all --json`.
10. `target/debug/runwarden eval all --json`.
11. `target/debug/runwarden eval scenarios --json`.
12. `target/debug/runwarden eval agent-native --json`.
13. `target/debug/runwarden bench run --json`.
14. `target/debug/runwarden release smoke --json`.
15. `target/debug/runwarden artifact submission --full --output artifacts --json`.
16. `target/debug/runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json`.
17. `scripts/artifact_leak_scan.sh`.

Install `cargo-deny` before running release gates locally:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

The local scripts fail with an installation hint when `cargo-deny` is missing.
GitHub Actions installs it before invoking gate scripts.

## Avoiding Duplicate Artifact Work

`scripts/release_gate_local.sh` is self-contained by default. Composite gates
that immediately regenerate artifacts set:

```bash
RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1
```

before invoking the release gate, then run:

```bash
bash scripts/generate_artifacts.sh
bash scripts/artifact_leak_scan.sh
```

once. `scripts/generate_artifacts.sh` uses
`scripts/artifact_bundle_gate.sh` for artifact submission and verification.

## CI Tiers

- Pull requests and pushes to `main` run `scripts/pr_fast_gate.sh`.
- Manual CI workflow dispatch runs `scripts/nightly_full_gate.sh`.
- Scheduled CI is disabled.
- Release evidence runs on tags and workflow dispatch with OS matrix smoke,
  schema generation, artifact bundle generation and verification, leak scan,
  cert, agent-native eval, bench, release build, uploaded assets, and tagged
  GitHub Release publication.

## Workflow Pinning

Release workflows pin external `uses:` actions to immutable commit SHAs,
including the publish action that has `contents: write`. Each pinned action
keeps a nearby comment naming the upstream action and tag or branch, such as
`softprops/action-gh-release@v2`, so action updates require intentionally
resolving and reviewing a new SHA.

## Schema and Contract Drift

Generated schemas are checked against Rust contract types by:

```bash
cargo test -p runwarden-kernel --test contract_schemas
```

Generated TypeScript declarations are checked by:

```bash
scripts/check_ts_contracts.sh
```
