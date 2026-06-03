# Release Process

Run the local release gate before tagging:

```bash
scripts/release_gate_local.sh
```

The gate runs:

1. Rust formatting and clippy.
2. Dependency policy from `deny.toml` via `cargo deny check`.
3. Rust workspace tests.
4. TypeScript tests and builds.
5. `runwarden check --strict`.
6. `runwarden cert all --json`.
7. `runwarden eval all --json`.
8. `runwarden eval scenarios --json`.
9. `runwarden eval agent-native --json`.
10. `runwarden bench run --json`.
11. `runwarden release smoke --json`.
12. `runwarden artifact submission --full --output artifacts --json`.
13. `runwarden artifact verify --artifacts artifacts --manifest
   artifacts/artifact-manifest.json --json`.
14. `scripts/artifact_leak_scan.sh`.

Install `cargo-deny` before running release gates locally:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

The local scripts fail with a clear installation hint when `cargo-deny` is
missing. GitHub Actions installs it before invoking the gate scripts.

`scripts/release_gate_local.sh` is self-contained by default. Composite gates
that immediately regenerate artifacts, such as manual full CI and the release
evidence workflow, set `RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1` before invoking the
release gate, then run `scripts/generate_artifacts.sh` and
`scripts/artifact_leak_scan.sh` once. `scripts/generate_artifacts.sh` uses
`scripts/artifact_bundle_gate.sh` for artifact submission and verification.

CI is tiered:

- PR and push events run `scripts/pr_fast_gate.sh`.
- Manual CI workflow dispatch runs `scripts/nightly_full_gate.sh`; scheduled CI
  is disabled.
- Release evidence runs on tags and workflow dispatch with OS matrix smoke,
  schema generation, artifact bundle generation and verification, leak scan,
  cert, agent-native eval, bench, release build, uploaded assets, and tagged
  GitHub Release publication.

Release workflows pin all external `uses:` actions to immutable commit SHAs,
including the publish action that has `contents: write`. Each pinned action keeps
a nearby comment naming the upstream action and tag or branch, such as
`softprops/action-gh-release@v2`, so action updates require intentionally
resolving and reviewing a new SHA.

Generated schemas are checked against Rust contract types by
`cargo test -p runwarden-kernel --test contract_schemas`, including
`provider-manifest`, `provider-contract`, and `report` schema artifacts.
