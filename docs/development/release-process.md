# Release Process

Run the local release gate before tagging:

```bash
scripts/release_gate_local.sh
```

The gate runs:

1. Rust formatting, clippy, and workspace tests.
2. TypeScript tests and builds.
3. `runwarden check --strict`.
4. `runwarden cert all --json`.
5. `runwarden eval all --json`.
6. `runwarden eval scenarios --json`.
7. `runwarden eval agent-native --json`.
8. `runwarden bench run --json`.
9. `runwarden release smoke --json`.
10. `runwarden artifact submission --full --output artifacts --json`.
11. `runwarden artifact verify --artifacts artifacts --manifest
   artifacts/artifact-manifest.json --json`.
12. `scripts/artifact_leak_scan.sh`.

`scripts/release_gate_local.sh` is self-contained by default. Composite gates
that immediately regenerate artifacts, such as nightly CI and the release
evidence workflow, set `RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1` before invoking the
release gate, then run `scripts/generate_artifacts.sh` and
`scripts/artifact_leak_scan.sh` once. `scripts/generate_artifacts.sh` uses
`scripts/artifact_bundle_gate.sh` for artifact submission and verification.

CI is tiered:

- PR and push events run `scripts/pr_fast_gate.sh`.
- Nightly scheduled CI runs `scripts/nightly_full_gate.sh`.
- Release evidence runs on tags and workflow dispatch with OS matrix smoke,
  schema generation, artifact bundle generation and verification, leak scan,
  cert, agent-native eval, bench, release build, uploaded assets, and tagged
  GitHub Release publication.

Generated schemas are checked against Rust contract types by
`cargo test -p runwarden-kernel --test contract_schemas`, including
`provider-manifest`, `provider-contract`, and `report` schema artifacts.
