# CI

Pull requests and pushes to `main` run `scripts/pr_fast_gate.sh`.

The gate checks:

- Rust formatting
- Clippy warnings as errors
- Rust workspace tests
- generated TypeScript contract drift
- pnpm tests
- pnpm builds

The release gate additionally runs cert, eval, scenario golden-corpus eval,
bench, release smoke, artifact submission, artifact verification, and leak scan.
By default `scripts/release_gate_local.sh` is self-contained and runs the
artifact bundle and leak scan. Composite gates such as nightly CI and release
evidence set `RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1` before calling it, then run
`scripts/generate_artifacts.sh` and `scripts/artifact_leak_scan.sh` once so
schema generation, artifact submission, verification, and leak scanning are not
duplicated.
