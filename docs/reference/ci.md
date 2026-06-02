# CI

Pull requests and pushes to `main` run `scripts/pr_fast_gate.sh`.

The gate checks:

- Rust formatting
- Clippy warnings as errors
- dependency policy from `deny.toml` via `cargo deny check`
- Rust workspace tests
- generated TypeScript contract drift
- pnpm tests
- pnpm builds

Local gate scripts require `cargo-deny` to be installed and fail with an
installation hint when it is missing. GitHub Actions installs
`cargo-deny@0.19.6` before running gate scripts that enforce the checked-in
dependency policy.
GitHub Actions installs `pnpm@11.4.0` with a pinned `pnpm/action-setup`
step before `actions/setup-node` enables `cache: pnpm`; the setup-node cache
restore path shells out to `pnpm`, so pnpm must already be on `PATH`.
Workspace crates inherit `publish = false` and a proprietary `LicenseRef-*`
identifier, then `cargo-deny` treats them as private for license checks;
third-party crates remain subject to the allowlist in `deny.toml`.
The bans policy still reports duplicate crate versions by default; the only
checked-in duplicate exception is `wit-bindgen@0.51.0`, which is pulled by
`getrandom` through target-specific WASI preview3 support while the same
`getrandom` release also carries a WASI preview2 dependency on
`wit-bindgen@0.57.1`.

The release gate additionally runs cert, eval, scenario golden-corpus eval,
bench, release smoke, artifact submission, artifact verification, and leak scan.
By default `scripts/release_gate_local.sh` is self-contained and runs the
artifact bundle and leak scan. Composite gates such as nightly CI and release
evidence set `RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1` before calling it, then run
`scripts/generate_artifacts.sh` and `scripts/artifact_leak_scan.sh` once so
schema generation, artifact submission, verification, and leak scanning are not
duplicated.

Workflow actions are pinned to immutable commit SHAs. Each pinned `uses:` entry
keeps a nearby comment with the upstream action and tag or branch for human
readability; update both the SHA and comment deliberately when bumping actions.
