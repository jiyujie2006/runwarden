# CI

Runwarden uses Rust-only gates after removal of the dead frontend package.

## Fast Gate

`scripts/pr_fast_gate.sh` runs:

- `cargo fmt --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo deny check`
- `cargo test --workspace`

`scripts/dev_gate.sh` runs the same checks and also validates red-team corpora
and Python harness unit tests.

## Contest Gate

`scripts/release_gate_local.sh` runs:

- `scripts/dev_gate.sh`
- `target/debug/runwarden check --strict --json`
- `target/debug/runwarden demo --all --output artifacts/demo --json`
- `target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json`

## Contest Bundle

`scripts/contest_bundle.sh` runs the local contest gate, runs deterministic
`proxy-probe`, then copies the submission whitelist into
`artifacts/contest-bundle`.

Local gates require `cargo-deny`:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

Workflow actions remain pinned to immutable SHAs.
