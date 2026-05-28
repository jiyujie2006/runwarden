# CI

Pull requests and pushes to `main` run `scripts/pr_fast_gate.sh`.

The gate checks:

- Rust formatting
- Clippy warnings as errors
- Rust workspace tests
- generated TypeScript contract drift
- pnpm tests
- pnpm builds

The release gate additionally runs cert, eval, scenario golden-corpus eval, bench, release smoke, artifact submission, artifact verification, and leak scan.
