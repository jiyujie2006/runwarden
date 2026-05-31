#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo clippy --workspace -- -D warnings
if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "error: cargo-deny is required for dependency policy checks. Install it with: cargo install cargo-deny --version 0.19.6 --locked" >&2
  exit 1
fi
cargo deny check
cargo test --workspace
scripts/check_ts_contracts.sh
pnpm test
pnpm build
