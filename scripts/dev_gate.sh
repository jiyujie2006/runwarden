#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
scripts/check_ts_contracts.sh
pnpm test
pnpm build
