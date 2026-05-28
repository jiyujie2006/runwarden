#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
pnpm test
pnpm build

