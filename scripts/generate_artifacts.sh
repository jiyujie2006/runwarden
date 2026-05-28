#!/usr/bin/env bash
set -euo pipefail
cargo run -p runwarden-kernel --example generate_schemas
node packages/agent-sdk/scripts/generate-contracts.mjs
cargo test -p runwarden-kernel --test contract_schemas
cargo run -p runwarden-cli -- artifact submission --full --output artifacts --json
cargo run -p runwarden-cli -- artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json
