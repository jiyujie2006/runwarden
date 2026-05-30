#!/usr/bin/env bash
set -euo pipefail
cargo run -p runwarden-kernel --example generate_schemas
node packages/agent-sdk/scripts/generate-contracts.mjs
cargo test -p runwarden-kernel --test contract_schemas
scripts/artifact_bundle_gate.sh artifacts
