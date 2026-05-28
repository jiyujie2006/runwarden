#!/usr/bin/env bash
set -euo pipefail
scripts/dev_gate.sh
target/debug/runwarden check --strict
target/debug/runwarden cert all --json
target/debug/runwarden eval all --json
target/debug/runwarden eval agent-native --json
target/debug/runwarden bench run --json
target/debug/runwarden release smoke --json
target/debug/runwarden artifact submission --full --output artifacts --json
target/debug/runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json
scripts/artifact_leak_scan.sh
