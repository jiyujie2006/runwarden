#!/usr/bin/env bash
set -euo pipefail
scripts/dev_gate.sh
target/debug/runwarden check --strict
target/debug/runwarden cert all --json
target/debug/runwarden eval all --json
target/debug/runwarden eval scenarios --json
target/debug/runwarden eval agent-native --json
target/debug/runwarden bench run --json
target/debug/runwarden release smoke --json
if [[ "${RUNWARDEN_SKIP_ARTIFACT_BUNDLE:-0}" != "1" ]]; then
  RUNWARDEN_BIN=target/debug/runwarden scripts/artifact_bundle_gate.sh artifacts
  scripts/artifact_leak_scan.sh
fi
