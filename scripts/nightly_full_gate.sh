#!/usr/bin/env bash
set -euo pipefail
RUNWARDEN_SKIP_ARTIFACT_BUNDLE=1 scripts/release_gate_local.sh
scripts/generate_artifacts.sh
scripts/artifact_leak_scan.sh
