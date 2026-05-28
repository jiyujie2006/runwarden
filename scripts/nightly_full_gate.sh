#!/usr/bin/env bash
set -euo pipefail
scripts/release_gate_local.sh
scripts/generate_artifacts.sh
scripts/artifact_leak_scan.sh
