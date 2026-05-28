#!/usr/bin/env bash
set -euo pipefail
artifact_dir="${ARTIFACT_DIR:-artifacts}"
if [ -d "$artifact_dir" ]; then
  rg -n 'SECRET|TOKEN|PASSWORD|PRIVATE KEY' "$artifact_dir" && exit 1 || true
fi
