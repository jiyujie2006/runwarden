#!/usr/bin/env bash
set -euo pipefail
artifact_dir="${ARTIFACT_DIR:-artifacts}"
if [ -d "$artifact_dir" ]; then
  set +e
  rg -n 'SECRET|TOKEN|PASSWORD|PRIVATE KEY' "$artifact_dir"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    exit 1
  fi
  if [ "$status" -gt 1 ]; then
    echo "artifact leak scan failed with rg status $status" >&2
    exit "$status"
  fi
fi
