#!/usr/bin/env bash
set -euo pipefail
artifact_dir="${ARTIFACT_DIR:-artifacts}"
leak_pattern='secret=|token=|password=|passwd=|api[_-]?key=|access_token=|refresh_token=|auth_token=|client_secret=|secret_access_key=|authorization:[[:space:]]*bearer|x-api-key:|private key|begin (rsa |ec |openssh )?private key'
if [ -d "$artifact_dir" ]; then
  set +e
  if command -v rg >/dev/null 2>&1; then
    rg -n -i -e "$leak_pattern" "$artifact_dir"
  else
    grep -r -I -n -i -E -e "$leak_pattern" "$artifact_dir"
  fi
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    exit 1
  fi
  if [ "$status" -gt 1 ]; then
    echo "artifact leak scan failed with status $status" >&2
    exit "$status"
  fi
fi
