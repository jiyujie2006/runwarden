#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${1:-artifacts}"

if [[ -n "${RUNWARDEN_BIN:-}" ]]; then
  runwarden_cmd=("${RUNWARDEN_BIN}")
elif [[ -x target/debug/runwarden ]]; then
  runwarden_cmd=(target/debug/runwarden)
else
  runwarden_cmd=(cargo run -p runwarden-cli --)
fi

"${runwarden_cmd[@]}" artifact submission --full --output "${artifact_dir}" --json
"${runwarden_cmd[@]}" artifact verify \
  --artifacts "${artifact_dir}" \
  --manifest "${artifact_dir}/artifact-manifest.json" \
  --json
