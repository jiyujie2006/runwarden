#!/usr/bin/env bash
set -euo pipefail
scripts/dev_gate.sh
rm -f artifacts/llm-proxy/trace.jsonl
target/debug/runwarden check --strict
target/debug/runwarden eval scenarios --json
for scenario in \
  prompt-injection-file-exfil \
  tool-hijack-email-api \
  memory-knowledge-poisoning \
  environment-local-web-risk \
  path-escape-file-boundary
do
  target/debug/runwarden demo run --scenario "$scenario" --output "artifacts/demo/$scenario" --json
done
target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json
target/debug/runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json
