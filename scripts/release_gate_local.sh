#!/usr/bin/env bash
set -euo pipefail
scripts/dev_gate.sh
rm -f artifacts/llm-proxy/trace.jsonl
target/debug/runwarden check --strict --json
target/debug/runwarden demo --all --output artifacts/demo --json
target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json
