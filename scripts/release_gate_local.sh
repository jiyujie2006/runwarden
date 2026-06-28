#!/usr/bin/env bash
set -euo pipefail
scripts/dev_gate.sh
target/debug/runwarden check --strict
target/debug/runwarden eval scenarios --json
target/debug/runwarden demo run --scenario prompt-injection-file-exfil --output artifacts/demo/prompt-injection-file-exfil --json
target/debug/runwarden demo run --scenario tool-hijack-email-api --output artifacts/demo/tool-hijack-email-api --json
target/debug/runwarden demo run --scenario memory-knowledge-poisoning --output artifacts/demo/memory-knowledge-poisoning --json
target/debug/runwarden demo run --scenario environment-local-web-risk --output artifacts/demo/environment-local-web-risk --json
target/debug/runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json
target/debug/runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json
