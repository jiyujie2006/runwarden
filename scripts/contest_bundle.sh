#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/release_gate_local.sh

mkdir -p artifacts/redteam
python3 redteam/run.py proxy-probe \
  --corpora \
    redteam/corpora/prompt_injection.jsonl \
    redteam/corpora/jailbreak.jsonl \
    redteam/corpora/indirect_prompt_injection.jsonl \
    redteam/corpora/encoded_bypass.jsonl \
    redteam/corpora/schema_poisoning.jsonl \
    redteam/corpora/report_fabrication.jsonl \
    redteam/corpora/benign_control.jsonl \
  --out artifacts/redteam/proxy-probe-results.jsonl \
  --summary-out artifacts/redteam/proxy-probe-summary.json

BUNDLE="artifacts/contest-bundle"
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE"

cp README.md "$BUNDLE/README.md"
cp SUBMISSION.md "$BUNDLE/SUBMISSION.md"
cp -R docs "$BUNDLE/docs"
cp -R scenarios "$BUNDLE/scenarios"
cp -R redteam "$BUNDLE/redteam"
cp -R schemas "$BUNDLE/schemas"

mkdir -p "$BUNDLE/reports"
cp artifacts/reports/contest-report.md "$BUNDLE/reports/contest-report.md"
cp -R artifacts/demo "$BUNDLE/demo"
cp artifacts/reviewer-console.html "$BUNDLE/reviewer-console.html"

if [ -d artifacts/redteam ]; then
  cp -R artifacts/redteam "$BUNDLE/redteam-results"
fi

SCENARIO_COUNT="$(find "$BUNDLE/scenarios" -mindepth 1 -maxdepth 1 -type d | wc -l)"
cat > "$BUNDLE/manifest.json" <<EOF
{
  "project": "runwarden",
  "bundle_type": "contest_submission",
  "scenario_count": ${SCENARIO_COUNT},
  "required_artifacts": {
    "submission": "SUBMISSION.md",
    "report": "reports/contest-report.md",
    "reviewer_console": "reviewer-console.html",
    "scenarios": "scenarios/",
    "redteam": "redteam/"
  },
  "generated_by": "scripts/contest_bundle.sh"
}
EOF

if find "$BUNDLE" -name ".env" -print -quit | grep -q .; then
  echo "contest bundle contains .env" >&2
  exit 1
fi
if find "$BUNDLE" \( -name "target" -o -name "node_modules" \) -print -quit | grep -q .; then
  echo "contest bundle contains build output" >&2
  exit 1
fi
if grep -R "sk-[A-Za-z0-9_-]\\{16,\\}" "$BUNDLE" >/dev/null 2>&1; then
  echo "contest bundle contains an API-key-looking token" >&2
  exit 1
fi

(
  cd "$BUNDLE"
  find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "contest bundle -> $BUNDLE"
