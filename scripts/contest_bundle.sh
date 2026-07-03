#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash scripts/release_gate_local.sh

rm -rf artifacts/redteam
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
  --summary-out artifacts/redteam/proxy-probe-summary.json \
  --fail-on-fail
python3 redteam/run.py output-probe \
  --corpora redteam/corpora/output_filter.jsonl \
  --out artifacts/redteam/output-probe-results.jsonl \
  --summary-out artifacts/redteam/output-probe-summary.json \
  --fail-on-fail

BUNDLE="artifacts/contest-bundle"
OFFICIAL_SCENARIOS=(
  prompt-injection-file-exfil
  tool-hijack-email-api
  memory-knowledge-poisoning
  environment-local-web-risk
  path-escape-file-boundary
)
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE"

cp README.md "$BUNDLE/README.md"
cp SUBMISSION.md "$BUNDLE/SUBMISSION.md"
cp -R docs "$BUNDLE/docs"
rm -rf "$BUNDLE/docs/superpowers"
cp -R redteam "$BUNDLE/redteam"
find "$BUNDLE/redteam" \( -type d -name "__pycache__" -o -type f -name "*.pyc" \) -prune -exec rm -rf {} +
cp -R schemas "$BUNDLE/schemas"
mkdir -p "$BUNDLE/scenarios"
for scenario in "${OFFICIAL_SCENARIOS[@]}"; do
  cp -R "scenarios/$scenario" "$BUNDLE/scenarios/$scenario"
done

mkdir -p "$BUNDLE/reports"
cp artifacts/reports/contest-report.md "$BUNDLE/reports/contest-report.md"
mkdir -p "$BUNDLE/demo"
for scenario in "${OFFICIAL_SCENARIOS[@]}"; do
  cp -R "artifacts/demo/$scenario" "$BUNDLE/demo/$scenario"
done
cp artifacts/demo/reviewer-console.html "$BUNDLE/reviewer-console.html"

if [ -d artifacts/redteam ]; then
  cp -R artifacts/redteam "$BUNDLE/redteam-results"
fi

python3 - <<'PY'
import json
import pathlib

bundle = pathlib.Path("artifacts/contest-bundle")
official_scenarios = {
    "prompt-injection-file-exfil",
    "tool-hijack-email-api",
    "memory-knowledge-poisoning",
    "environment-local-web-risk",
    "path-escape-file-boundary",
}
scenario_names = {p.name for p in (bundle / "scenarios").iterdir() if p.is_dir()}
demo_names = {p.name for p in (bundle / "demo").iterdir() if p.is_dir()}
if scenario_names != official_scenarios:
    raise SystemExit(f"bundle scenarios are not the official five: {sorted(scenario_names)}")
if demo_names != official_scenarios:
    raise SystemExit(f"bundle demo scenarios are not the official five: {sorted(demo_names)}")
scenario_list = sorted(scenario_names)
scenario_count = len(scenario_list)

def load_summary(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

def redteam_manifest(summary, name):
    return {
        "summary": f"redteam-results/{name}-summary.json",
        "results": f"redteam-results/{name}-results.jsonl",
        "total": summary.get("total"),
        "pass": summary.get("pass"),
        "fail": summary.get("fail"),
        "skip": summary.get("skip"),
    }

proxy_summary_path = pathlib.Path("artifacts/redteam/proxy-probe-summary.json")
output_summary_path = pathlib.Path("artifacts/redteam/output-probe-summary.json")
proxy_summary = load_summary(proxy_summary_path)
output_summary = load_summary(output_summary_path)
coverage = proxy_summary.get("coverage") or output_summary.get("coverage") or {}

manifest = {
    "project": "runwarden",
    "bundle_type": "contest_submission",
    "scenario_count": scenario_count,
    "scenarios": scenario_list,
    "scenario_summary": {
        "summary": "demo/",
        "entries": {
            name: {
                "scenario": f"scenarios/{name}/",
                "demo": f"demo/{name}/",
                "report": f"demo/{name}/report.json",
                "trace": f"demo/{name}/trace.json",
                "webui": f"demo/{name}/webui.json",
            }
            for name in scenario_list
        },
    },
    "required_artifacts": {
        "submission": "SUBMISSION.md",
        "report": "reports/contest-report.md",
        "reviewer_console": "reviewer-console.html",
        "scenarios": "scenarios/",
        "redteam": "redteam/",
        "redteam_results": "redteam-results/",
    },
    "redteam_proxy_probe": redteam_manifest(proxy_summary, "proxy-probe"),
    "redteam_output_probe": redteam_manifest(output_summary, "output-probe"),
    "generated_by": "scripts/contest_bundle.sh",
}

(bundle / "manifest.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)

summary_md_path = bundle / "redteam-results" / "SUMMARY.md"
summary_md_path.parent.mkdir(parents=True, exist_ok=True)
coverage_rows = "\n".join(
    f"| {category} | {path} |" for category, path in sorted(coverage.items())
) or "| N/A | N/A |"

if proxy_summary_path.exists() or output_summary_path.exists():
    summary_md = f"""# Red-Team Probe Summary

## Proxy Probe

| Metric | Value |
| --- | ---: |
| total | {proxy_summary.get("total", "N/A")} |
| pass | {proxy_summary.get("pass", "N/A")} |
| fail | {proxy_summary.get("fail", "N/A")} |
| skip | {proxy_summary.get("skip", "N/A")} |

## Output Probe

| Metric | Value |
| --- | ---: |
| total | {output_summary.get("total", "N/A")} |
| pass | {output_summary.get("pass", "N/A")} |
| fail | {output_summary.get("fail", "N/A")} |
| skip | {output_summary.get("skip", "N/A")} |

## Coverage Matrix

| Corpus Category | Coverage Path |
| --- | --- |
{coverage_rows}

Generated by `scripts/contest_bundle.sh` from red-team summary JSON.
"""
else:
    summary_md = """# Red-Team Probe Summary

red-team probes were not run. Execute `bash scripts/contest_bundle.sh` to generate results.
"""
summary_md_path.write_text(summary_md, encoding="utf-8")
PY

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
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

echo "contest bundle -> $BUNDLE"
