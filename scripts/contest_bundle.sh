#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUNDLE="artifacts/contest-bundle"
STAGING="artifacts/.contest-bundle.staging"
# Never leave a stale prior submission looking current after a failed gate.
# Build the replacement beside it, then publish with one same-filesystem rename.
rm -rf "$BUNDLE" "$STAGING"
trap 'rm -rf "$STAGING"' EXIT

bash scripts/release_gate_local.sh

mkdir -p artifacts/redteam
# Refresh deterministic probe artifacts without deleting optional, costly
# agent-drive evidence from a prior explicitly requested live-model run.
rm -f \
  artifacts/redteam/proxy-probe-results.jsonl \
  artifacts/redteam/proxy-probe-summary.json \
  artifacts/redteam/proxy-trace.jsonl \
  artifacts/redteam/output-probe-results.jsonl \
  artifacts/redteam/output-probe-summary.json \
  artifacts/redteam/output-trace.jsonl
python3 redteam/run.py proxy-probe \
  --corpora \
    redteam/corpora/prompt_injection.jsonl \
    redteam/corpora/jailbreak.jsonl \
    redteam/corpora/indirect_prompt_injection.jsonl \
    redteam/corpora/encoded_bypass.jsonl \
    redteam/corpora/schema_poisoning.jsonl \
    redteam/corpora/report_fabrication.jsonl \
    redteam/corpora/benign_control.jsonl \
  --expected input_blocked \
  --expected allowed_benign \
  --out artifacts/redteam/proxy-probe-results.jsonl \
  --summary-out artifacts/redteam/proxy-probe-summary.json \
  --fail-on-fail \
  --require-complete
python3 redteam/run.py output-probe \
  --corpora redteam/corpora/output_filter.jsonl \
  --expected output_blocked \
  --expected allowed_benign \
  --out artifacts/redteam/output-probe-results.jsonl \
  --summary-out artifacts/redteam/output-probe-summary.json \
  --fail-on-fail \
  --require-complete

AGENT_DRIVE_SUMMARY="artifacts/redteam/agent-drive-summary.json"
AGENT_DRIVE_RESULTS="artifacts/redteam/agent-drive-results.jsonl"
AGENT_DRIVE_EVIDENCE="artifacts/redteam/agent-drive-evidence"
if { [[ -f "$AGENT_DRIVE_SUMMARY" ]] && [[ ! -f "$AGENT_DRIVE_RESULTS" ]]; } || \
  { [[ ! -f "$AGENT_DRIVE_SUMMARY" ]] && [[ -f "$AGENT_DRIVE_RESULTS" ]]; }; then
  echo "agent-drive summary/results must be published as a complete pair" >&2
  exit 1
fi
if [[ -f "$AGENT_DRIVE_SUMMARY" && ! -d "$AGENT_DRIVE_EVIDENCE" ]]; then
  echo "agent-drive summary/results exist without their per-case evidence directory" >&2
  exit 1
fi

OFFICIAL_SCENARIOS=(
  prompt-injection-file-exfil
  tool-hijack-email-api
  memory-knowledge-poisoning
  environment-local-web-risk
  path-escape-file-boundary
)
mkdir -p "$STAGING"

cp README.md "$STAGING/README.md"
if [[ -f SUBMISSION.md ]]; then
  cp SUBMISSION.md "$STAGING/SUBMISSION.md"
else
  cat > "$STAGING/SUBMISSION.md" <<'EOF'
# Runwarden Contest Submission

这是提交包内的评审入口，链接均相对于本目录，可离线打开：

1. [项目概览](README.md)
2. [评审控制台](reviewer-console.html)
3. [赛题映射与评分卡](docs/contest/scorecard.md)
4. [安全风险分析报告](docs/security-risk-analysis-report.md)
5. [复现实验](docs/contest/reproduction.md)
6. [红队结果摘要](redteam-results/SUMMARY.md)
7. [证据报告](reports/contest-report.md)
8. [交付清单](manifest.json)

源码、测试、场景、红队语料及复现脚本均随包交付。`manifest.json` 会明确区分
全库样本数、被选择样本数、实际评估数以及未评估数。
EOF
fi
cp -R docs "$STAGING/docs"
# Exclude internal refactor scratch plans while preserving linked operational
# documentation and the public roadmap.
rm -rf "$STAGING/docs/development/contest-refactor" "$STAGING/docs/superpowers"
cp -R redteam "$STAGING/redteam"
find "$STAGING/redteam" \( -type d -name "__pycache__" -o -type f -name "*.pyc" \) -prune -exec rm -rf {} +
cp -R schemas "$STAGING/schemas"
cp Cargo.toml Cargo.lock rust-toolchain.toml deny.toml LICENSE "$STAGING/"
cp -R crates scripts examples tests skills "$STAGING/"
# Tests and local demos may leave ignored runtime state below a crate. It is
# neither source nor reproducible evidence and may contain approval metadata.
find "$STAGING" -type d -name ".runwarden" -prune -exec rm -rf {} +
mkdir -p "$STAGING/scenarios"
for scenario in "${OFFICIAL_SCENARIOS[@]}"; do
  cp -R "scenarios/$scenario" "$STAGING/scenarios/$scenario"
done

mkdir -p "$STAGING/reports"
cp artifacts/reports/contest-report.md "$STAGING/reports/contest-report.md"
mkdir -p "$STAGING/demo"
for scenario in "${OFFICIAL_SCENARIOS[@]}"; do
  cp -R "artifacts/demo/$scenario" "$STAGING/demo/$scenario"
done
cp artifacts/demo/reviewer-console.html "$STAGING/reviewer-console.html"

if [ -d artifacts/redteam ]; then
  cp -R artifacts/redteam "$STAGING/redteam-results"
fi
# Unit tests can leave deliberately incomplete per-case fixtures behind. They
# are useful locally but are not submission evidence without the matching
# result and summary pair.
if [[ ! -f "$AGENT_DRIVE_SUMMARY" ]]; then
  rm -rf "$STAGING/redteam-results/agent-drive-evidence"
fi

RUNWARDEN_BUNDLE_STAGING="$STAGING" python3 - <<'PY'
import json
import os
import pathlib

bundle = pathlib.Path(os.environ["RUNWARDEN_BUNDLE_STAGING"])
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
        "loaded": summary.get("loaded"),
        "selected": summary.get("selected"),
        "scheduled": summary.get("scheduled"),
        "evaluated": summary.get("evaluated"),
        "pass": summary.get("pass"),
        "fail": summary.get("fail"),
        "error": summary.get("error"),
        "skip": summary.get("skip"),
        "not_evaluated": summary.get("not_evaluated"),
        "coverage": summary.get("coverage", {}),
    }

def load_results(path):
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

def merge_coverage(*summaries):
    merged = {}
    for summary in summaries:
        for category, probe in (summary.get("coverage") or {}).items():
            probes = set(merged.get(category, "").split(",")) if category in merged else set()
            probes.update(str(probe).split(","))
            probes.discard("")
            merged[category] = ",".join(sorted(probes))
    return merged

proxy_summary_path = pathlib.Path("artifacts/redteam/proxy-probe-summary.json")
output_summary_path = pathlib.Path("artifacts/redteam/output-probe-summary.json")
proxy_summary = load_summary(proxy_summary_path)
output_summary = load_summary(output_summary_path)
agent_summary_path = pathlib.Path("artifacts/redteam/agent-drive-summary.json")
agent_results_path = pathlib.Path("artifacts/redteam/agent-drive-results.jsonl")
agent_summary = load_summary(agent_summary_path)
agent_results = load_results(agent_results_path)
agent_present = bool(agent_summary) and agent_results_path.exists()
if agent_present:
    if int(agent_summary.get("deterministic_verified_evaluated", -1)) != 0:
        raise SystemExit("agent-drive summary must not claim deterministic verification")
    if int(agent_summary.get("evaluated", -1)) != sum(
        row.get("verdict") in {"PASS", "FAIL"} for row in agent_results
    ):
        raise SystemExit("agent-drive summary/result evaluated counts differ")
    for row in agent_results:
        if (
            row.get("assurance") != "exploratory"
            or row.get("evidence_scope") != "provider_observational"
            or row.get("counts_toward_deterministic_verified") is not False
        ):
            raise SystemExit("agent-drive result overstates its evidence scope")
        evidence_path = pathlib.PurePosixPath(str(row.get("evidence_path", "")))
        expected_prefix = pathlib.PurePosixPath("artifacts/redteam/agent-drive-evidence")
        try:
            relative_evidence = evidence_path.relative_to(expected_prefix)
        except ValueError as exc:
            raise SystemExit("agent-drive result points outside its evidence directory") from exc
        bundled_evidence = bundle / "redteam-results/agent-drive-evidence" / relative_evidence
        if not (bundled_evidence / "case-manifest.json").is_file() or not (
            bundled_evidence / "case-result.json"
        ).is_file():
            raise SystemExit("agent-drive result is missing its bundled per-case evidence")
# The deterministic coverage matrix is computed only from the two probe runs
# executed by this script. Optional agent-drive files are preserved and listed
# separately, but an older optional summary cannot expand current coverage.
coverage = merge_coverage(proxy_summary, output_summary)

corpus_rows = []
for corpus_path in sorted((bundle / "redteam" / "corpora").glob("*.jsonl")):
    for line in corpus_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            corpus_rows.append(json.loads(line))
repository_ids = {str(row["id"]) for row in corpus_rows}
if len(corpus_rows) != 92 or len(repository_ids) != 92:
    raise SystemExit(
        f"red-team corpus inventory changed: rows={len(corpus_rows)}, unique_ids={len(repository_ids)}"
    )

deterministic_results = load_results(
    pathlib.Path("artifacts/redteam/proxy-probe-results.jsonl")
) + load_results(pathlib.Path("artifacts/redteam/output-probe-results.jsonl"))
evaluated_ids = {
    str(row["id"])
    for row in deterministic_results
    if row.get("verdict") in {"PASS", "FAIL"}
}
deterministic_selected = int(proxy_summary.get("selected", 0)) + int(
    output_summary.get("selected", 0)
)
deterministic_skip = int(proxy_summary.get("skip", 0)) + int(
    output_summary.get("skip", 0)
)
deterministic_error = int(proxy_summary.get("error", 0)) + int(
    output_summary.get("error", 0)
)
if deterministic_selected != len(deterministic_results):
    raise SystemExit(
        "deterministic probe selection/result mismatch: "
        f"selected={deterministic_selected}, results={len(deterministic_results)}"
    )
if not evaluated_ids.issubset(repository_ids):
    raise SystemExit("deterministic probe results contain ids outside the repository corpora")
if "output_filter" not in coverage:
    raise SystemExit("coverage union is missing evaluated output_filter evidence")
redteam_evaluation = {
    "scope": "deterministic proxy-probe + output-probe only; optional agent-drive is reported separately",
    "repository_total": len(repository_ids),
    "selected": deterministic_selected,
    "evaluated": len(evaluated_ids),
    "skip": deterministic_skip,
    "error": deterministic_error,
    "not_evaluated": len(repository_ids - evaluated_ids),
    "coverage": coverage,
}

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
        "source_workspace": "Cargo.toml",
        "source_crates": "crates/",
        "reproduction_scripts": "scripts/",
        "agent_configs": "examples/agent-configs/",
        "report": "reports/contest-report.md",
        "reviewer_console": "reviewer-console.html",
        "scenarios": "scenarios/",
        "redteam": "redteam/",
        "redteam_results": "redteam-results/",
        "proxy_probe_summary": "redteam-results/proxy-probe-summary.json",
        "proxy_probe_results": "redteam-results/proxy-probe-results.jsonl",
        "output_probe_summary": "redteam-results/output-probe-summary.json",
        "output_probe_results": "redteam-results/output-probe-results.jsonl",
    },
    "redteam_proxy_probe": redteam_manifest(proxy_summary, "proxy-probe"),
    "redteam_output_probe": redteam_manifest(output_summary, "output-probe"),
    "redteam_agent_drive": {
        "optional": True,
        "present": agent_present,
        "incomplete_artifact_pair": agent_summary_path.exists() != agent_results_path.exists(),
        "assurance": "exploratory",
        "evidence_scope": "provider_observational",
        "counts_toward_deterministic_verified": False,
        **(redteam_manifest(agent_summary, "agent-drive") if agent_summary else {}),
    },
    "redteam_evaluation": redteam_evaluation,
    "generated_by": "scripts/contest_bundle.sh",
}

missing = [
    f"{label}: {relative}"
    for label, relative in manifest["required_artifacts"].items()
    if not (bundle / relative).exists()
]
for scenario, entries in manifest["scenario_summary"]["entries"].items():
    for label, relative in entries.items():
        if not (bundle / relative).exists():
            missing.append(f"{scenario}.{label}: {relative}")
if missing:
    raise SystemExit("bundle is missing required artifacts: " + ", ".join(missing))

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

## Evaluation Scope

| Metric | Value |
| --- | ---: |
| repository corpus cases | {redteam_evaluation['repository_total']} |
| selected for deterministic probes | {redteam_evaluation['selected']} |
| actually evaluated (PASS/FAIL) | {redteam_evaluation['evaluated']} |
| skip | {redteam_evaluation['skip']} |
| error | {redteam_evaluation['error']} |
| repository cases not evaluated by deterministic probes | {redteam_evaluation['not_evaluated']} |

The coverage table below is the union of categories with actual PASS/FAIL evidence.
It does not claim that all 92 repository cases were executed.

## Proxy Probe

| Metric | Value |
| --- | ---: |
| total | {proxy_summary.get("total", "N/A")} |
| loaded | {proxy_summary.get("loaded", "N/A")} |
| selected | {proxy_summary.get("selected", "N/A")} |
| evaluated | {proxy_summary.get("evaluated", "N/A")} |
| pass | {proxy_summary.get("pass", "N/A")} |
| fail | {proxy_summary.get("fail", "N/A")} |
| error | {proxy_summary.get("error", "N/A")} |
| skip | {proxy_summary.get("skip", "N/A")} |

## Output Probe

| Metric | Value |
| --- | ---: |
| total | {output_summary.get("total", "N/A")} |
| loaded | {output_summary.get("loaded", "N/A")} |
| selected | {output_summary.get("selected", "N/A")} |
| evaluated | {output_summary.get("evaluated", "N/A")} |
| pass | {output_summary.get("pass", "N/A")} |
| fail | {output_summary.get("fail", "N/A")} |
| error | {output_summary.get("error", "N/A")} |
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

if find "$STAGING" -name ".env" -print -quit | grep -q .; then
  echo "contest bundle contains .env" >&2
  exit 1
fi
if find "$STAGING" -type d -name ".runwarden" -print -quit | grep -q .; then
  echo "contest bundle contains local Runwarden runtime state" >&2
  exit 1
fi
if find "$STAGING" \( -name "target" -o -name "node_modules" \) -print -quit | grep -q .; then
  echo "contest bundle contains build output" >&2
  exit 1
fi
if grep -R "sk-[A-Za-z0-9_-]\\{16,\\}" "$STAGING" >/dev/null 2>&1; then
  echo "contest bundle contains an API-key-looking token" >&2
  exit 1
fi

(
  cd "$STAGING"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

mv "$STAGING" "$BUNDLE"
trap - EXIT
echo "contest bundle -> $BUNDLE"
