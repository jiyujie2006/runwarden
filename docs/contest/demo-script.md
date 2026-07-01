# Demo Script

1. Run `bash scripts/release_gate_local.sh`.
2. Run a quick deterministic proxy-probe demo:

   ```bash
   python3 redteam/run.py proxy-probe \
     --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
       redteam/corpora/encoded_bypass.jsonl redteam/corpora/benign_control.jsonl \
     --summary-out artifacts/redteam/proxy-probe-summary.json \
     --fail-on-fail
   ```

   完整 deterministic proxy-probe 覆盖 `indirect_prompt_injection`、`schema_poisoning`、`report_fabrication` 等 corpus，由 `scripts/contest_bundle.sh` 自动运行并写入 `artifacts/redteam/proxy-probe-summary.json`。

   完整测试由 contest bundle 自动运行：

   ```bash
   bash scripts/contest_bundle.sh
   ```

   它会自动运行完整 proxy-probe corpus（7 个文件），并把结果打包到 `artifacts/contest-bundle/redteam-results/`。
3. Open `artifacts/reviewer-console.html`.
4. Show `prompt-injection-file-exfil`: input inspection, review hold, API denial.
5. Show `tool-hijack-email-api`: email `requires_review`, hidden API `denied`.
6. Show `path-escape-file-boundary`: filesystem `root_escape` denial.
7. Show `environment-local-web-risk`: localhost and metadata egress denial.
8. Open `artifacts/reports/contest-report.md` and point to cited `obs_*` refs.
9. Inspect `artifacts/contest-bundle/manifest.json`.
