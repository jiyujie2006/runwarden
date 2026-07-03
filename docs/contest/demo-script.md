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

   deterministic proxy-probe 覆盖模型输入过滤 corpus；工具、路径、记忆和 egress corpus 由 scenario replay 或可选 `agent-drive` 覆盖。

   完整测试由 contest bundle 自动运行：

   ```bash
   bash scripts/contest_bundle.sh
   ```

   它会自动运行 proxy-probe 和 output-probe，并把结果打包到 `artifacts/contest-bundle/redteam-results/`。
3. Open `artifacts/demo/reviewer-console.html`.
4. Show `prompt-injection-file-exfil`: input inspection, review hold, API denial.
5. Show `tool-hijack-email-api`: email `requires_review`, hidden API `denied`.
6. Show `path-escape-file-boundary`: filesystem `root_escape` denial.
7. Show `environment-local-web-risk`: localhost and metadata egress denial.
8. Open `artifacts/reports/contest-report.md` and point to cited `obs_*` refs.
9. Inspect `artifacts/contest-bundle/manifest.json`.
10. Point reviewers at business-tool evidence:
    `scenarios/tool-hijack-email-api/expected/provider-calls.json` for email review,
    `scenarios/tool-hijack-email-api/expected/denials.json` for API denial,
    `scenarios/path-escape-file-boundary/expected/denials.json` for root escape,
    and `scenarios/memory-knowledge-poisoning/expected/provider-calls.json` for knowledge review.
