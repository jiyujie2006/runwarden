# Red-Team Results

## Summary

红队测试分三层：

| 层 | corpus / scenario | 验证方式 | 结果位置 |
| --- | --- | --- | --- |
| Model-call filtering | `prompt_injection`, `jailbreak`, `indirect_prompt_injection`, `encoded_bypass`, `schema_poisoning`, `report_fabrication`, `benign_control` | `proxy-probe` (deterministic, offline) | `artifacts/redteam/proxy-probe-summary.json` |
| Tool-call mediation | 5 个 `scenarios/*` | `runwarden eval scenarios` + `demo run` | `artifacts/demo/*/report.json`, `artifacts/reports/contest-report.md` |
| Real LLM agent drive | `path_escape` subset | `agent-drive` (optional, model-dependent) | `artifacts/redteam/agent-drive-results.jsonl` (if run) |

## Deterministic Proxy Probe

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
            redteam/corpora/indirect_prompt_injection.jsonl redteam/corpora/encoded_bypass.jsonl \
            redteam/corpora/schema_poisoning.jsonl redteam/corpora/report_fabrication.jsonl \
            redteam/corpora/benign_control.jsonl \
  --summary-out artifacts/redteam/proxy-probe-summary.json
```

结果在 `artifacts/redteam/proxy-probe-summary.json`，含 `total`/`pass`/`fail`/`skip`/`by_category`。

`contest_bundle.sh` 自动运行此命令并打包结果。
混合 corpus 中的 `tool_denied` / `requires_review` 行属于工具调用面，在
`proxy-probe` 中记为 `SKIP`，由 scenario replay 或 `agent-drive` 覆盖。

## Tool-Call Replay

```bash
target/debug/runwarden eval scenarios --json
bash scripts/release_gate_local.sh
```

5 个 scenario 的 provider-call 决策、denial、obs_ref、side_effect_executed 写入 `artifacts/demo/*/webui.json`，汇总到 `artifacts/reports/contest-report.md`。

## Notes

- `proxy-probe` 是 deterministic 且 offline 的，不依赖真实 LLM。
- `agent-drive` 使用 OpenCode + 真实/免费模型，因模型工具调用稳定性而列为可选。
- `allowed_benign` 样本证明过滤器不会全拦截。
- `expected` 枚举只有 4 值：`input_blocked` / `tool_denied` / `requires_review` / `allowed_benign`。`allowed_benign` 仅走 `proxy-probe`。
