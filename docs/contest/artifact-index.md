# Artifact Index

## Open These First

1. `artifacts/demo/reviewer-console.html`
2. `artifacts/reports/contest-report.md`
3. `artifacts/contest-bundle/manifest.json`
4. `artifacts/contest-bundle/redteam-results/SUMMARY.md`

## Judge Route Map

```text
OpenCode agent
  |- model call -> runwarden-llm-proxy -> input/output filter -> model_call obs_*
  `- tool call  -> runwarden-mcp -> KernelEnforcer -> providers -> provider_call obs_*
                                                `-> approval / deny / anomaly

Reviewer console/report <- verified obs_* evidence chain
```

| Path | Purpose |
| --- | --- |
| `SUBMISSION.md` | 中文提交总入口。 |
| `docs/contest/scorecard.md` | 赛题要求到实现证据映射。 |
| `docs/security-risk-analysis-report.md` | 安全风险分析报告。 |
| `redteam/corpora/*.jsonl` | 对抗样本与 benign control。 |
| `redteam/run.py` | proxy-probe、output-probe 和 agent-drive 攻击脚本。 |
| `scenarios/*` | deterministic scenario fixtures。 |
| `artifacts/demo/*` | demo replay 输出。 |
| `artifacts/reports/contest-report.md` | trace-backed contest report。 |
| `artifacts/demo/reviewer-console.html` | 静态 reviewer console。 |
| `artifacts/contest-bundle/redteam-results/SUMMARY.md` | 最终包内生成的 red-team probe 摘要和覆盖矩阵。 |
| `artifacts/contest-bundle/manifest.json` | 最终包 manifest，含 red-team probe 摘要字段。 |
| `artifacts/contest-bundle/` | 最终提交包。 |
| `artifacts/redteam/proxy-probe-summary.json` | deterministic proxy-probe 结果汇总。 |
| `artifacts/redteam/proxy-probe-results.jsonl` | 每条攻击的详细决策。 |
| `artifacts/redteam/output-probe-summary.json` | deterministic output-probe 结果汇总。 |
| `artifacts/redteam/output-probe-results.jsonl` | 每条输出过滤样本的详细决策。 |
| `docs/contest/redteam-results.md` | 红队测试覆盖说明。 |
