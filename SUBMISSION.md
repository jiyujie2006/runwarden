# Runwarden: 面向大模型及其应用的安全性研究提交说明

## Quickstart

1. `bash scripts/release_gate_local.sh` — 5 个 scenario 真实 kernel/provider demo + report + console。
2. `bash scripts/contest_bundle.sh` — 自动运行完整 proxy-probe + 生成最终提交包。
3. 打开 `artifacts/reviewer-console.html` — 查看 timeline / review queue / denied / obs_ref。
4. 阅读 `artifacts/reports/contest-report.md` — trace-backed 报告，每个结论引用 `obs_*`。
5. 检查 `artifacts/redteam/proxy-probe-summary.json` — deterministic 红队测试结果。

## 1. 项目一句话

Runwarden 是一个 Rust-owned agent security kernel, 把智能体工具调用统一收敛到 MCP 边界后执行策略审计、审批、阻断、异常评分和证据化报告。

## 2. 赛题预期成果覆盖

### 成果一: 安全风险分析报告

- 至少 3 类攻击场景: 5 个 scenario, 见 `scenarios/`。
- 对抗样本与越狱用例集: 80+ JSONL, 见 `redteam/corpora/`。
- 智能体攻击脚本: proxy-probe + agent-drive, 见 `redteam/run.py`。

### 成果二: 行为监督原型系统

- 拦截智能体与外部工具交互: `KernelEnforcer` + `runwarden-mcp`。
- 允许/拒绝/询问策略: `PolicyDecision` 三态。
- 异常检测: `runwarden-anomaly`, 对 allowed call 做事后评分。
- 模拟业务工具: file/email/api/memory/knowledge/browser providers。
- 模型调用链路监控: `runwarden-llm-proxy` sealed hash-chain trace。
- 基座模型过滤: `inspect_input` 规则 + 词形相似原型。
- 监督端展示: Rust reviewer console + live SSE。
- 开源智能化应用载体: OpenCode, 使用 runwarden-only config。

## 3. 场景清单

| Scenario | 攻击面 | 期望决策 |
| --- | --- | --- |
| `prompt-injection-file-exfil` | 提示注入 | `input_blocked` |
| `tool-hijack-email-api` | 工具劫持 | `requires_review` + `denied` |
| `memory-knowledge-poisoning` | 记忆/知识投毒 | `requires_review` |
| `environment-local-web-risk` | SSRF/环境污染 | `egress_denied` |
| `path-escape-file-boundary` | 文件越界 | `denied root_escape` |

## 4. 快速复现

```bash
cargo build --workspace
bash scripts/release_gate_local.sh
bash scripts/contest_bundle.sh
```

## 5. 演示路线

1. Prompt injection 被 LLM proxy 阻断为 `input_blocked`。
2. Tool hijack 触发 email `requires_review` 和 API `denied`。
3. Path escape 触发 `root_escape` denied。
4. Local metadata SSRF 触发 `egress_denied`。
5. WebUI 查看 `provider_call` timeline / review queue / `obs_ref` / `side_effect_executed`; live 模式额外展示 `model_call`。

## 6. 安全设计

- 输入输出过滤: `inspect_input`。
- 上下文隔离: MCP 边界收敛。
- 工具边界收敛: raw tools disabled。
- Rust policy gate: `KernelEnforcer`。
- 审批机制: `RequiresReview` + browser approval file + MCP retry consumption。
- 行为异常评分: `runwarden-anomaly`。
- Hash-chain trace: sealed `TraceEvent`。
- Report citation lint: `report_lint` 测试覆盖。

## 7. 局限

- API/browser provider 为安全模拟, 不真发请求。
- L2 semantic filter 是轻量词形相似原型, 不是 embedding 模型。
- 真实 LLM `agent-drive` 受模型工具调用稳定性影响; 核心演示以 deterministic demo 为准。
- 异常检测是 allowed-call 事后评分, 不阻断, 不作为 red-team corpus `expected`。
- Runwarden 当前为比赛原型仓库；赛题中"开源智能化应用"要求由 OpenCode（MIT license）作为被监督对象满足。评审需要源码时，可提供仓库访问权限或公开评审快照。
