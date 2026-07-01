# Runwarden: 面向大模型及其应用的安全性研究提交说明

## 1. 项目一句话

Runwarden 是一个 Rust-owned agent security kernel, 把智能体工具调用统一收敛到 MCP 边界后执行策略审计、审批、阻断、异常评分和证据化报告。

## 2. 赛题预期成果覆盖

| 赛题要求 | Runwarden 实现 | 证据路径 |
| --- | --- | --- |
| 3+ 攻击场景 | 5 个 deterministic scenarios | `scenarios/*` |
| 对抗样本与越狱测试集 | 84 条 JSONL corpora | `redteam/corpora/*.jsonl` |
| 智能体攻击脚本 | proxy-probe + agent-drive | `redteam/run.py` |
| 工具调用拦截 | MCP -> KernelEnforcer | `crates/runwarden-mcp`, `crates/runwarden-kernel` |
| 允许/拒绝/询问 | `PolicyDecision::{Allowed,Denied,RequiresReview}` | `crates/runwarden-kernel/src/contracts/provider.rs` |
| 邮件/文件/API 模拟工具 | external providers | `crates/runwarden-providers` |
| 模型链路监控插件 | OpenAI-compatible proxy + sealed trace | `crates/runwarden-llm-proxy` |
| 基座过滤原型 | `inspect_input` + 词形相似 L2 | `crates/runwarden-providers::input` |
| 异常检测模型 | allowed-call 事后评分 | `crates/runwarden-anomaly` |
| 实时展示告警/阻断 | WebUI static + live SSE | `packages/webui`, `runwarden ui serve --live` |
| trace-backed report | report lint/render | `crates/runwarden-assurance` |
| 开源智能化应用载体 | OpenCode (runwarden-only config) | `examples/agent-configs/opencode.runwarden-only.json` |
| 最终提交包 | contest bundle | `scripts/contest_bundle.sh` -> `artifacts/contest-bundle/` |

## 3. 场景清单

| Scenario | 攻击面 | 期望决策 (provider-call) | 拒绝原因 |
| --- | --- | --- | --- |
| `prompt-injection-file-exfil` | 提示注入 / 文件外泄 | `requires_review` + `denied` | - |
| `tool-hijack-email-api` | 工具劫持 | `requires_review` + `denied` | - |
| `memory-knowledge-poisoning` | 记忆/知识投毒 | `requires_review` | - |
| `environment-local-web-risk` | SSRF / 环境污染 | `denied` | `egress_denied` |
| `path-escape-file-boundary` | 文件越界 | `denied` | `root_escape` |

> 说明：模型调用面的 prompt injection / jailbreak 由 `runwarden-llm-proxy` 在 `redteam/run.py proxy-probe` 中阻断为 `input_blocked`；scenario replay 侧展示的是攻击从 prompt 进入工具链后，文件读取被 review gate 拦截、外泄 API 被 deny 的证据链。"期望决策"列只含 `PolicyDecision` 枚举值（`allowed` / `denied` / `requires_review`）；"拒绝原因"列是 `error_kind`。

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
- 审批机制: `RequiresReview` + CLI approval。
- 行为异常评分: `runwarden-anomaly`。
- Hash-chain trace: sealed `TraceEvent`。
- Report citation lint: `report_lint` 测试覆盖。

## 7. 局限

- API/browser provider 为安全模拟, 不真发请求。
- L2 semantic filter 是轻量词形相似原型, 不是 embedding 模型。
- 真实 LLM `agent-drive` 受模型工具调用稳定性影响; 核心演示以 deterministic demo 为准。
- 异常检测是 allowed-call 事后评分, 不阻断, 不作为 red-team corpus `expected`。
- Runwarden 为私有原型，不要求开源；赛题要求的"开源智能化应用"由 OpenCode 满足（MIT license，配置见 `examples/agent-configs/opencode.runwarden-only.json`）。如需公开评审源代码，可提供仓库访问权限。
