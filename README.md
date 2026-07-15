# Runwarden · Causal Defense Fabric for AI Agents

Runwarden 是面向大模型智能体的因果行为防火墙：在副作用发生前统一监督模型输入/输出、工具调用、文件与网络资源、异常行为和人类审批，并把每次裁决绑定到可复核的证据链。项目以 Rust 内核为可信裁决源，OpenCode 只看见一个 `runwarden-mcp` 能力边界。

它不把安全寄托在另一段 system prompt 上。核心链路是：

```text
attack stimulus → deterministic agent intent → policy + behavior risk
  → atomic one-use approval claim → durable execution reservation
  → simulated/contained effect → receipt + hash-chained observation
```

竞赛版提供五条可复现攻击链、92 条红队语料、OpenAI-compatible 模型代理、模拟邮件/文件/API/记忆工具、0–100 可解释风险融合，以及在线/离线共用的 AI Security Control Plane。

Agents see only `runwarden-mcp`. Filesystem, browser, email, API, memory, knowledge, and downstream MCP capabilities are represented as Runwarden providers and evaluated by Rust policy before any trusted side effect.

## Why It Is Different

- **Stimulus / driver / oracle 分离**：攻击文本、实际执行的 agent 脚本和预期断言不再混为一份 golden fixture；trace 写入攻击内容 SHA-256 和父 observation。
- **策略 + 行为联合监督**：序列偏离、未知出口、异常参数、敏感 source→sink、重复突发融合为 0–100 风险、等级、建议动作和逐项解释。
- **事务型副作用前门**：高风险审批使用原子 claim；动态批准还绑定短 TTL 风险上下文。执行前必须持久化 reservation，返回后推进最终状态；审计不可写时 fail closed，并发审批恰好一次消费。
- **隐私化可验证审计**：行为历史跨进程恢复但只存最小元数据，工具输出落盘仅保留类型/长度/hash，完整 provider wrapper 与 hash chain 双重验篡改。
- **证据驱动报告**：阻断、执行状态和报告 claim 通过 `obs_*` 与哈希链连接；空评测集不会得到虚假的满分。
- **评委可直接操作**：控制台展示 Model → Agent → Kernel → Tool 因果流、攻击故事板、审批台、异常解释与证据完整性，而不是普通日志列表。

## Core Components

| Component | Role |
| --- | --- |
| `crates/runwarden-kernel` | Rust source of truth for sessions, provider policy, approvals, trace, and contracts. |
| `crates/runwarden-providers` | First-party providers plus mediated demo/external provider catalog. |
| `crates/runwarden-mcp` | Only MCP server exposed to agents. |
| `crates/runwarden-cli` | Contest workflow: interactive demo, scenario runs, trace, reports, and checks. |
| `crates/runwarden-assurance` | Report lint/render and trace-backed scenario metrics. |
| `crates/runwarden-llm-proxy` | Local proxy for model-call filtering and red-team probes. |
| `crates/runwarden-anomaly` | 可解释的 0–100 行为风险融合与 source→sink 监测。 |
| `crates/runwarden-cli/src/console.html` | Rust-served reviewer console. |

## Demo

```bash
cargo build --workspace

target/debug/runwarden check --strict --json

target/debug/runwarden demo --all --output artifacts/demo --json

# Open the self-contained evidence replay
# artifacts/demo/reviewer-console.html

target/debug/runwarden report render \
  --scenario-suite scenarios \
  --format markdown \
  --output artifacts/reports/contest-report.md \
  --json
```

## Scenario Set

- `prompt-injection-file-exfil`
- `tool-hijack-email-api`
- `memory-knowledge-poisoning`
- `environment-local-web-risk`
- `path-escape-file-boundary`

Each scenario contains a benign request, attack prompt, deterministic demo-agent script, expected provider calls, expected denials, obs refs, report claims, and metric baselines.

## Verification

```bash
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
cargo test --workspace
```

完整创新架构见 [docs/contest/innovation-architecture.md](docs/contest/innovation-architecture.md)，风险分析见 [docs/security-risk-analysis-report.md](docs/security-risk-analysis-report.md)，比赛入口见 [docs/contest/README.md](docs/contest/README.md)。
