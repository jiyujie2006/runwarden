# Contest Scorecard

| Requirement | Status | Implementation | Evidence | Note |
| --- | --- | --- | --- | --- |
| 3+ attack scenarios | Done | 5 scenarios | `scenarios/*` | 第 5 个为文件越界场景。 |
| Adversarial prompts | Done | JSONL 80+ | `redteam/corpora` | 覆盖提示注入、越狱、工具劫持、路径逃逸、投毒和 benign control。 |
| Agent attack scripts | Done | proxy-probe, agent-drive | `redteam/run.py` | deterministic proxy probe 和真实 LLM agent-drive 分离。 |
| Tool-call supervision | Done | `KernelEnforcer` | `crates/runwarden-kernel` | Rust-owned policy gate。 |
| File access audit | Done | scoped root + `root_escape` | `crates/runwarden-kernel/tests/kernel_enforcement.rs` | 越界读取在 side effect 前拒绝。 |
| API/email tools | Done | `external.api.request`, `external.email.send` | provider catalog | 模拟业务工具, 不真发网络或邮件。 |
| Model-call filtering | Done | `runwarden-llm-proxy` | `crates/runwarden-llm-proxy` | 输入过滤、输出过滤和 sealed trace。 |
| Anomaly model | Done | `runwarden-anomaly` | `crates/runwarden-anomaly` | allowed-call 事后评分, 不替代 deny/review policy。 |
| Supplemental anomaly evidence | Done | example fixture | `examples/scenarios/anomalous-provider-sequence` | 不属于官方 5 场景, 用于展示 anomaly metadata。 |
| Live console | Done | Rust SSE console | CLI | timeline + review queue 展示 Rust-produced state。 |
| Evidence-backed report | Done | report lint 21 tests | `crates/runwarden-assurance/tests/report_lint.rs` | 验证 `obs_*` 引用和 claim semantics。 |
| Allow/deny/ask | Done | `PolicyDecision` 3 态 | `crates/runwarden-kernel/src/contracts/provider.rs` | `Allowed`, `Denied`, `RequiresReview`。 |
| OpenCode integration | Done | runwarden-only config | `examples/agent-configs` | OpenCode 只看见 `runwarden-mcp`。 |
