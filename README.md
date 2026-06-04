# Runwarden Enterprise

> MCP + Skills 原生的 AI Agent 安全运行时边界。

Runwarden 让 agent 只看见 `runwarden-mcp`，并把所有工具调用、外部 MCP、Skill
辅助能力和报告输出都收束到 Rust 安全内核。内核在副作用发生前完成 provider
allowlist、scoped root、egress、budget、active assessment、authz、approval 和
trace 检查。

![Runwarden Agent-Native Security Runtime](docs/assets/runwarden-agent-native-control-plane.png)

一句话：

> Agent 可以规划任务，但执行动作必须经过 Runwarden。人类审查风险、审批高危动作、验证证据。

## 适用场景

Runwarden 面向需要可审批、可审计、可复现 agent 执行面的政企场景：

- 政务办公助手和企业知识库问答助手。
- 文档处理、流程办理、审批和运维协同 agent。
- 需要 MCP、Skill、插件或外部 API 扩展的高风险 agent。
- 需要输出 `obs_*` trace、cited report、audit summary 和 artifact bundle 的评测或审计流程。

## 核心边界

```text
AI Agent / LLM Runtime
    |
    v
Runwarden Skill + runwarden-mcp
    |
    v
runwarden.provider.call
    |
    v
Rust Runtime Enforcement Kernel
    |
    +--> controlled providers
    +--> approval queue
    +--> denied outcome with side_effect_executed=false
    |
    v
obs_* hash-chained trace
    |
    v
cited reports / audit / accountability / artifact bundle
```

Agents must not receive raw shell, filesystem, browser, HTTP, or downstream MCP
servers directly. Those capabilities are represented as Runwarden providers and
are evaluated by the same kernel policy path.

## 主要组件

| Component | Role |
| --- | --- |
| `crates/runwarden-kernel` | Rust source of truth for contracts, manifests, policy gates, approvals, trace, artifacts, and provider outcomes. |
| `crates/runwarden-mcp` | Agent-facing MCP server. It exposes only `runwarden.*` tools. |
| `crates/runwarden-cli` | Human control plane for sessions, providers, approvals, trace, reports, eval, cert, bench, artifacts, UI, and Local API. |
| `crates/runwarden-api` | Token-protected Local API used by the Reviewer Console and SDK. |
| `crates/runwarden-providers` | First-party provider catalog plus mediated external-provider adapters. |
| `crates/runwarden-assurance` | Report lint/render/scaffold, audit, accountability, eval, cert, bench, and artifact checks. |
| `packages/agent-sdk` | TypeScript Local API client and generated Rust contract declarations. |
| `packages/webui` | Dependency-free static Reviewer Console renderer. |
| `packages/config-tools` | TypeScript helper for invoking Rust-owned agent-config certification. |
| `skills/runwarden-security-assessment` | Agent skill that instructs agents to stay inside the Runwarden boundary. |

## 快速开始

Prerequisites:

- Rust `1.95+`
- Node.js compatible with the workspace TypeScript toolchain
- `pnpm 11.4.0+`
- `cargo-deny 0.19.6` for local gates

```bash
pnpm install
cargo build --workspace
```

Run the fast development gate:

```bash
bash scripts/dev_gate.sh
```

Run the release-style local gate:

```bash
bash scripts/release_gate_local.sh
```

On Windows, replace `target/debug/runwarden` with
`target\debug\runwarden.exe` when invoking the compiled binary directly.

## 一条评审链路

```bash
target/debug/runwarden session create \
  --manifest scenarios/enterprise-agent-security/manifests/assessment.toml \
  --session enterprise_ops \
  --json

target/debug/runwarden provider list \
  --session enterprise_ops \
  --json

target/debug/runwarden trace verify \
  --trace tests/fixtures/default-trace.json \
  --json

target/debug/runwarden report lint \
  --report tests/fixtures/default-report.json \
  --trace tests/fixtures/default-trace.json \
  --json

target/debug/runwarden artifact submission \
  --full \
  --output artifacts \
  --json

target/debug/runwarden artifact verify \
  --artifacts artifacts \
  --manifest artifacts/artifact-manifest.json \
  --json
```

Launch the static Reviewer Console bundle:

```bash
target/debug/runwarden ui \
  --bind 127.0.0.1 \
  --port 8088 \
  --artifacts artifacts \
  --json
```

`launch_url` points to the generated `reviewer-console.html` file. Start the
Local API separately when browser approval submission is needed:

```bash
target/debug/runwarden api serve \
  --bind 127.0.0.1 \
  --port 8088 \
  --json
```

## 文档入口

Start with the grouped documentation index:

- [Runwarden Docs](docs/README.md)
- [Repository Review](docs/repository-review.md)
- [CLI Reference](docs/reference/cli.md)
- [MCP Reference](docs/reference/mcp.md)
- [Reviewer Console Guide](docs/guides/reviewer-console.md)
- [Release Process](docs/development/release-process.md)

Reference pages under `docs/reference/` are intentionally kept as the source for
provider, report, artifact, approval, MCP, and release behavior. When changing
those surfaces, update the matching reference page with the code change.

## 当前状态

Runwarden Enterprise is an agent-native security runtime prototype. The current
workspace provides:

- MCP + Skill boundary for agents.
- Rust-owned runtime enforcement kernel.
- Human review surfaces through CLI, static WebUI, and Local API.
- Evidence-backed outputs through `obs_*` trace, cited reports, audit,
  accountability, eval, cert, bench, and artifact bundles.
