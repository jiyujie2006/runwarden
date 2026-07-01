# Contest Submission

Runwarden 的比赛交付入口:

- [Scorecard](scorecard.md)
- [Reproduction](reproduction.md)
- [Demo Script](demo-script.md)
- [Artifact Index](artifact-index.md)
- [Limitations](limitations.md)
- [Red-Team Results](redteam-results.md)

## OpenCode Integration

```text
OpenCode(agent, all builtin tools disabled)
  |- model call -> runwarden-llm-proxy -> cloud/mock LLM
  `- tool call  -> runwarden-mcp -> KernelEnforcer -> providers -> obs_* trace
```

OpenCode 是本项目选择的开源智能化应用载体。配置在 `examples/agent-configs/opencode.runwarden-only.json`: 内置工具全为 `false`, 只配置一个本地 MCP server `runwarden`。

验证覆盖:

- `crates/runwarden-mcp/tests/e2e_agent_flow.rs` 断言 `tools/list` 只含 `runwarden.*`。
- `validate_runwarden_only_agent_config` 拒绝 raw/unsafe/多 MCP/extra args/env/cwd/remote 配置。
- `examples/agent-configs/opencode.provider-call-denied-transcript.json` 记录文件越界读取被 Runwarden 拒绝。
