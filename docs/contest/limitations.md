# Limitations

- API/browser provider 为安全模拟, 不真发网络请求。
- L2 semantic filter 是规则 + 词形相似原型, 非 embedding 模型。
- 真实 LLM `agent-drive` 受模型工具调用稳定性影响; 核心证据以 deterministic demo 为准。
- 异常检测是 allowed-call 事后评分, 不阻断; 不作为 red-team corpus `expected` 值。
- `output_blocked` 仅在流式路径产生; 非流式 proxy-probe 只记录 `output_flagged`; deterministic `output-probe` 和 proxy 单元测试共同证明流式阻断路径。
- WebUI 不是策略引擎; 它只通过 Rust `/api/approve` 和 `/api/deny` handler 提交审批决定, 写入 `.runwarden/approvals`, 再由 MCP 重试消费。
