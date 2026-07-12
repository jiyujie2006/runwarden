# Limitations

- API/browser provider 为安全模拟, 不真发网络请求。
- L2 semantic filter 是规则 + 词形相似原型, 非 embedding 模型。
- 真实 LLM `agent-drive` 受模型工具调用稳定性影响; 核心证据以 deterministic demo 为准。
- 异常检测是 allowed-call 事后评分, 不阻断; 不作为 red-team corpus `expected` 值。
- `output_blocked` 仅在流式路径产生; 非流式 proxy-probe 只记录 `output_flagged`; deterministic `output-probe` 和 proxy 单元测试共同证明流式阻断路径。
- WebUI 不是策略引擎；它只向 loopback Rust reviewer API 提交带 nonce、origin 和双版本约束的决定。SQLite journal 是唯一审批状态源，等待中的原始 MCP 调用继续同一个 operation；浏览器不写审批文件，也不重发 provider 参数。
