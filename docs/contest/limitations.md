# Limitations

- API/browser provider 为安全模拟, 不真发网络请求。
- L2 semantic filter 是规则 + 词形相似原型, 非 embedding 模型。
- 真实 LLM `agent-drive` 受模型工具调用稳定性影响; 核心证据以 deterministic demo 为准。
- 异常检测是固定权重、未经生产数据校准的可解释原型。MCP 已在副作用前 preview：critical 拒绝、high 要求精确绑定且有时限的动态审批；它只能升级处置，不能推翻 kernel deny 或授予新权限。
- 代理的 Chat/Responses 非流式与 SSE 均检查输出。`output-probe` 专门评测流式 corpus；严格字段/类型、多 choice/output、tool arguments、Responses 终态和 Chat `[DONE]` 的完整负向覆盖位于 Rust 测试，不应把 corpus 数量解读为全部协议状态的样本数。
- 真实 LLM `agent-drive` 仅是 `provider_observational` / `exploratory`；它验证调用与 sealed provider event 的 session、provider/action 和关键参数绑定，不密码学证明 prompt-to-tool 因果，不计入确定性覆盖和指标。
- report lint 的“证据支持”指 typed predicate 与 sealed trace 精确匹配；自由文本是人类可读描述，并没有 NLP 级语义真值证明。
- WebUI 不是策略引擎；它只通过带 reviewer capability、Host/Origin 校验的 Rust `/api/approvals/{id}/decision` 提交决定，写入 run-scoped approval ledger 与审批哈希链，再由 MCP 核验并单次消费。
- SSE 是不可信的更新提示；页面不直接渲染 SSE payload，而是重取 run-scoped snapshot 并显示服务端重算的验证结果。
- HTTP 审批决定要求 reviewer capability 与 Host/Origin 约束，但这不等同于操作系统用户隔离；能读取启动终端或浏览器 session 的同权限恶意程序仍可能窃取 capability。
- 本机模型代理有 header/body/连接数/I/O 时间上限并拒绝歧义 HTTP framing，但它仍是 loopback 原型，不提供 TLS、按 OS 身份限流或多租户边缘网关级抗 DoS；同权限本地进程仍可争用有限连接容量。
- 文件 provider 的应用层 canonical containment 仍存在检查到打开之间的 TOCTOU；生产版需要 dirfd/openat2/O_NOFOLLOW 与有界读取。
- `external.code.execute` 只是无文件/网络/env/shell/进程原语的有界 typed AST VM，不是任意代码运行时，也不是容器、seccomp 或 microVM 级 OS 沙箱。
