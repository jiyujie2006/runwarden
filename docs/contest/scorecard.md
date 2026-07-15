# 竞赛能力记分卡

状态不是完成度口号，而是证据等级：

- **Verified**：当前代码路径存在，并有测试或确定性场景可复核；
- **Prototype**：原型可运行，但依赖 mock、简化假设、可选外部组件或尚未达到生产强度；
- **Gap**：当前没有实现，答辩时不得暗示已经具备。

## 赛题要求与实现

| 能力 | 状态 | 具体实现与证据 | 诚实口径 |
| --- | --- | --- | --- |
| 至少 3 类攻击场景 | **Verified** | `scenarios/*` 中 5 个正式场景 | 覆盖提示注入/外泄、工具劫持、投毒、环境污染/SSRF、路径逃逸。 |
| 对抗样本与越狱用例集 | **Verified** | `redteam/corpora`：13 个 JSONL、92 条样本 | 手工标注 corpus，不是大规模公开 benchmark。 |
| 智能体攻击脚本 | **Verified** | `redteam/run.py` 的 `proxy-probe`、`output-probe`；各场景 `agent/script.json` | 两类 probe 与 scenario replay 可确定性复现；不用真实模型的脚本结果代替真实 agent 因果证据。 |
| 真实模型 agent-drive | **Prototype** | `redteam/run.py agent-drive` + OpenCode config + 每 case 证据目录 | 仅为 `provider_observational` / `exploratory`；可校验 session、run nonce、新鲜度、provider/action/关键参数摘要和 sealed event，但 prompt 到 tool-call 的因果未被密码学证明。不计入确定性 verified 覆盖或指标。 |
| Stimulus / driver / oracle 分离 | **Verified** | `attacks/*.md`、`agent/script.json`、`expected/provider-calls.json`；`validate_scenario_story` | driver 只含调用意图；稳定 `obs_ref` 仍来自 oracle，属于 fixture 而非盲测。 |
| 攻击输入来源绑定 | **Verified** | `story.input_sha256`、trace `source_sha256` | SHA-256 绑定原始攻击文件。 |
| 场景内因果链接 | **Verified** | trace `parent_obs_id` + `previous_hash` | 确定性 replay 中成立。 |
| Allow / deny / ask | **Verified** | `PolicyDecision::{Allowed,Denied,RequiresReview}` | Rust 内核拥有最终副作用裁决权。 |
| 工具调用与文件访问审计 | **Verified** | `KernelEnforcer`、scoped-root、`root_escape` 场景 | 越界路径在副作用前拒绝。 |
| Egress / SSRF 防护 | **Verified** | egress policy、`environment-local-web-risk` | 正式场景覆盖 localhost 与云元数据地址。 |
| 参数/身份/动作绑定、单次审批 | **Verified** | `ServerIdentity` + `ApprovalBinding` + durable claim；canonical provider-action gate；并发单次执行测试 | session/actor 由 MCP 启动边界注入，审批精确绑定 provider、canonical action、参数和风险上下文；不信任调用参数中自报的身份或伪装 action。单一共享文件系统上用原子 claim 防双花。 |
| Execution reservation | **Verified** | `.runwarden/execution-reservations`；reservation 写失败/完成测试 | 外部 provider 前先落 `reserved`，返回后原子推进为 completed/failed/indeterminate 并绑定输出摘要。 |
| 审计 fail-closed 语义 | **Verified** | `trace_write_failure_payload` 与相关 MCP 测试 | 前置 claim/reservation 失败不执行；完成审计失败不谎报副作用，但不能回滚外部动作。 |
| 0–100 五信号风险融合 | **Verified** | `crates/runwarden-anomaly/src/lib.rs` | 五个固定权重信号、risk level、建议动作和解释文本均可序列化。 |
| 异常风险动态门控 | **Verified** | durable anomaly history/challenge + `behavior_anomaly` gate | session 历史跨进程恢复；review 精确绑定 profile、风险信号、历史 generation 和 5 分钟 TTL，critical/deny 在副作用前拒绝。 |
| 代理客户端鉴权 | **Verified** | `RUNWARDEN_PROXY_CLIENT_TOKEN` Bearer capability + 鉴权/密钥分离与 HTTP framing 负向测试 | demo 每次生成独立 256-bit 客户 capability；代理先在 32 KiB/128 字段上限内解析 header 并拒绝重复 `Content-Length`/`Authorization`、`Transfer-Encoding`、慢请求与歧义 framing，再在读取 body、输入检查和上游转发前鉴权。连接并发与 I/O 时间也有界。客户 token 与上游 API key 必须使用不同环境变量和值。这是本机 capability，不是 OS 用户隔离。 |
| 模型输入/输出过滤 | **Verified** | `runwarden-llm-proxy` + `inspect_input` + proxy/output probes + 协议负向测试 | 按 Chat/Responses 严格 tagged union 检查所有文本、tool/function/custom 参数与 schema；拒绝未知 model-visible 字段、持久上下文、非文本输入和旁路 server builtin。非流式与 SSE 均 fail closed；Chat 必须有 `[DONE]`，Responses 必须有有效 completed 终态；坏 JSON、未知通道、截断和预算超限均不释放输出。trace 不落正文。 |
| Provider 审计完整性/隐私 | **Verified** | wrapper/completion binding、跨进程 append lock、output/debug redaction tests | 外层 decision/data/side-effect 与 reservation 被 sealed trace 绑定；日志只留输出摘要，空/坏 trace 不会通过验证。 |
| 安全与效用指标 | **Verified** | `runwarden_assurance::security_eval`、`tests/security_metrics.rs` | 定义 ASR、containment、recall、误拦截、任务完成、exact match、阻断及时性、P50/P95；零分母为 `null`。数值来自确定性 corpus/场景，不混入 exploratory agent-drive。 |
| 场景级 security_metrics | **Prototype** | `runwarden demo --all` 生成 `webui.json` / `metrics.json` | 当前 adapter 在 oracle 校验后评分，且无真实 latency；适合演示摘要，不是独立盲测。 |
| 证据支持的安全报告 | **Verified** | report lint + typed trace predicates | claim 必须引用唯一已知的 `obs_*`，provider、event type、decision、execution status、side-effect 完整 predicate 逐项精确匹配；空证据、重复 obs、provider-only 伪结论 fail closed。**Verified 仅表示结构化 predicate 被证据支持**，报告自由文本是描述，未经 NLP 语义真值证明。 |
| WebUI v2 snapshot / SSE | **Verified** | `/api/console/snapshot`、`/events`、30 秒 reconcile；run-scoped evidence verification | 每次交互 demo 使用新的 `.runwarden/runs/demo-*`。SSE 只是“有更新”通知，浏览器不直接渲染其 payload，而是重取 snapshot 并使用服务端重算的 trace/report/approval 验证结果；坏 JSONL 降级为 tampered。 |
| Attack Lab 与静态回放 | **Verified** | `reviewer-console.html`、四阶段故事板 | replay 是只读快照，不提供伪审批按钮。 |
| 实时审批台 | **Verified** | `/api/approvals/{id}/decision` + reviewer capability/Host/Origin gate + `approval-events.jsonl` | reviewer 身份固定于 Rust 服务器 session，不接受 JSON 自报；决定在共享锁下以原子替换写 record，再追加 sealed 审批链，审计失败时回滚 record。审计保留 canonical record/binding 摘要及 reviewer/理由摘要。MCP 在 claim 前精确核对；审批只改变 record，provider 仍必须重试并重新通过内核。 |
| 实时跨模型/工具权威因果链 | **Prototype** | UI 合并 model/provider trace | 两条链仍独立，snapshot 展示 sequence 不是事务级共同 story 顺序。 |
| OpenCode 单一 MCP 边界 | **Prototype** | `examples/agent-configs/opencode.runwarden-only.json` + 严格 config validator | provider/model 限定在本机代理，tool 规则为未知工具默认拒绝。配置可被验证，但真实部署仍需保证 agent 进程未获取上游 key，且没有旁路 shell/原生工具。 |
| 模拟邮件/API/浏览器/记忆工具 | **Prototype** | provider catalog、本地 sandbox/replay | 能演示策略和审计，不会发送真实邮件或生产 API 请求。 |
| 受限代码执行 | **Prototype** | `external.code.execute` + `runwarden-expression-v1` typed AST VM + 审批后单次执行测试 | 仅支持无环境能力的纯表达式 AST，上限为 16 KiB、256 节点、32 层、64 KiB 输出；没有文件、网络、env、shell 或进程原语。尚未纳入 5 个正式场景，是语言层 VM，**不是通用代码运行时或 OS 沙箱**。 |

## 不得过度声明的 Gap

| 能力 | 状态 | 当前缺口 | 建议下一步 |
| --- | --- | --- | --- |
| 外部数字签名/可信时间戳 | **Gap** | 当前只有本地 SHA-256 hash chain | 用 KMS/HSM 签署 chain head，并锚定远端 append-only log。 |
| 容器/VM/seccomp 强隔离 | **Gap** | 主要依赖应用层 allowlist、路径/网络策略和进程约束 | 增加独立低权限 runner、namespace/seccomp 或 microVM。 |
| 文件打开的 TOCTOU 消除 | **Gap** | 已做 canonical containment，但路径检查到打开之间仍可被同权限进程竞态替换 | 改用 dirfd + `openat2`/`O_NOFOLLOW` 组合，并对打开后对象重验与有界读取。 |
| 多节点智能体集群一致性 | **Gap** | claim/history/event lock 可协调同一共享文件系统，但不覆盖不同磁盘、网络分区和自动崩溃恢复 | 引入事务数据库/共识日志、租约、幂等键和 crash recovery。 |
| 真实生产邮件/API 集成 | **Gap** | 正式演示使用 mock/simulated provider | 增加安全测试租户、credential broker、幂等重试和回执对账。 |
| 训练型/跨节点异常模型 | **Gap** | 当前为固定权重 fusion；最小化历史虽可跨进程恢复，但阈值未校准且没有跨 state-directory 特征仓 | 用良性/恶意轨迹训练并建立共享特征仓，同时保留漂移、校准和解释评测。 |
| 正式训练数据泄露评测 | **Gap** | 没有成员推断/训练数据抽取独立场景 | 引入可控 canary、泄露率和拒答效用 benchmark。 |
| 跨链统一 story ledger | **Gap** | live model/provider trace 没有共同事务 story id | 在代理、MCP、审批和报告间传递不可伪造 correlation capability。 |

详细限制和指标定义见[安全风险分析报告](../security-risk-analysis-report.md)，架构差异化见[创新架构说明](innovation-architecture.md)。
