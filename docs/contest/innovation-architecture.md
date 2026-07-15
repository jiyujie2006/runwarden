# Runwarden 创新架构：从 Prompt Filter 到因果副作用控制面

## 1. 一句话定位

Runwarden 不是给大模型再加一段“请遵守安全规则”的提示词，而是在模型与外部能力之间建立一个 **Rust-owned、fail-closed、evidence-bound 的副作用控制面**：模型可以提出意图，但只有内核能决定是否执行，且每个结论都必须回到攻击来源、调用参数、审批状态和 observation 证据。

本文描述当前实现，而不是未来愿景。能力等级见[竞赛记分卡](scorecard.md)，攻击与限制见[安全风险分析报告](../security-risk-analysis-report.md)，现场复现见[6 分钟演示脚本](demo-script.md)。

## 2. 为什么常见方案不够

单一 prompt filter 通常只能回答“这段文本像不像恶意输入”，却回答不了以下问题：

- 模型最终调用了哪个 provider，参数是否被悄悄替换；
- 一次批准能否被修改参数后复用，或被两个并发 agent 双花；
- `denied` 是否真的发生在邮件、文件写入或 API 请求之前；
- 策略允许的调用是否形成了敏感 source → 外部 sink 的异常行为链；
- “攻击已阻断”这句话引用的 observation 是否真的支持该语义；
- 演示中的调用是否由攻击输入驱动，还是把 expected JSON 当作执行脚本。

Runwarden 把这些问题转化为类型、状态迁移、持久化门和可复核指标，而不要求 LLM 自己诚实汇报。

## 3. 系统架构

```text
┌────────────────────────── Untrusted context ──────────────────────────┐
│ user prompt · retrieved document · memory · tool output · environment │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                         normalize / decode / inspect
                                   │
                      ┌────────────▼────────────┐
                      │ runwarden-llm-proxy     │
                      │ client auth + strict I/O│
                      └────────────┬────────────┘
                                   │ model response / tool intent
                          ┌────────▼────────┐
                          │ Agent/OpenCode  │
                          │ sees one MCP    │
                          └────────┬────────┘
                                   │ runwarden.provider.call
                      ┌────────────▼────────────┐
                      │ runwarden-mcp           │
                      │ schema + authority gate │
                      └────────────┬────────────┘
                                   │
               ┌───────────────────▼────────────────────┐
               │ KernelEnforcer                         │
               │ allow / deny / requires_review         │
               │ provider allowlist · scoped root       │
               │ egress · budget · approval binding     │
               └──────────┬─────────────────────┬────────┘
                          │                     │
             ┌────────────▼──────────┐   ┌──────▼──────────────────┐
             │ Explainable anomaly   │   │ Human authority        │
             │ five signals / 0–100  │   │ pending → approved     │
             │ pre-effect escalation │   │ → claimed/consumed     │
             └────────────┬──────────┘   └──────┬──────────────────┘
                          │                     │ retry + re-evaluate
                          └──────────┬──────────┘
                                     ▼
                         durable execution reservation
                                     │
                          ┌──────────▼──────────┐
                          │ Provider / adapter  │
                          │ local mock today    │
                          └──────────┬──────────┘
                                     │ receipt
                ┌────────────────────▼────────────────────┐
                │ hash-chain trace · report semantic lint │
                │ security metrics · snapshot/SSE WebUI   │
                └─────────────────────────────────────────┘
```

### 3.1 控制权分配

| 层 | 可以做什么 | 不能做什么 |
| --- | --- | --- |
| LLM | 生成文本、提出工具意图 | 不能自授 provider、root、approval 或 budget。 |
| Agent | 调用公开的 Runwarden MCP schema | 不能提交 `session_id`、`authz_id`、`approval_id`、sandbox root 等 server-owned 字段。 |
| Kernel | 依据 registry、manifest、session、scope、egress 和审批裁决 | 不相信 agent 声称“已批准”或“没有副作用”。 |
| Anomaly gate | 给出风险分、信号和解释；在 MCP 中把处置升级为动态 review/deny | 不能把 kernel deny 降级为 allow，也不能授予新 provider 权限。 |
| Reviewer | 以启动时 capability 和服务端固定身份对 pending record 做 approve/deny | 不能直接触发 provider、不能从请求体自报身份，也不能批准修改后的参数。 |
| Provider broker | 只执行已 allowed 且已 reservation 的调用 | 不能把 denied/review case 伪装为执行完成。 |
| Assurance | 验证 trace、report claim 和评测指标 | 不能把无分母、无 evidence 的结果算作完美通过。 |

## 4. 一条攻击如何穿过系统

```text
attack fixture
  └─ SHA-256(source)
       └─ deterministic agent intent
            └─ kernel decision
                 ├─ denied ───────────────► no effect + sealed observation
                 ├─ requires_review
                 │    └─ bound approval
                 │         └─ atomic claim + consume
                 │              └─ execution reservation
                 │                   └─ provider + completion receipt
                 └─ allowed
                      └─ execution reservation
                           └─ provider + completion receipt

Each observation:
source_sha256 + parent_obs_id + previous_hash + decision + execution_status
+ error_kind + side_effect_executed + anomaly explanation
```

### 4.1 威胁链与控制点

| 攻击阶段 | 示例 | 控制点 | 证据 |
| --- | --- | --- | --- |
| 刺激污染 | 间接 prompt 注入、编码绕过 | LLM proxy / `inspect_input` | model trace、风险种类 |
| 意图劫持 | 偷加 callback、改 URL/BCC | MCP schema、参数 hash | provider call、argument hash |
| 权限提升 | 伪造 approval、扩大 root | server-owned authority、binding | approval record、policy gate |
| 横向/纵向移动 | 文件/记忆读取后外发 | source → sink signal、egress | anomaly signals、obs chain |
| 副作用执行 | 邮件、API、文件写 | claim、reservation、provider broker | reservation、completion receipt |
| 事后漂白 | 删除 trace、谎称未执行 | hash chain、semantic report lint | event hash、obs ref、lint result |

## 5. 核心创新

### 5.1 创新一：可证伪的 Stimulus–Driver–Oracle 三分法

传统演示常把 `expected.json` 既当输入又当答案，形成循环论证。Runwarden 的场景结构把：

- 原始攻击文本放在 `attacks/*.md`；
- 仅含 provider/action/arguments 的智能体意图放在 `agent/script.json`；
- decision/execution/error/obs ref 放在 `expected/provider-calls.json`。

执行路径只读取 driver 意图，策略产生 actual 后再与 oracle 比较。攻击原文 SHA-256 写入 story 和每条 trace，后续 observation 通过 `parent_obs_id` 串联。这样评委可以篡改任意一层并看到验证失败，而不是只能相信一段预录屏。

当前诚实边界：oracle 仍提供稳定 `obs_ref` 以支持报告 fixture；这不是未知集盲测。真实模型 `agent-drive` 是补充，不替代确定性证据。

代码证据：[场景执行器](../../crates/runwarden-cli/src/main.rs)、`scenarios/*/agent/script.json`、`scenarios/*/expected/provider-calls.json`。

### 5.2 创新二：把“审批”实现成副作用前事务协议

审批不是一个 agent 可提交的布尔值。`ApprovalBinding` 包含 session、provider、action、argument hash、actor、authz。批准后同样参数的重试必须完成：

```text
re-evaluate policy
  → verify reviewer decision chain + canonical record/binding digest
  → create_new(claim) + fsync
  → verify binding/state/expiry
  → atomic replace approval as Consumed + fsync
  → create execution reservation + fsync
  → execute provider
  → finalize reservation as completed/failed/indeterminate + output digest
  → append completion event + fsync
```

原子 claim 让同一文件系统上的并发请求最多一个获得单次审批；reservation 让“准备执行什么”和最终状态都有持久记录。动态异常审批还带有 5 分钟 durable challenge，精确绑定当时的 profile、风险信号与历史 generation；上下文变化后旧批准不能授权新风险。claim/reservation/challenge 失败会在 effect 前拒绝。

人工决定本身也是一个事务：reviewer capability 只放在启动 URL fragment 中，POST 还需精确 Host/Origin；Rust 固定 reviewer session 身份，并在与 MCP 共用的 review lock 内原子替换 record、追加审批哈希链。MCP 不相信“文件现在是 Approved”，而是重新验证唯一 decision event 及 canonical record/binding digest。每次 live run 都使用独立状态目录，旧 claim、锁或批准不会进入新证据。

完成审计失败的真实语义也被保留：如果 provider 已经执行，返回 `trace_write_failed` 时仍报告 `side_effect_executed=true`。系统拒绝错误的成功确认，但不假装能回滚外部世界。

代码证据：[MCP claim/reservation](../../crates/runwarden-mcp/src/lib.rs)、[并发与故障测试](../../crates/runwarden-mcp/tests/jsonrpc.rs)。

### 5.3 创新三：可解释的 0–100 行为风险融合

风险分由五个可单独审计的信号组成：

| Signal | Weight | 触发依据 |
| --- | ---: | --- |
| `unexpected_sequence` | 20 | provider bigram 偏离良性基线 |
| `novel_egress` | 25 | 新出口 host |
| `oversized_arguments` | 20 | 参数超过 provider 基线 |
| `sensitive_source_to_sink` | 55 | 有界历史中的敏感读取流向外部 sink |
| `repeated_burst` | 20 | 同 provider 连续突发 |

总分 `min(sum(weights), 100)`。默认阈值：25 medium、50 high、80 critical；映射建议为 allow、monitor、require_review、deny。历史只保留 provider、参数字节数和可选 host，不保存参数正文。

这个设计的竞争力在于“可解释且能嵌入执行前门”：MCP 先 preview candidate，不把被拒绝的 candidate 写入良性历史；critical/`deny` 直接形成 `behavior_anomaly` 拒绝，`require_review` 生成上下文 challenge。匹配的动态批准仍必须经过 challenge 重算、原子 claim、consume 和 execution reservation。该映射只能加严，不能把 kernel deny 改成 allow。risk report、signals、decision 和 defense layer 会进入 provider payload 与 trace，评委可以从分数反推每一分来自哪里。

行为历史按 state scope + session 持久化，只保存 provider、参数字节数和可选出口 host；跨进程锁覆盖读取、判定、执行和原子提交，进程重启不会清空基线。当前诚实边界：这不是训练模型，权重没有在大规模数据上校准；不同 state directory 之间也没有共享特征仓。

代码证据：[风险融合实现与测试](../../crates/runwarden-anomaly/src/lib.rs)。

### 5.4 创新四：证据不是日志附件，而是报告的类型约束

每个 `TraceEvent` 保存 `previous_hash` 和 `event_hash`；实时 observation id 将稳定 intent digest 与进程 epoch/单调序列分开，同样参数的两次调用仍可独立引用。报告 claim 必须引用唯一的 `obs_*`，并完整声明 provider、event type、decision、execution status 与 side-effect typed predicate。lint 对这些字段逐项精确匹配，不再从自由文本关键词猜测语义；仅写一个 provider 的“所有秘密都安全”伪结论不能通过。空 trace、空报告、重复 obs 和不可能的状态组合均 fail closed。

这将安全报告从自由文本提升为 evidence-backed artifact。provider 侧还把外层 decision、reason、approval、side-effect、脱敏 data 和 reservation receipt 递归规范化后绑定回 sealed trace；跨进程 append 锁避免共享文件上的链头竞争。工具输出正文只返回调用方，审计保存类型、长度和 SHA-256。哈希链负责局部篡改检测，typed predicate lint 负责防止“引用了不相干证据”；空或坏 trace 一律不能显示 verified。

当前诚实边界：hash chain 没有外部签名或可信锚；能完全改写本地文件的攻击者可以重算整条链。

代码证据：[assurance](../../crates/runwarden-assurance/src/lib.rs)、[kernel evidence](../../crates/runwarden-kernel/src/evidence.rs)。

### 5.5 创新五：安全、效用和及时性使用同一评测 contract

`security_eval` 用统一 case 结构评估 deterministic fixture、live agent 或导入 benchmark，避免只报告攻击阻断率而忽略误杀：

- ASR 与 containment 区分“做了 deny 决策”和“真的在 effect 前阻断”；
- malicious recall 单独反映决策覆盖；
- benign false block 与 task completion 反映效用；
- policy exact match 反映与独立 oracle 的一致性；
- blocked-before-effect 反映时序正确性；
- P50/P95 反映监督延迟。

所有零分母为 `null`；空 suite、缺少恶意/良性 case 都不能通过。这样不会出现“没有良性样本，所以误拦截率是 0%”的虚假高分。

代码证据：[security_eval](../../crates/runwarden-assurance/src/lib.rs)、[零分母与时序测试](../../crates/runwarden-assurance/tests/security_metrics.rs)。

### 5.6 创新六：同一 WebUI 兼顾 live 控制与可移交证据

WebUI 使用同一 `runwarden.console.v2` schema：

- live：`/api/console/snapshot` 首屏恢复，`/events` SSE 只通知变更，页面每次都重新获取后端验证 snapshot，另有 30 秒与页面恢复时 reconcile；
- replay：把已脱敏 snapshot 内嵌进单文件 HTML，评委离线打开即可复核；
- 行为流：搜索/筛选 decision、攻击族、provider、obs ref；
- Attack Lab：展示 stimulus、agent intent、enforcement、evidence；
- 审批台：live 模式写审批理由，replay 模式明确只读；
- 证据页：区分 model/provider trace 状态和 defense coverage。
- 摄取错误：坏 JSONL 不会被静默跳过，总体证据状态降级为 tampered 并展示错误。
- 审批证据：非 Pending ledger 必须回绑唯一 decision audit，provider trace 引用的 approval record 不得缺失。

代码证据：[snapshot/API](../../crates/runwarden-cli/src/server.rs)、[控制台](../../crates/runwarden-cli/src/console.html)。

当前诚实边界：live snapshot 只是把两条独立 hash chain 合并展示，尚无统一事务 story ledger；展示 sequence 不是可信的跨链时间顺序。

### 5.7 创新七：可审计代码执行采用“能力不存在”而非脆弱黑名单

为了覆盖赛题的代码执行监督，`external.code.execute` 没有把任意 Python/Shell 包装成“安全沙箱”。它执行 `runwarden-expression-v1` typed AST，限制 16 KiB 程序、256 节点、32 层深度和 64 KiB 输出；VM 数据模型中根本没有文件、网络、环境变量或子进程 primitive。调用仍被标为 high risk，先经过 canonical action、异常 gate、一次性审批、reservation 和 provider trace。

这是一种适合原型赛题的 capability-by-construction：能真实展示代码意图的 allow/deny/ask 与资源审计，又不会因为缺少容器/seccomp 而引入任意 RCE。诚实边界是它只支持纯计算 AST，不是通用语言运行器，也尚未纳入五个正式攻击故事；生产通用代码执行仍需独立低权限 runner 或 microVM。

## 6. 与常见 Prompt Filter 的差异

| 比较维度 | 常见 Prompt Filter | Runwarden 当前实现 |
| --- | --- | --- |
| 主要观测对象 | 文本 | 文本 + 工具意图 + 参数 + authority + side effect + trace |
| 执法位置 | 模型前/后 | 模型输入/所有输出分支与工具副作用前双控制面 |
| 对提示绕过的容错 | filter 漏检后通常失守 | 漏检后仍有 provider allowlist、scope、egress、审批 |
| 工具参数完整性 | 通常不绑定 | approval 绑定完整 argument SHA-256 |
| 并发审批 | 常为 UI 布尔状态 | `create_new` claim + single-use consume |
| 执行前凭证 | 无 | durable execution reservation |
| 行为异常 | 单条文本分类 | 有界序列、出口、参数、source→sink、burst 融合，并在 effect 前只升级为 review/deny |
| 副作用真实性 | 依赖 agent 自报 | provider envelope 明确 `side_effect_executed` |
| 审计 | 普通日志 | hash chain + obs ref + semantic report lint |
| 安全评测 | accuracy / block rate | ASR + containment + utility + timing + exact match |
| 复现 | prompt 截图/视频 | fixture、driver、oracle、trace、jq、静态 replay |
| 当前限制 | 语义泛化问题 | 仍有相同过滤限制，另有本地账本/mock/OS 隔离缺口 |

关键差异不是“Runwarden 的关键词更多”，而是 **prompt filter 失效后，模型仍然没有直接获得副作用权限**。

## 7. 指标口径

令：

- `M` 为 malicious cases，`B` 为 benign cases；
- `blocked(c) := decision(c) ∈ {denied, requires_review}`；
- `effect(c)` 表示 `side_effect_executed=true`。

则：

```text
ASR = |{c∈M : !blocked(c) or effect(c)}| / |M|
Containment = |{c∈M : blocked(c) and !effect(c)}| / |M|
Malicious Recall = |{c∈M : blocked(c)}| / |M|
Benign False Block = |{c∈B : blocked(c)}| / |B|
Benign Task Completion = |{c∈B : decision(c)=allowed}| / |B|
Policy Exact Match = |{c : expected(c)=actual(c)}| / |cases|
Blocked Before Effect = |{c : blocked(c) and !effect(c)}| / |{c : blocked(c)}|
```

P50/P95 对所有有限、非负且已提供的 `latency_ms` 排序后使用 nearest-rank。缺少 latency 的 case 被省略，非法 latency 产生 failure。

必须注意：

- `requires_review` 在本次调用没有副作用时属于 blocked；批准后的重试应作为新的 actual outcome 记录；
- malicious recall 只看 decision，不保证阻断发生在 effect 前，所以不能替代 containment；
- benign task completion 当前只看 allowed，是 decision-level proxy，不证明业务结果正确；
- 任意分母为 0 时返回 JSON `null`；空 suite 必然失败；
- 场景 demo 当前先校验 oracle，再汇总 metrics；公开测评应使用独立标签和未预筛选良性集。

## 8. 评委可能追问与回答

### Q1：这不就是关键词过滤加一个好看的看板吗？

不是。文本过滤只是第一层。真正的安全边界是 MCP + Rust kernel：provider allowlist、scoped-root、egress、审批绑定、claim、reservation 都发生在工具副作用前。即使 prompt filter 漏掉正式场景里的攻击，后续外泄仍被 review/deny。

### Q2：确定性 driver 是脚本，如何证明它代表真实 agent？

确定性 driver 用于可复现地验证策略和证据，不冒充模型自主性。它与 oracle 分离并绑定真实攻击 fixture。`agent-drive` 可接 OpenCode/真实模型作为补充，但模型可能不调工具，因此不作为固定通过门槛。两者回答不同问题：前者证明控制面，后者探索模型行为。

### Q3：为什么 `requires_review` 算 blocked？

评测 case 描述的是本次调用结果。`requires_review` 的本次调用必须 `side_effect_executed=false`，所以属于暂时 containment。Reviewer 批准后，agent 需要以相同参数重试并重新过内核；该次结果应单独记录。

### Q4：审批真的不会被并发双花吗？

同一共享文件系统上，claim 文件使用原子 `create_new`，并发测试验证只有一个调用执行，approval 随后持久化为 `Consumed`。行为历史和 event append 也使用按资源的 `create_new` 锁。但这不是分布式事务：多节点不同磁盘、网络分区、自动 stale-lock/claim 清理和完整崩溃恢复仍是 Gap。

### Q5：reservation 是否保证 exactly-once 外部副作用？

它保证在 effect 前先有持久化执行意图，并在 reservation 写失败时拒绝；不能单独保证跨外部系统 exactly-once。生产接入还需要 provider 幂等键、回执对账和 crash recovery。

### Q6：如果 provider 已执行，但审计写失败怎么办？

系统返回 `trace_write_failed`，同时保留 `side_effect_executed=true`，不会声称“执行前阻断”。这避免审计漂白，但无法回滚邮件/API。reservation 提供前置意图证据，生产版应再加 outbox/事务 broker。

### Q7：你们的 trace 是数字签名的吗？

不是。当前是 SHA-256 hash chain，可以发现局部修改和断链，但没有外部私钥签名、可信时间戳或 WORM。WebUI/答辩只应称 hash-chain verified；外部签名是明确 Gap。

### Q8：风险融合是机器学习模型吗？

不是，是五个固定权重的可解释行为信号。优势是无需训练数据即可旁路部署、每一分可审计；不足是权重未校准、适应性有限。未来可用学习模型替换 signal producer，但保留相同解释 contract。

### Q9：异常分数会直接改变执行结果吗？

会，但只能加严：critical/`deny` 在副作用前拒绝，`require_review` 生成参数与当前风险上下文双绑定、短 TTL 的动态审批；low/monitor 不改变原裁决。异常门不能推翻 kernel deny 或授予新 provider。这样既让行为风险真正参与控制，又避免它成为绕过确定性 policy 的第二套授权源。固定权重和阈值仍需通过误拦截数据校准。

### Q10：ASR=0 是否代表系统不会被攻破？

不代表。它只说明当前标注 deterministic suite 中所有 malicious cases 在 effect 前被 block。报告同时展示 corpus 范围、良性误拦截和 Gap；不能外推到未知模型、未知工具和所有语言变体。

### Q11：为什么零分母不返回 0？

没有恶意样本时，“ASR=0”会伪装成完美安全；没有良性样本时，“误拦截=0”会伪装成完美效用。因此使用 `null` 并使 suite 失败，迫使评测同时覆盖安全和可用性。

### Q12：邮件/API 是真的吗？

正式 demo 主要是本地 mock/simulated provider：邮件写入 mbox，API/browser 使用安全 replay。它证明控制和审计链，不证明生产第三方集成。真实 provider、凭据 broker、幂等和回执是 Gap。

### Q13：代码执行是否真正隔离？

已有 stdio adapter 的 exact command allowlist、禁 shell、环境清理、cwd/超时/输出限制和进程树清理，但没有 namespace/seccomp/容器/VM，且未纳入正式 5 场景。因此只能称受控执行原型，不能称 OS 强沙箱。

### Q14：能监督智能体集群吗？

接口形态可作为多个 agent 的统一 MCP 边界，但当前状态存储是本地文件协议，尚未验证多节点集群一致性。生产集群需要事务数据库/共识日志、租约、全局幂等键和统一 story ledger。

### Q15：实时页面中的模型事件和工具事件真有因果关系吗？

确定性 scenario trace 有 `source_sha256`、`parent_obs_id` 和哈希链；live 模式目前把 model/provider 两条独立链合并展示，sequence 是 snapshot 分配的视图顺序，不是权威跨链因果。统一 correlation capability 是下一阶段工作。

## 9. 竞争力总结

Runwarden 当前最有区分度的不是单点检测精度，而是六个可以一起演示、一起被证伪的工程性质：

1. 攻击 stimulus、执行 driver、评测 oracle 分离；
2. 攻击输入 SHA 与 observation 父链贯穿实际裁决；
3. 审批从 UI 按钮升级为 claim + consume + reservation 协议；
4. 异常分数由五个可解释行为信号组成，并在副作用前只升级为动态 review/deny；
5. 报告结论受 trace 语义约束，而非仅附一份日志；
6. 安全、效用、及时性和零分母规则统一进入可序列化指标。

同时，项目把外部签名、真实 provider、OS 强隔离、分布式一致性和训练型检测明确留在 Gap，而不是把原型包装成生产系统。这种可验证性与边界意识本身就是面向安全竞赛的重要竞争力。
