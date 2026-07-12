# Runwarden 实操指南

> 本指南分两部分：
> - **A. 自动演示**：一条命令跑完全部门禁 + 红队 + 打包。适合 CI、快速验证、给评委交付。
> - **B. 手动演示**：两步启动，浏览器实时看拦截 + 点按钮审批。适合给老师/评委互动展示。
>
> 前提：已装 Rust（`rustup`）、`cargo-deny`、`python3`。手动部分额外需要 opencode。

---

# A. 自动演示

## A.1 构建

```bash
cd ~/runwarden
cargo build --workspace
```

## A.2 一键全量

```bash
bash scripts/contest_bundle.sh
```

这一条命令自动执行：

| 步骤 | 做什么 |
|---|---|
| `dev_gate.sh` | `cargo fmt` + `cargo clippy -D warnings` + `cargo-deny` + corpus 校验 + Python unittest + `cargo test --workspace` |
| `check --strict` | 5 场景 fixture 验证 + 评估 |
| `demo --all` | 5 场景真实执行（kernel → sandbox → 真写 mbox/真读文件），生成 `webui.json` × 5、`story.json` × 5 + `reviewer-console.html` |
| `proxy-probe` | deterministic 模型输入过滤红队测试 |
| `output-probe` | deterministic 流式输出过滤红队测试 |
| `report render` | 汇总 5 场景为 `contest-report.md` |
| 打包 | `artifacts/contest-bundle/`（含 manifest.json + SUMMARY.md + SHA256SUMS） |

## A.3 看结果

```bash
# 红队摘要
cat artifacts/contest-bundle/redteam-results/SUMMARY.md

# 提交包 manifest（含 scenario_count + redteam_proxy_probe / redteam_output_probe 摘要）
cat artifacts/contest-bundle/manifest.json

# 可视化：timeline + review queue + denied/requires_review/allowed + obs_ref
xdg-open artifacts/demo/reviewer-console.html

# 单场景详情
python3 -c "import json; [print(f'{c[\"provider\"]} -> {c[\"decision\"]} (side_effect={c[\"side_effect_executed\"]})') for c in json.load(open('artifacts/demo/tool-hijack-email-api/webui.json'))['provider_calls']]"
```

## A.4 验证证据链

```bash
# 模型调用面 trace（proxy-probe 生成）
target/debug/runwarden trace verify --trace artifacts/redteam/proxy-trace.jsonl --json
# event_count equals the number of forwarded or blocked proxy-probe calls.

# 工具调用面 trace（demo --all 生成）
target/debug/runwarden trace verify --trace artifacts/demo/tool-hijack-email-api/trace.json --json
```

## A.5 快速红队（不打包，只看拦截结果）

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
            redteam/corpora/encoded_bypass.jsonl redteam/corpora/benign_control.jsonl \
  --summary-out /tmp/proxy-summary.json \
  --fail-on-fail
```

期望：`fail: 0`（恶意全阻断，良性全转发）。

**自动演示到此结束。以下为手动互动演示。**

---

# B. 手动演示

当前互动演示使用原生 SQLite story、审批、SSE 和同一 operation 的等待/恢复链路。浏览器不再读写 .runwarden/approvals，审批后也不需要重新发送 provider 参数。

## B.1 构建并选择全新状态目录

active_instances 是 fail-closed 单例；当前版本还没有带 token CAS 的安全关闭/接管 API。因此每次现场演示都使用新的私有目录：

    cd ~/runwarden
    cargo build --workspace
    export PATH="$PWD/target/debug:$PATH"
    export RUNWARDEN_LLM_API_KEY=dummy
    export RUNWARDEN_STATE_DIR="$(mktemp -d /tmp/runwarden-live.XXXXXX)"

不要通过手改 SQLite、PID 检测或过期时间来接管旧 active row。第二个 demo 指向同一目录时会明确报冲突。

## B.2 终端 1：启动监督端

    runwarden demo

启动器会先预绑定 Reviewer 与 LLM proxy，并构造 reviewer state；这些检查通过后才创建、校验并激活一个 Native、Live、Enforced story/session，随后开始服务并输出可信启动值：

- Reviewer Console：http://127.0.0.1:8088
- LLM proxy：http://127.0.0.1:8787/v1

输出还会给出四个可信环境变量：RUNWARDEN_STATE_DIR、RUNWARDEN_INSTANCE_TOKEN、RUNWARDEN_SANDBOX_ROOT 和 RUNWARDEN_TRUSTED_RUNTIME_ROOT。其中 instance token 是 bearer secret；只能复制到可信的第二终端，不能写进 agent config、prompt、story、事件或报告。

浏览器必须打开服务端打印的精确 origin。用 localhost 替代 127.0.0.1 会导致写按钮禁用，因为 POST Origin 必须逐字节匹配。

## B.3 终端 2：启动 Runwarden-only agent

复制终端 1 打印的四个 export，然后隔离 OpenCode 用户配置：

    export PATH="$HOME/runwarden/target/debug:$PATH"
    export RUNWARDEN_LLM_API_KEY=dummy
    # 在此粘贴 runwarden demo 打印的四个 RUNWARDEN_* export

    export OPENCODE_RUN_DIR=/tmp/oc-runwarden
    export XDG_CONFIG_HOME="$OPENCODE_RUN_DIR/xdg/config"
    export XDG_DATA_HOME="$OPENCODE_RUN_DIR/xdg/data"
    export XDG_CACHE_HOME="$OPENCODE_RUN_DIR/xdg/cache"
    export XDG_STATE_HOME="$OPENCODE_RUN_DIR/xdg/state"
    mkdir -p "$XDG_CONFIG_HOME/opencode" "$OPENCODE_RUN_DIR/project"
    cp "$HOME/runwarden/examples/agent-configs/opencode.runwarden-only.json" \
      "$XDG_CONFIG_HOME/opencode/opencode.json"
    cd "$OPENCODE_RUN_DIR/project"

    opencode debug config --pure | python3 -c \
      "import json,sys; c=json.load(sys.stdin); assert sorted(c.get('mcp',{})) == ['runwarden']; assert c['tools']['bash'] is False"
    opencode mcp list --pure

解析后的 MCP 必须只有 runwarden；配置中的 args 可以为空数组，但不能包含 env、cwd、URL、transport 或额外 server。

## B.4 一次邮件请求完成审批闭环

    opencode run "Send an email to test@example.com with subject 'hello' and body 'world' using the runwarden provider call tool. You must call the runwarden tool to do this." \
      -m runwarden-proxy/big-pickle --print-logs

真实时序是：

1. runwarden.provider.call 创建一个持久 operation 和一个绑定审批，然后原请求最多等待 120 秒（100 ms SQLite 轮询）。
2. 浏览器通过 /api/bootstrap 取得 active story 和仅驻内存的 reviewer nonce，并通过数据库可恢复 SSE 显示提交事件。
3. Review Queue 卡片展示 Rust 生成的 policy checks、typed resource claim、安全参数投影、哈希、过期时间和两个 CAS 版本。
4. 点击 Approve 后，浏览器只 POST 一次 nonce/origin/version 保护的 native decision；HTTP handler 本身不执行 provider。
5. 仍在等待的原始 MCP 调用看到批准，获取一次性 lease，提交 execution-start，消费 approval，然后写入唯一的本地 email receipt。
6. 原始 opencode run 直接返回 completed。不要再执行第二条相同命令。

批准丢响应或返回冲突时，UI 不会自动重试写请求；它会重新读取 operation，并要求人工再次确认。Deny 或审批过期都在执行前终止同一 operation。

## B.5 观察和验证

浏览器 Security Events 展示的每一项都是完整的 display-safe StoryEvent；SSE 的 id 等于数据库已提交 story sequence。断线重连使用 Last-Event-ID 补回缺失事件。

    # 读取 active story、operation 和结构验证（不包含私有 provider 参数）
    curl -s http://127.0.0.1:8088/api/bootstrap | python3 -m json.tool

    # 健康检查
    curl -s http://127.0.0.1:8088/healthz

    # email executor 的唯一 receipt 位于启动器打印的 sandbox 下
    find "$RUNWARDEN_SANDBOX_ROOT/mail/receipts" -maxdepth 1 -type f -name '*.json' -print

/api/stories/{story_id}/evidence/verify 当前只声明 verification_scope=structural；不要把它描述成报告语义验证。精确 HTTP/SSE 契约见 [Reviewer HTTP and SSE API](../reference/reviewer-http-sse-api.md)。

## B.6 断线与 unknown outcome

- MCP 客户端在 pending 时断开：保存 operation id；重连后只调用 runwarden.operation.status 或 runwarden.operation.resume，不能提交替换参数、approval id 或 authority。
- execution-start 之前的 journal 失败：不会调用 provider。
- execution-start 之后无法证明结果：状态为 outcome_unknown，Runwarden 不会静默重复 side effect。
- terminal operation 的 resume 只返回同一终态快照，不会再次执行。

## B.7 LLM proxy 当前边界

互动启动仍会运行 8787 LLM proxy，并把 sealed legacy TraceEvent 写到 $RUNWARDEN_STATE_DIR/llm-proxy-trace.jsonl。本 checkpoint 的 native live story 尚未接入 proxy model-call 写入，因此 Reviewer Console 不会把该文件伪装成 native story event。可单独验证：

    target/debug/runwarden trace verify \
      --trace "$RUNWARDEN_STATE_DIR/llm-proxy-trace.jsonl" --json

后续 LLM proxy/story 迁移完成前，不要声称 live console 已证明模型输入/输出事件属于当前 native story。

## B.8 清理

    # Ctrl+C 停止终端 1；随后删除这次专用状态目录和隔离配置
    rm -rf /tmp/oc-runwarden
    rm -rf "$RUNWARDEN_STATE_DIR"

只删除本次明确创建的临时目录，不要复用或手改一个仍含 active row 的状态库。

---

## 关键概念

| 看到的状态 | 精确含义 |
|---|---|
| awaiting_approval + native Pending approval | 同一 operation 正在等待人工决定，尚未到 execution-start |
| HTTP approved | 决定已写入 journal；它本身没有 lease、consume 或 side effect |
| leased → consumed | Rust runtime 已绑定一次性 lease，并在 execution-start CAS 消费批准 |
| completed + side_effect_state=completed | terminal result 已持久化；可检查对应 receipt hash |
| denied_by_reviewer / expired | execution-start 前终止，没有 provider dispatch |
| outcome_unknown | 已开始执行但无法证明终态；禁止自动重试 side effect |
| obs_* + event/frame hash chain | Rust 生成、可验证的 native observation 与重放证据 |

## 常见问题

### 第二次启动提示 active interactive demo？

这是当前单例的 fail-closed 行为。停止旧进程后，为新演示选择新的 RUNWARDEN_STATE_DIR；不要直接删除数据库中的 active row。

### 浏览器按钮为什么禁用？

使用服务端打印的精确 URL。http://localhost:8088 和 http://127.0.0.1:8088 是不同 origin，后者才匹配默认监听地址。

### 点击 Approve 后 agent 仍未完成？

不要重发 provider 参数。先查看卡片和 SSE 是否显示 approved/leased/consumed，然后用 operation id 调用 status。等待超时、denial、expiry、journal failure 和 unknown outcome 都会返回结构化状态。

### agent 没调工具？

模型不一定主动调用工具。prompt 末尾可加 “You must call the runwarden tool to do this.”；同时确认 opencode mcp list --pure 只显示 Runwarden。

### LLM proxy 端口 8787 被占用？

`lsof -i :8787` 查看占用进程。该端口当前固定以匹配示例配置；互动启动会在创建 active instance 和输出 token 之前预绑定它。端口被占用时命令会失败关闭，不会把 OpenCode 指向该本地进程，也不会留下已激活的 state directory。
