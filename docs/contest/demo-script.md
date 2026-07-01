# Demo Script

## Goal

展示 Runwarden 如何在模型调用面和工具调用面同时监督智能体。

## Step 1: Build and Gate

```bash
cargo build --workspace
bash scripts/release_gate_local.sh
```

讲解点：5 个 scenario 全部 replay，通过 trace completeness 与 citation accuracy。

## Step 2: Prompt Injection Proxy Probe

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
            redteam/corpora/encoded_bypass.jsonl redteam/corpora/benign_control.jsonl
```

讲解点：恶意 prompt 被 `input_blocked`（HTTP 403），benign prompt 被 forwarded（HTTP 200）。trace 写入 `artifacts/redteam/proxy-trace.jsonl`。

## Step 3: Tool Hijack Scenario

```bash
target/debug/runwarden demo run \
  --scenario tool-hijack-email-api \
  --output artifacts/demo/tool-hijack-email-api \
  --json
```

讲解点：email send `requires_review`，hidden API callback `denied`，`side_effect_executed:false`。

## Step 4: Path Escape Scenario

```bash
target/debug/runwarden demo run \
  --scenario path-escape-file-boundary \
  --output artifacts/demo/path-escape-file-boundary \
  --json
```

讲解点：provider 在 allowlist 中，但 path 越界被 `root_escape` 拒绝，`side_effect_executed:false`。证明 Runwarden 不是"禁用所有危险工具"，而是在允许文件 provider 的情况下仍能判断越界。

## Step 5: Reviewer Console (static)

```bash
target/debug/runwarden ui build \
  --input artifacts/demo \
  --output artifacts/reviewer-console.html \
  --json
```

打开 `artifacts/reviewer-console.html`，展示：Security Events timeline、Review Queue、`obs_ref`、`side_effect_executed`。

## Step 6: Live SSE Replay

```bash
target/debug/runwarden ui serve --live \
  --demo artifacts/demo/tool-hijack-email-api \
  --llm-trace artifacts/redteam/proxy-trace.jsonl \
  --port 8088
```

讲解点：`provider_call` 与 `model_call` 统一出现在 live SSE stream。`proxy-trace.jsonl` 由 Step 2 的 proxy-probe 生成（含 sealed hash-chain events）。

## Step 7: Contest Bundle

```bash
bash scripts/contest_bundle.sh
```

讲解点：`artifacts/contest-bundle/` 含 SUBMISSION.md、docs、scenarios、redteam、demo、reports、reviewer-console.html、redteam-results、manifest.json、SHA256SUMS。
