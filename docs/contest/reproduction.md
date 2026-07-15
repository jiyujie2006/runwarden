# Reproduction

## Build

```bash
cargo build --workspace
```

## Contest Gate

```bash
bash scripts/release_gate_local.sh
```

## Final Bundle

```bash
bash scripts/contest_bundle.sh
```

## Red-Team Proxy Probe

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
  --summary-out artifacts/redteam/proxy-probe-summary.json \
  --fail-on-fail
```

## Red-Team Output Probe

```bash
python3 redteam/run.py output-probe \
  --corpora redteam/corpora/output_filter.jsonl \
  --summary-out artifacts/redteam/output-probe-summary.json \
  --fail-on-fail
```

## Red-Team Agent Drive

```bash
mkdir -p /tmp/oc-test
cp examples/agent-configs/opencode.runwarden-only.json /tmp/oc-test/opencode.json
export PATH="$PWD/target/debug:$PATH"
python3 redteam/run.py agent-drive \
  --corpora redteam/corpora/path_escape.jsonl \
  --config-dir /tmp/oc-test --model runwarden-proxy/big-pickle --limit 2
```

该可选路径要求本地 `127.0.0.1:8787` 代理已启动并配置可用 upstream；可先在另一终端运行 `runwarden demo`。每个 case 会注入独立的 server-owned session identity。

## Live Reviewer Console

```bash
./target/debug/runwarden demo
```

## Approve A Pending Review

```bash
Open `http://127.0.0.1:8088` and click Approve on a pending review.
```
