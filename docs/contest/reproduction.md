# Reproduction

## Build

```bash
cargo build --workspace
pnpm install
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

## Red-Team Agent Drive

```bash
python3 redteam/run.py agent-drive \
  --corpora redteam/corpora/path_escape.jsonl \
  --model opencode/big-pickle --limit 2
```

## Live Reviewer Console

```bash
./target/debug/runwarden ui serve --live \
  --demo artifacts/demo/tool-hijack-email-api \
  --llm-trace artifacts/llm-proxy/trace.jsonl \
  --port 8088
```

## Approve A Pending Review

```bash
target/debug/runwarden approval pending --json
target/debug/runwarden approval approve <approval_id> \
  --reviewer reviewer_alice --reason "reviewed scope and risk" --json
```
