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

## Red-Team Agent Drive

```bash
python3 redteam/run.py agent-drive \
  --corpora redteam/corpora/path_escape.jsonl \
  --model opencode/big-pickle --limit 2
```

## Live Reviewer Console

```bash
./target/debug/runwarden demo
```

## Approve A Pending Review

```bash
Open `http://127.0.0.1:8088` and click Approve on a pending review.
```
