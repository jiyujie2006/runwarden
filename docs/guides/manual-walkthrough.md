# Runwarden Manual Walkthrough

## Automatic Gate

```bash
cd ~/runwarden
cargo build --workspace
bash scripts/release_gate_local.sh
xdg-open artifacts/demo/reviewer-console.html
```

The gate runs strict fixture checks, all five real demo scenarios, and the
trace-backed contest report.

## Interactive Demo

Terminal 1:

```bash
cd ~/runwarden
cargo build --workspace
target/debug/runwarden demo
```

Open `http://127.0.0.1:8088`.

Terminal 2:

```bash
cd ~/runwarden
export PATH="$PWD/target/debug:$PATH"
export RUNWARDEN_LLM_API_KEY=dummy
export RUNWARDEN_STATE_DIR="$PWD/.runwarden"
mkdir -p /tmp/oc-runwarden
cp examples/agent-configs/opencode.runwarden-only.json /tmp/oc-runwarden/opencode.json
cd /tmp/oc-runwarden
opencode run "send an email to test@example.com using the runwarden provider call tool" \
  -m opencode/big-pickle --print-logs
```

Expected flow:

1. MCP returns `requires_review` and writes `.runwarden/approvals/webui-obs_*.json`.
2. Browser review queue shows the pending provider call.
3. Click Approve.
4. Agent retries the same `runwarden.provider.call`.
5. MCP loads the approved record, kernel consumes it once, and the local mbox side effect is recorded.

Denied/path-escape prompts should stay `side_effect_executed=false`.
