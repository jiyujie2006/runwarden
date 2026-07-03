# CLI Reference

`runwarden` exposes four user-facing commands. Session, provider, approval,
authority, eval, and UI internals are no longer separate CLI surfaces.

## Command Map

```bash
runwarden demo
runwarden demo --scenario tool-hijack-email-api --output artifacts/demo/tool-hijack-email-api --json
runwarden demo --all --output artifacts/demo --json

runwarden trace verify --trace trace.json --json
runwarden trace export --trace trace.json --provider runwarden.input.inspect --compact-refs --json

runwarden report lint --report report.json --trace trace.json --json
runwarden report render --report report.json --trace trace.json --format markdown --json
runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json

runwarden check --strict --json
```

## Demo

`runwarden demo` starts the Rust console at `http://127.0.0.1:8088` and the
LLM proxy at `http://127.0.0.1:8787/v1`. The browser console streams sealed
model-call JSONL and MCP provider-call events. Approval buttons update
`.runwarden/approvals/*.json`; MCP retries load matching approved records and
consume them once.

When running an agent from a different working directory, set:

```bash
export RUNWARDEN_STATE_DIR="$PWD/.runwarden"
export XDG_CONFIG_HOME=/tmp/oc-runwarden/xdg/config
export XDG_DATA_HOME=/tmp/oc-runwarden/xdg/data
export XDG_CACHE_HOME=/tmp/oc-runwarden/xdg/cache
export XDG_STATE_HOME=/tmp/oc-runwarden/xdg/state
```

The `XDG_*` variables keep OpenCode from merging user-level MCP servers into
the demo. Copy `examples/agent-configs/opencode.runwarden-only.json` to
`$XDG_CONFIG_HOME/opencode/opencode.json` and confirm `opencode debug config
--pure` lists only `runwarden` under `mcp`.

`runwarden demo --scenario <name> --output <dir> --json` executes the scenario
provider calls through the Rust kernel and provider layer, then writes
`trace.json`, `provider-calls.json`, `denials.json`, `report.json`,
`metrics.json`, and `webui.json`.

`runwarden demo --all --output artifacts/demo --json` runs all five scenarios
and writes `artifacts/demo/reviewer-console.html`.

## Trace Commands

`runwarden trace verify` and `runwarden trace export` accept sealed
`TraceEvent` data as either a JSON array or newline-delimited JSONL. Missing
`event_hash`, malformed JSONL, or hash-chain tampering fails closed.

## Output Paths

Demo and report outputs must be relative workspace paths. Absolute paths,
parent traversal, and symlink escapes are rejected. Symlink components are
accepted only when canonical containment keeps the output inside the workspace.
