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
LLM proxy at `http://127.0.0.1:8787/v1`. Startup first pre-binds both loopback
listeners and constructs reviewer state, then creates one Native, Live,
Enforced story/session and claims the state directory's singleton active
instance. A bind or reviewer setup failure leaves no active instance and emits
no trusted launcher values. The browser console reads native snapshots,
resumes committed story events over SSE, and submits
nonce/origin/version-protected decisions.

Launcher paths must be UTF-8 and free of terminal control characters. The
derived `sandbox` and `runtime` roots must be real direct child directories of
the canonical state directory; file leaves, symlinks, and escapes fail before
activation. LLM proxy bind, upstream, API-key environment name, and trace
values also reject empty or control-character text before they can be logged.
An approved original MCP call continues as the same operation and produces at
most one provider receipt; the operator does not resend provider arguments.

Use a fresh private state directory for each live launch; a second launch on an
already active directory fails closed. Startup prints the exact trusted values
to export in the OpenCode terminal. They have this shape:

```bash
export RUNWARDEN_STATE_DIR="$PWD/.runwarden"
export RUNWARDEN_INSTANCE_TOKEN="<ephemeral launcher secret>"
export RUNWARDEN_SANDBOX_ROOT="$RUNWARDEN_STATE_DIR/sandbox"
export RUNWARDEN_TRUSTED_RUNTIME_ROOT="$RUNWARDEN_STATE_DIR/runtime"
export XDG_CONFIG_HOME=/tmp/oc-runwarden/xdg/config
export XDG_DATA_HOME=/tmp/oc-runwarden/xdg/data
export XDG_CACHE_HOME=/tmp/oc-runwarden/xdg/cache
export XDG_STATE_HOME=/tmp/oc-runwarden/xdg/state
```

Copy the printed values rather than inventing them. The instance token is a
sensitive bearer secret: do not add it to agent config, transcripts, stories,
events, or reports. `runwarden demo --json` returns the same values under
`trusted_mcp_environment` for a trusted local launcher.

The `XDG_*` variables keep OpenCode from merging user-level MCP servers into
the demo. Copy `examples/agent-configs/opencode.runwarden-only.json` to
`$XDG_CONFIG_HOME/opencode/opencode.json` and confirm `opencode debug config
--pure` lists only `runwarden` under `mcp`.

`runwarden demo --scenario <name> --output <dir> --json` evaluates scenario
provider calls through the legacy Rust kernel projection, then writes
`trace.json`, `provider-calls.json`, `denials.json`, `report.json`,
`metrics.json`, `webui.json`, and the redacted, explicitly incomplete
`story.json` legacy projection. First-party inspection still runs in process.
External calls in this retained CLI scenario projection fail closed as
`native_executor_required`; the CLI never falls back to the removed public
business-tool dispatcher. The production MCP path already uses the durable
policy, approval, execution-lease, permit, executor, and result-journal chain,
and interactive mode now supplies its live story/session context. Static
scenario execution remains an explicitly incomplete legacy projection.

Exact reviewer routes and recovery behavior are documented in
[Reviewer HTTP and SSE API](reviewer-http-sse-api.md).

`runwarden demo --all --output artifacts/demo --json` runs all five scenarios
and writes exactly one `story.json` per official scenario plus
`artifacts/demo/reviewer-console.html`. Before the run it removes only direct
stale `story.json` file or symlink leaves from immediate ordinary nonofficial
child directories; it preserves directories, other files, nested stories, and
child symlink directories.

## Trace Commands

`runwarden trace verify` and `runwarden trace export` accept sealed
`TraceEvent` data as either a JSON array or newline-delimited JSONL. Missing
`event_hash`, malformed JSONL, or hash-chain tampering fails closed.

## Output Paths

Demo and report outputs must be relative workspace paths. Absolute paths,
parent traversal, and symlink escapes are rejected. Symlink components are
accepted only when canonical containment keeps the output inside the workspace.
Demo story writes additionally validate the `story.json` leaf, preventing an
existing leaf symlink from redirecting bytes outside the workspace.
