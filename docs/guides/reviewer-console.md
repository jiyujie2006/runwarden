# Reviewer Console Guide

The Reviewer Console is a Rust-served security workbench for humans. It
displays Rust-produced event JSON and can write reviewer approval decisions.
It is not a policy engine.

## Local Build

Build the workspace first:

```bash
cargo build --workspace
```

Generate demo JSON:

```bash
target/debug/runwarden demo --all --output artifacts/demo --json
```

Open the static console:

```bash
xdg-open artifacts/demo/reviewer-console.html
```

For interactive review, choose a fresh private state directory, run the demo,
and open `http://127.0.0.1:8088`:

```bash
export RUNWARDEN_STATE_DIR="$PWD/.runwarden-live"
target/debug/runwarden demo
```

In a second trusted terminal, copy the exact environment exports printed by
the demo, install the Runwarden-only OpenCode config as instructed, and launch
the agent. Treat `RUNWARDEN_INSTANCE_TOKEN` as a bearer secret and never put it
inside the agent configuration or prompt.

## Review Workflow

For a live review:

1. Open the loopback console using the exact host printed by the server.
2. Start one agent provider request. The original MCP call waits up to 120
   seconds by default while the native operation appears in Review Queue.
3. Inspect its Rust-produced policy checks, typed resource claim, safe argument
   projection, hashes, expiry, and entity versions.
4. Enter reviewer and reason, then approve or deny once. A stale version
   refreshes the card and requires a new click; the browser never retries a
   decision automatically.
5. On approval, observe the same operation move through lease, consumed,
   executing, and terminal events. Do not resend the provider call. Use status
   or resume by operation id only after a client disconnect.

For static review, open the generated HTML, inspect its scenario events and
adjacent reports, and follow cited `obs_*` references. Static mode has no
network requests or approval controls.

## Security Rules

- The browser may submit only the exact native reviewer decision through the
  nonce-, origin-, and version-protected Rust HTTP handler.
- High-risk review states come from Rust-produced demo JSON.
- `--output` must be a relative workspace path. Absolute paths, parent
  traversal, and symlink escapes are rejected before writing.
- The WebUI displays Rust-owned state; it must not reimplement provider,
  approval, egress, or report policy.
- A second demo cannot claim an already active state directory. This checkpoint
  has no unsafe PID/expiry takeover; select a fresh directory for a new run.

Maintained reference: [WebUI Review Console](../reference/webui-review-console.md).
Exact API contract: [Reviewer HTTP and SSE API](../reference/reviewer-http-sse-api.md).
