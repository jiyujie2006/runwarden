# Agent Integration

Agents integrate by exposing only `runwarden-mcp`.

Raw filesystem, shell, browser, HTTP, and vendor MCP servers must not be visible directly to the agent. Those capabilities are modeled as Runwarden providers and mediated by Rust policy.

The contest edition removed agent-config generation/check commands from the CLI. Agent configuration remains a deployment concern: the safe shape is one MCP server named Runwarden whose command launches `runwarden-mcp`, without downstream server overrides.
The Rust MCP crate validates the checked-in safe and unsafe examples: empty
`args: []` is allowed, while non-empty or malformed `args` and any `env`,
`environment`, `cwd`, `url`, or `transport` override are rejected.

For OpenCode, the checked config must use `type: "local"`, `command:
["runwarden-mcp"]`, must not set `enabled: false`, and must include a top-level
`tools` object that explicitly sets every pinned OpenCode 1.17.13 built-in tool
to `false`. A partial map such as only `{"bash": false}` is rejected; upgrading
the pinned OpenCode version requires reviewing this deny set.
The checked config also defines `runwarden-proxy/big-pickle` as the
OpenAI-compatible model entry that routes model calls through the local LLM
proxy at `http://127.0.0.1:8787/v1`. Interactive startup pre-binds that fixed
loopback port before it activates a durable demo or prints trusted launcher
values. If another process owns the port, startup fails closed instead of
directing model traffic to that process.

The reserved listener does not accept model requests until the embedded proxy
has initialized its journal sink against the exact active story, session, and
instance-token hash. A standalone proxy validates the same trusted inherited
context before binding. The launcher canonicalizes the configured LLM upstream
origin and freezes it into the session's provider-specific network authority;
neither an agent request nor agent configuration can replace that origin,
state directory, token, or model budget.

For every accepted model call, the proxy commits the active-context, origin,
input-filter, and model call/input-byte budget transition to SQLite before any
upstream connection. It commits the response/filter and output-byte evidence
before releasing response bytes. A journal failure before forwarding reaches
no upstream; a failure after upstream contact withholds the completion, marks
evidence invalid when possible, and returns `503`. Raw prompts, completions,
filter evidence, tool arguments, API keys, and instance tokens are not written
to the story journal or a parallel live JSONL trace.

OpenCode also reads user-level configuration. For a strict Runwarden-only demo,
run OpenCode with clean `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`,
and `XDG_STATE_HOME` directories, place the Runwarden config at
`$XDG_CONFIG_HOME/opencode/opencode.json`, and verify `opencode debug config
--pure` resolves exactly one MCP entry: `runwarden`.

Agent configuration arguments and MCP tool arguments do not carry Runwarden
session policy. Agents cannot provide provider allowlists, active-assessment
state, scoped roots, authz grants or ids, budgets, approval ids, or
self-approval fields through MCP. Rejected MCP argument names include `root`,
`root_path`, and `sandbox_root`; those values are owned by Runwarden's Rust
authority/session path and runtime configuration, not agent-controlled JSON.

Checked-in examples:

- `examples/agent-configs/claude.runwarden-only.json`
- `examples/agent-configs/opencode.runwarden-only.json`
- `examples/agent-configs/opencode.tools-list-transcript.json`
- `examples/agent-configs/opencode.provider-call-denied-transcript.json`

The OpenCode transcript fixture records the `tools/list` response from
`runwarden-mcp` and is validated by the MCP tests. It must contain only
`runwarden.*` tools and must not list raw shell, filesystem, browser, HTTP, or
downstream MCP tools.

The denied provider-call transcript records OpenCode asking
`runwarden.provider.call` to invoke `external.mcp.filesystem.read_file` on a
path traversal target. MCP obtains the action from the Rust catalog rather than
accepting it from the agent. The typed resource extractor rejects the path
before creating an operation, returning `error_kind=resource_invalid` and
`side_effect_executed=false` without echoing the private path.

Validation coverage:

```bash
cargo test -p runwarden-mcp --test e2e_agent_flow
```
