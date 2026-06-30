# Agent Integration

Agents integrate by exposing only `runwarden-mcp`.

Raw filesystem, shell, browser, HTTP, and vendor MCP servers must not be visible directly to the agent. Those capabilities are modeled as Runwarden providers and mediated by Rust policy.

The contest edition removed agent-config generation/check commands from the CLI. Agent configuration remains a deployment concern: the safe shape is one MCP server named Runwarden whose command launches `runwarden-mcp`, without downstream server overrides.
The Rust MCP crate validates the checked-in safe and unsafe examples: empty
`args: []` is allowed, while non-empty or malformed `args` and any `env`,
`environment`, `cwd`, `url`, or `transport` override are rejected.

For OpenCode, the checked config must use `type: "local"`, `command:
["runwarden-mcp"]`, must not set `enabled: false`, and must include a top-level
`tools` object whose built-in tools are all set to `false`.

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

The OpenCode transcript fixture records the `tools/list` response from
`runwarden-mcp` and is validated by the MCP tests. It must contain only
`runwarden.*` tools and must not list raw shell, filesystem, browser, HTTP, or
downstream MCP tools.

Validation coverage:

```bash
cargo test -p runwarden-mcp --test e2e_agent_flow
```
