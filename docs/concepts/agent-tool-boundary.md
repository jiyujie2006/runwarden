# Agent Tool Boundary

Runwarden's central rule is:

> Agents receive Runwarden. They do not receive raw tools.

The agent-facing MCP server is `runwarden-mcp`. It exposes `runwarden.*` tools
that submit provider calls to kernel mediation. Raw shell, filesystem, browser,
HTTP, and downstream MCP servers stay behind provider manifests, allowlists,
approval records, and trace enforcement.

## Why This Boundary Exists

Direct tool exposure makes prompt injection and tool injection hard to audit.
If an agent can call raw tools, the runtime may not know:

- whether the call was inside the assessment scope
- whether the target path escaped a scoped root
- whether network egress went to a private or local address
- whether a reviewer approved a high-risk action
- whether a report claim cites evidence that supports it

Runwarden turns those questions into kernel decisions before side effects.

## Allowed Agent Shape

A safe agent config exposes exactly one MCP server named `runwarden`:

```json
{
  "mcpServers": {
    "runwarden": {
      "command": "runwarden-mcp",
      "args": []
    }
  }
}
```

Empty `args: []` is allowed. Non-empty or malformed args and any `env`, `cwd`,
`url`, or `transport` override are rejected because they can redirect execution
outside the kernel boundary.

## Verification

```bash
runwarden agent generate-config --client claude --output examples/agent-configs/claude.runwarden-only.json
runwarden agent check-config --client claude --input examples/agent-configs/claude.runwarden-only.json --json
runwarden eval agent-native --json
```

Maintained reference: [Agent Integration](../reference/agent-integration.md).
