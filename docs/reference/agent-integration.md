# Agent Integration

Agents integrate by exposing only `runwarden-mcp`.

Raw filesystem, shell, browser, HTTP, and vendor MCP servers must not be visible directly to the agent. Those capabilities are modeled as Runwarden providers and mediated by Rust policy.

The contest edition removed agent-config generation/check commands from the CLI. Agent configuration remains a deployment concern: the safe shape is one MCP server named Runwarden whose command launches `runwarden-mcp`, without downstream server overrides.
