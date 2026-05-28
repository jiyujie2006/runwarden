# Agent Integration

Agents integrate with Runwarden by exposing only the `runwarden-mcp` server. Raw filesystem, shell, browser, HTTP, and vendor MCP servers must not be visible directly to the agent.

Use:

```bash
runwarden agent generate-config --client claude --output claude.runwarden-only.json
runwarden agent check-config --client claude --input claude.runwarden-only.json --json
```

The generated configuration routes all tool requests through Runwarden provider mediation.
