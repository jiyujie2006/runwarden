# Agent Integration

Agents integrate with Runwarden by exposing only the `runwarden-mcp` server. Raw filesystem, shell, browser, HTTP, and vendor MCP servers must not be visible directly to the agent.

Use:

```bash
runwarden agent generate-config --client claude --output claude.runwarden-only.json
runwarden agent check-config --client claude --input claude.runwarden-only.json --json
```

The generated configuration routes all tool requests through Runwarden provider mediation.

Safe agent configs must expose exactly one MCP server named `runwarden` whose
command is `runwarden-mcp`. The config checker rejects extra MCP servers and
also rejects `args`, `env`, `cwd`, `url`, or `transport` overrides on the
Runwarden entry because those fields can redirect the agent outside the kernel
boundary.

The TypeScript `RunwardenClient` accepts `launchToken` only for local API
origins (`localhost`, `.localhost`, `127.0.0.1`, or `::1`) unless
`allowRemoteLaunchToken` is explicitly set. Do not send launch tokens to remote
origins by default.
