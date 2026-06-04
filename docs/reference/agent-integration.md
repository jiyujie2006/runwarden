# Agent Integration

Agents integrate with Runwarden by exposing only the `runwarden-mcp` server.
Raw filesystem, shell, browser, HTTP, and vendor MCP servers must not be visible
directly to the agent.

## Generate and Check Config

```bash
runwarden agent generate-config --client claude --output claude.runwarden-only.json
runwarden agent check-config --client claude --input claude.runwarden-only.json --json
```

Safe configs expose exactly one MCP server named `runwarden` whose command is
`runwarden-mcp`. Empty `args: []` is allowed for clients that require an
explicit argument array.

The config checker rejects:

- extra MCP servers
- non-empty or malformed `args`
- `env`
- `cwd`
- `url`
- `transport`

Those fields can redirect the agent outside the kernel boundary.

## Rust Owns Policy

`runwarden agent check-config` and `runwarden cert agent-config` both use the
Rust assurance `certify_agent_config` implementation for the allow/deny
decision. CLI output may format the result, but it must not maintain a separate
agent-config policy.

TypeScript config helpers are non-authoritative. `@runwarden/config-tools` may
build the `runwarden cert agent-config <path> --json` command and summarize the
Rust certifier report, but it must not accept a raw agent config and make its
own safe/unsafe decision.

## SDK Token Rules

The TypeScript `RunwardenClient` accepts `launchToken` only for local API
origins (`localhost`, `.localhost`, `127.0.0.1`, or `::1`) unless
`allowRemoteLaunchToken` is explicitly set.

Generated Reviewer Console files may call the Local API from a `file://` browser
origin. Local API control-plane routes still require the launch token plus the
allowed Host check before any approval mutation or trusted side effect.
