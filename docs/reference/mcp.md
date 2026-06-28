# MCP Reference

`runwarden-mcp` is the only MCP server agents should see. It does not expose raw shell, filesystem, browser, HTTP, or downstream MCP tools.

## Tools

- `runwarden.agent.bootstrap`
- `runwarden.provider.list`
- `runwarden.provider.status`
- `runwarden.provider.call`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

Unknown tools, raw tools, and removed tools such as `runwarden.session.create_from_manifest` are rejected without side effects.

## Semantics

- Protocol problems use JSON-RPC errors.
- Known-tool policy denials return MCP tool results with `isError: true`.
- Tool descriptors include input and output schemas.
- Denials include `side_effect_executed: false`.

## Trace And Report Tools

`runwarden.trace.verify` and `runwarden.trace.export` accept inline trace events and verify hash-chain integrity before returning evidence. `runwarden.report.lint` and `runwarden.report.render` accept inline report and trace payloads; render is blocked unless cited observations support the claims.
