# MCP Reference

`runwarden-mcp` exposes only Runwarden tools to agents. It does not expose raw
shell, filesystem, browser, HTTP, or downstream MCP tools.

Default tools:

- `runwarden.agent.bootstrap`
- `runwarden.provider.list`
- `runwarden.provider.call`
- `runwarden.provider.status`
- `runwarden.session.create_from_manifest`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

MCP mapping rules:

- Protocol problems use JSON-RPC errors.
- Known-tool execution denials return a tool result with `isError: true`.
- Tool results include `content`, `structuredContent`, and `isError`.
- Every descriptor includes `inputSchema` and `outputSchema`.
- Denials include `side_effect_executed: false`.
- `runwarden.trace.verify` accepts inline `trace_events` and verifies the hash
  chain before report use.
- `runwarden.trace.export` accepts inline `trace_events`, provider/event/obs
  filters, offset/limit pagination, byte budgets, and optional compact obs refs.
- Stdio accepts `Content-Length` frames and EOF-terminated raw JSON payloads,
  including pretty-printed multiline JSON, up to 1 MiB.
- Framed stdio rejects `Content-Length` bodies above 1 MiB and headers above
  16 KiB before allocating the body.
- MCP helper encoders reject messages that do not serialize to JSON instead of
  emitting malformed frames.

Minimal flow:

```text
initialize
tools/list
tools/call runwarden.provider.list
tools/call runwarden.provider.call
tools/call runwarden.report.lint
tools/call runwarden.report.render
```

`runwarden.provider.call` supports inline safe providers such as
`runwarden.input.inspect`, `runwarden.audit.summary`,
`runwarden.accountability.summary`, and `runwarden.eval.agent-native`.
