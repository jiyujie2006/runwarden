# MCP Reference

`runwarden-mcp` is the only MCP server agents should see. It does not expose raw
shell, filesystem, browser, HTTP, or downstream MCP tools.

## Tools

- `runwarden.agent.bootstrap`
- `runwarden.provider.list`
- `runwarden.provider.call`
- `runwarden.provider.status`
- `runwarden.session.create_from_manifest`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

Unknown tools are rejected by the Runwarden MCP boundary.

## Minimal Agent Flow

```text
initialize
tools/list
tools/call runwarden.agent.bootstrap
tools/call runwarden.provider.list
tools/call runwarden.provider.call
tools/call runwarden.trace.verify
tools/call runwarden.trace.export
tools/call runwarden.report.lint
tools/call runwarden.report.render
```

`runwarden.provider.call` supports inline safe providers such as
`runwarden.input.inspect`, `runwarden.audit.summary`,
`runwarden.accountability.summary`, and `runwarden.eval.agent-native`.

## JSON-RPC and Tool Result Semantics

- Protocol problems use JSON-RPC errors.
- Known-tool execution denials return a tool result with `isError: true`.
- Tool results include `content`, `structuredContent`, and `isError`.
- Every tool descriptor includes `inputSchema` and `outputSchema`.
- Denials include `side_effect_executed: false`.

## Trace and Report Tools

- `runwarden.trace.verify` accepts inline `trace_events` and verifies the hash
  chain before report use.
- `runwarden.trace.export` accepts inline `trace_events`, provider/event/obs
  filters, offset/limit pagination, byte budgets, and optional compact obs refs.
- `runwarden.report.lint` checks claim citations against verified observation
  references.
- `runwarden.report.render` renders only cited reports.

## Stdio Framing

Stdio accepts `Content-Length` frames and EOF-terminated raw JSON payloads,
including pretty-printed multiline JSON.

Limits:

- Raw JSON payloads are bounded to 1 MiB.
- Framed bodies above 1 MiB are rejected.
- Oversized headers are rejected before allocating the body.
- MCP helper encoders reject messages that do not serialize to JSON instead of
  emitting malformed frames.

## External MCP Egress

External MCP HTTP/SSE adapter calls reject private, local, link-local,
carrier-grade NAT, unique-local, unspecified, and IPv4-mapped local addresses
before connecting, including when the URL contains the IP literal directly.
