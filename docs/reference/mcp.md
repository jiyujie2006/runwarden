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
`runwarden.provider.list` and `runwarden.provider.status` report the full
Runwarden-managed provider catalog, including external provider families such as
`external.shell.command`; those external capabilities are still invoked only via
Runwarden provider calls, not exposed as raw MCP tools.
Provider execution is submitted to the Runwarden platform executor with an
inline session manifest derived from `session_allowed_providers`,
`active_assessment`, actor, and authz arguments. The MCP boundary formats
successful provider output back into the existing tool payload shape and formats
kernel denials as tool results with `isError: true`.

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

Dedicated `runwarden.trace.export`, `runwarden.report.lint`, and
`runwarden.report.render` tool calls use the same platform executor path as
generic provider calls. `runwarden.trace.export` still rejects tampered inline
trace events before exporting and before returning any event page. Approved
trace export calls preserve the platform executor's page contract, including
offset, limit, total matching count, next offset, byte truncation metadata, and
compact obs refs derived from the returned page.

Approval-required dedicated tools return a normal MCP tool result with
`isError: true` before approval. The payload is the platform `ProviderOutcome`
and includes `decision: "requires_review"`, `envelope.approval_id`, and
`next_actions: ["review_approval"]`. After the matching approval is recorded,
`runwarden.trace.export` returns `exported`, `verified`, `compact_refs`,
`side_effect_executed`, and `page` with `offset`, `limit`, `total_matching`,
`next_offset`, `truncated_by_bytes`, and `events`.

## Stdio Framing

Stdio accepts `Content-Length` frames and EOF-terminated raw JSON payloads,
including pretty-printed multiline JSON.

Limits:

- Raw JSON payloads are bounded to 1 MiB.
- Framed bodies above 1 MiB are rejected.
- Oversized headers are rejected before allocating the body.
- MCP helper encoders reject messages that do not serialize to JSON instead of
  emitting malformed frames.
- Handler-generated MCP platform roots are removed after request handling.
  Explicit platform roots passed by embedding tests or callers are not cleaned
  up by `runwarden-mcp`.

## External MCP Egress

External MCP HTTP/SSE adapter calls reject private, local, link-local,
carrier-grade NAT, unique-local, unspecified, and IPv4-mapped local addresses
before connecting, including when the URL contains the IP literal directly.
