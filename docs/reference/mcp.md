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
- `runwarden.provider.call`, `runwarden.provider.list`, and
  `runwarden.provider.status` declare strict argument schemas for their
  top-level keys.
- Denials include `side_effect_executed: false`.
- `runwarden.provider.list` and `runwarden.provider.status` include both
  first-party Runwarden providers and the external provider catalog. External
  tools are never exposed as MCP tools; they remain provider ids behind
  `runwarden.provider.call`.
- External provider calls are mediated by the Rust kernel. MCP callers cannot
  provide `simulated_approval` or any other self-approval field. Allowed
  external outcomes are simulated replay results only and return
  `event_type=provider_simulated_replay`, `execution_status=simulated`,
  `simulated=true`, and `side_effect_executed=false`; denied and
  review-blocked calls also return `side_effect_executed=false`.
- Provider-call results include `obs_ref` plus a sealed `trace_event` payload
  whose `obs_id` starts with `obs_*`.

## Trace And Report Tools

`runwarden.trace.verify` and `runwarden.trace.export` accept inline trace events and verify hash-chain integrity before returning evidence. `runwarden.report.lint` and `runwarden.report.render` accept inline report and trace payloads; render is blocked unless cited observations support the claims.
