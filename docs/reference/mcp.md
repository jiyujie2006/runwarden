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
- MCP arguments are provider inputs, not a session or approval policy envelope.
  Callers cannot supply session policy, assessment, authz, budget, roots, or
  approval-like fields through MCP arguments. Rejected keys include
  `session_id`, `actor_id`, `authz_id`, `approval_id`, `active_assessment`,
  `session_allowed_providers`, `session_roots`, `authz_grants`, `budget`,
  `budgets`, `root`, `root_path`, `sandbox_root`, and self-approval fields.
- Denials include `side_effect_executed: false`.
- `runwarden.provider.call` implements `runwarden.input.inspect` and external
  provider ids. First-party trace and report provider ids are listed for
  registry/status metadata and exposed through dedicated MCP tools, not as
  generic `provider.call` inline execution targets.
- `runwarden.provider.list` and `runwarden.provider.status` include both
  first-party Runwarden providers and the external provider catalog. External
  tools are never exposed as MCP tools; they remain provider ids behind
  `runwarden.provider.call`.
- External provider calls are mediated by the Rust kernel. MCP callers cannot
  provide `simulated_approval` or any other self-approval field. The MCP
  server constructs the conservative inline kernel policy itself: active
  assessment is server-owned, provider ids come from the Rust catalog, the
  sandbox root comes from Runwarden runtime configuration, public egress hosts
  come from external provider manifests, and argument bytes are capped before
  side effects. MCP does not derive provider allowlists, active-assessment
  state, roots, authz, approvals, or budgets from agent-supplied arguments.
- For review-blocked calls, MCP writes a pending approval record and a
  provider-call event under `RUNWARDEN_STATE_DIR` when set, otherwise
  `.runwarden` under the MCP process working directory. On retry, MCP loads
  matching approved records from `.runwarden/approvals`, attaches the approval
  id before kernel evaluation, and persists the consumed state after allow.
  Denied approval records do not allow the call.
- Allowed API and browser outcomes
  are replay-simulated and return `event_type=provider_simulated_replay`,
  `execution_status=simulated`, `simulated=true`, and
  `side_effect_executed=false`. Allowed local sandbox filesystem, email,
  memory, and knowledge providers report truthful local execution status and
  side-effect flags after kernel policy permits them. Denied and
  review-blocked calls always return `side_effect_executed=false`.
- Provider-call results include `obs_ref` plus a sealed `trace_event` payload
  whose `obs_id` starts with `obs_*`. Provider-call events appended to
  `.runwarden/events.jsonl` chain each `trace_event.previous_hash` to the prior
  provider event hash so the WebUI can verify the provider-call trace.
- Allowed external provider-call results include `anomaly: { score,
  is_anomalous, reasons }`, produced by `runwarden-anomaly` from provider
  sequence, argument size, and URL host. This is evidence metadata only; it
  does not change allow, deny, or approval policy.

## Trace And Report Tools

`runwarden.trace.verify` accepts inline `trace_events` and returns verification
status without side effects. `runwarden.trace.export` verifies inline trace
events before policy evaluation and supports `offset`, `limit`, `provider`,
`event_type`, `obs_prefix`, `max_bytes`, and `compact_refs`.
`runwarden.report.lint` accepts a `report` and enforces citation support only
against the server-owned MCP provider-call trace store at
`RUNWARDEN_STATE_DIR/events.jsonl` when that environment variable is set, or
`.runwarden/events.jsonl` relative to the MCP process otherwise. It ignores
agent-supplied inline `trace_events` for report evidence.
`runwarden.report.render` is review-blocked in the MCP inline path before
rendering; agents should use lint through MCP and a reviewer-approved non-agent
path for rendering.
