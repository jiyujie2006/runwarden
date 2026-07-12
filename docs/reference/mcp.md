# MCP Reference

`runwarden-mcp` is the only MCP server agents should see. It does not expose
raw shell, filesystem, browser, HTTP, or downstream MCP tools.

## Tools

- `runwarden.agent.bootstrap`
- `runwarden.provider.list`
- `runwarden.provider.status`
- `runwarden.provider.call`
- `runwarden.operation.status`
- `runwarden.operation.resume`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

Unknown tools, raw tools, and removed tools such as
`runwarden.session.create_from_manifest` are rejected without side effects.
External capabilities remain provider ids behind `runwarden.provider.call`;
they are never exposed as raw MCP tools.

## Production Runtime Binding

Production `runwarden-mcp` requires `RUNWARDEN_STATE_DIR` and
`RUNWARDEN_INSTANCE_TOKEN` from the trusted launcher. At startup it opens the
native SQLite journal, loads exactly one active native story/session/authority,
validates the instance-token hash and lifetime, generates one permit authority,
and constructs one `OperationRuntime` plus `DefaultProviderExecutor`. The
runtime's copy of the raw token is moved into zeroizing invocation-key material;
the trusted launcher remains responsible for the inherited process environment.
The token is not serialized into MCP responses, story snapshots, or events.

`RUNWARDEN_SANDBOX_ROOT`, `RUNWARDEN_TRUSTED_RUNTIME_ROOT`, and the optional
bounded `RUNWARDEN_MCP_APPROVAL_WAIT_MS` are trusted process configuration.
They are not MCP arguments. Runwarden-only agent configs reject `env`, `cwd`,
`url`, `transport`, non-empty or malformed `args`, and any additional MCP
server. The pinned OpenCode config explicitly disables every built-in tool in
the OpenCode 1.17.13 set.

The public `handle_jsonrpc_body` helper is for protocol tests only. Each call
creates a throwaway native story, session, SQLite journal, sandbox, and executor
under an isolated temporary directory. Production never uses that helper.

## Protocol And Invocation Identity

- Both `Content-Length` framing and one-JSON-value-per-line NDJSON are accepted.
- Malformed JSON returns JSON-RPC `-32700` with `id: null`; it does not terminate
  the stdio server or consume subsequent NDJSON requests.
- A side-effecting request id must be a string of at most 1024 bytes or an
  integer in the interoperable JSON range. Null, float, boolean, array, object,
  and out-of-range ids cannot invoke a tool. Notifications never invoke tools.
- Protocol failures use JSON-RPC errors. Known-tool policy/runtime failures use
  MCP tool results with `isError: true`.
- The invocation key is HMAC-SHA-256 over Canonical JSON v1 containing schema
  version, active instance id, normalized JSON-RPC request id, and tool name.
  Arguments are intentionally excluded: retrying the same request id with
  changed arguments reaches the journal binding conflict instead of creating a
  second operation.
- Within one active instance, clients must use a request id only once except
  for a byte-identical retransmission of the same logical tool call. A client
  restart must preserve or namespace its id sequence. Reusing an id with the
  same arguments intentionally returns the earlier operation, because the
  server cannot distinguish a lost-response retry from a new logical call.
- A JSON-RPC correlation id is not model evidence and is never copied into
  `parent_model_call_id` or `proposed_tool_call_id`. Plan 5 supplies those links
  from trusted proxy evidence.

## Durable Provider Calls

`runwarden.provider.call` accepts a flat, strict provider-argument object. MCP
removes `provider`, obtains the canonical action from the Rust provider catalog,
and delegates to the runtime. Callers cannot provide action, session, policy,
assessment, authz, approval, budget, root, classification, lease, permit,
transport, environment, or runtime controls.

The runtime performs catalog lookup, typed claim extraction, redaction and
argument commitment, durable operation creation, Rust policy evaluation,
durable policy/approval writes, one-shot lease acquisition, durable
execution-start, permit sealing, provider execution, and conservative result
persistence. A journal failure before execution-start prevents the executor
call. A failure after execution-start is never serialized as completed; it is
reported for reconciliation or as `outcome_unknown`.

The durable generic call surface currently admits bounded input inspection and
the native local filesystem, email, memory, and knowledge providers. API and
browser providers remain catalogued for metadata and later scenarios, but are
reported unavailable on this enforced call surface because their current
executor implementations are simulation-only. External MCP transports remain
quarantined by the provider-adapter rules.

## Approval, Status, And Resume

Review-required calls create one native SQLite approval bound to one immutable
operation. The default MCP wait is 120 seconds with 100 ms journal polling; a
trusted launcher may shorten it, including to zero for tests. Timeout returns
the same operation as `awaiting_approval` and never creates a replacement.

`runwarden.operation.status` and `runwarden.operation.resume` accept exactly
one `operation_id`. They reject replacement provider arguments, approval ids,
sessions, roots, environment, URLs, and transports. Status returns a
display-safe snapshot. Resume loads the frozen private request from SQLite and
can continue only an approved, allowed-policy, or unstarted leased operation.
Executing, terminal, and uncertain operations are never retried.

MCP no longer reads or writes `.runwarden/approvals`, does not create the fixed
`mcp-inline` session, and does not append legacy provider-call authority events.
Legacy approval JSON cannot authorize a native lease or provider execution.
The loopback nonce/origin/version-protected reviewer API can decide the native
approval through the journal's active-story CAS. The dependency-free legacy
console is not yet wired to that API, and its file-backed buttons remain
non-authoritative compatibility behavior.

## Trace And Report Compatibility Tools

`runwarden.trace.verify` verifies an inline trace hash chain without side
effects. `runwarden.trace.export` verifies before returning a filtered,
size-bounded in-memory page; it does not write an artifact.

`runwarden.report.lint` currently reads the old `events.jsonl` provider trace as
a read-only compatibility evidence source. It ignores and rejects agent-supplied
inline trace material for report support. This file is not runtime authority and
cannot approve, lease, resume, or execute an operation. Plan 6 replaces this
compatibility evidence path with story-native semantic verification.

`runwarden.report.render` remains disabled to agents and returns
`reviewer_artifact_route_required`. Rendering and artifact paths stay behind a
reviewer-controlled, workspace-relative output boundary.
