# Authority and Session

Sessions and approval records define the runtime policy envelope for provider calls.

## Sessions

Sessions are now internal to demo/check flows. A session derived from an
assessment manifest carries provider allowlist, scoped roots, budgets, actor
id, authz state, and active-assessment state used by `KernelEnforcer`.

The reviewer-facing `AuthoritySnapshot` preserves that boundary as typed Rust
data: provider, file, network, email, store, code, input, evidence, and artifact
authority are separate fields rather than caller-defined JSON. Native snapshot
views reject unknown fields. `max_argument_bytes` and `max_wall_time_ms` are
per-operation ceilings; call, file-byte, and network-byte budgets are cumulative
session counters; model call/input/output budgets are reserved separately by
the model proxy.

MCP callers do not create or mutate that envelope through tool arguments.
`runwarden-mcp` builds any inline kernel policy from server-owned defaults and
rejects agent-supplied session, assessment, authz, budget, root, and
approval-like fields such as `session_allowed_providers`, `active_assessment`,
`authz_grants`, `budget`, `budgets`, `root`, `root_path`, `sandbox_root`,
`authz_id`, and `approval_id`.

## Approval Records

Approval records bind a reviewer decision to one exact provider call:

- session id
- provider id
- action
- argument hash
- authz id
- actor id

High-risk provider calls consume matching approved records once. File-backed calls bind SHA-256 digests after kernel path policy allows the path and verify those digests again before approval consumption or execution.

`ApprovalState::Leased` is reserved for the durable execution-lease contract.
The legacy in-memory authority path does not acquire leases and rejects records
already in that state instead of consuming or executing them.

`ApprovalView` is a typed, display-safe projection carried by a
`SecurityOperation`. It can expose the typed approval and lease identifiers,
state, binding digest, reviewer metadata, and expiry, but it is not itself an
authorization input. Provider execution continues to consume the Rust-owned
approval record and lease contract.

Interactive approvals are file-backed. `runwarden demo` writes reviewer
decisions to `.runwarden/approvals`, while `runwarden-mcp` reads the same
directory via `RUNWARDEN_STATE_DIR` when the agent runs outside the repository
working directory.
