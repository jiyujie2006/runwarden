# Authority and Session

Sessions and approval records define the runtime policy envelope for provider calls.

## Sessions

Sessions are now internal to demo/check flows. A session derived from an
assessment manifest carries provider allowlist, scoped roots, budgets, actor
id, authz state, and active-assessment state used by `KernelEnforcer`.

MCP callers do not create or mutate that envelope through tool arguments.
The launcher owns `RUNWARDEN_SESSION_ID` and `RUNWARDEN_ACTOR_ID`; when no
session is supplied, MCP creates one process-unique epoch instead of reusing a
global identity. The legacy `mcp-inline` identity is available only when set
explicitly.
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

Interactive approvals are file-backed inside the fresh run directory printed
by `runwarden demo`. A decision requires the reviewer capability from the
printed URL plus exact Host/Origin; the server fixes reviewer identity. The
record transition and sealed `approval-events.jsonl` append share a durable
review lock with MCP. Before a claim, MCP verifies the approval hash chain and
the canonical record/binding digests, then atomically creates a one-use claim,
marks the record consumed, and reserves execution. Editing a Pending JSON file
to Approved is insufficient.
