# WebUI Review Console

The contest WebUI is served by `runwarden demo` from Rust (`axum`) and uses a
single dependency-free `console.html`. It is presentation and approval
delivery only; policy decisions stay in Rust kernel/MCP/provider code.

## Interactive Mode

`runwarden demo` serves:

- `GET /` console HTML
- `GET /events` Server-Sent Events for `model_call`, `provider_call`, and approval updates
- `GET /api/pending` pending approval records from the active run-scoped
  `approvals/` directory
- `POST /api/approvals/{approval_id}/decision` performs an authenticated,
  auditable state transition for one existing pending record
- `GET /api/trace/verify` hash-chain verification for the LLM proxy trace and
  MCP provider-call trace from the active run state directory
- `GET /healthz`

Every interactive demo creates a fresh `.runwarden/runs/demo-*` state
directory. Copy the printed `RUNWARDEN_STATE_DIR`, `RUNWARDEN_SESSION_ID`, and
actor setup into the agent terminal so retries bind to the same run and
identity.

The decision POST requires the 256-bit reviewer capability delivered only in
the fragment of the printed `Reviewer:` URL, plus exact `Host` and `Origin`.
The fragment is removed from browser history after being placed in
`sessionStorage`; it is not embedded in the ordinary HTML response. Reviewer
identity is fixed by the Rust server session, not accepted from JSON. The
review transaction holds the same cross-process lock used by MCP, atomically
persists the record, and appends a sealed `approval-events.jsonl` decision. MCP
will not claim an approved record unless that audit event and its canonical
record/binding digests verify.

SSE payloads are update hints only: the browser never renders them as evidence.
On an SSE notification it fetches `/api/console/snapshot` again, so trace,
report, approval-ledger, and approval-audit status comes from server-side
recomputation. A 30-second reconciliation and visibility-change refresh cover
missed notifications.

## Static Mode

`runwarden demo --all --output artifacts/demo --json` writes
`artifacts/demo/reviewer-console.html` with scenario events embedded as JSON.
Only the five official scenario `webui.json` files generated for that run are
embedded; stale or example scenario outputs under the same directory are not
included. The static page does not submit approval decisions.

## Policy Boundary

The browser uses DOM text APIs and `fetch`; it must not reimplement allow,
deny, egress, provider, report, artifact, or trace verification policy.
Denied and review-blocked state comes from Rust-produced event JSON.
Defense-layer labels are produced by Rust event JSON (`defense_layer`) and the
browser displays them without reclassifying provider ids.
