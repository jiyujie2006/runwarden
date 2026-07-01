# WebUI Review Console

The contest WebUI is served by `runwarden demo` from Rust (`axum`) and uses a
single dependency-free `console.html`. It is presentation and approval
delivery only; policy decisions stay in Rust kernel/MCP/provider code.

## Interactive Mode

`runwarden demo` serves:

- `GET /` console HTML
- `GET /events` Server-Sent Events for `model_call`, `provider_call`, and approval updates
- `GET /api/pending` pending approval records from `.runwarden/approvals`
- `POST /api/approve` and `POST /api/deny` state changes for existing approval records
- `GET /api/trace/verify` hash-chain verification for the LLM proxy trace
- `GET /healthz`

MCP writes pending approval records and provider-call events under
`RUNWARDEN_STATE_DIR` when set, otherwise `.runwarden` under its current
directory. For the two-terminal demo, export `RUNWARDEN_STATE_DIR` to the repo
state directory before launching the agent.

## Static Mode

`runwarden demo --all --output artifacts/demo --json` writes
`artifacts/demo/reviewer-console.html` with scenario events embedded as JSON.
The static page does not submit approval decisions.

## Policy Boundary

The browser uses DOM text APIs and `fetch`; it must not reimplement allow,
deny, egress, provider, report, artifact, or trace verification policy.
Denied and review-blocked state comes from Rust-produced event JSON.
