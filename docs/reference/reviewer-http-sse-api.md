# Reviewer HTTP and SSE API

The reviewer API is a loopback-only Rust `axum` surface over the native SQLite
story journal. It presents verified, display-safe state and accepts one
version-bound human decision. It never evaluates provider policy in the
browser and never executes a provider from an HTTP handler.

## Startup and trust boundary

`runwarden demo` creates one Native, Live, Enforced story and session, then
claims the state directory's singleton active instance. A second demo using
the same directory fails with an active-demo conflict. This checkpoint has no
token-CAS shutdown or takeover operation, so use a fresh
`RUNWARDEN_STATE_DIR` for a later live launch.

The trusted launcher generates a 32-byte random instance token. SQLite stores
only its SHA-256 digest. Normal startup output prints shell exports and
`--json` returns them under `trusted_mcp_environment` so a trusted harness can
start OpenCode/MCP with the exact state, token, sandbox, and runtime roots.
Treat that output as a bearer secret: do not persist it in agent configuration,
story data, events, reports, browser storage, or logs. Runwarden-only agent
configuration continues to reject `env`; the trusted parent environment owns
these values.

The server refuses non-loopback listeners. At server construction it also
generates an independent 32-byte reviewer nonce held only in memory. Restarting
the server invalidates the old reviewer nonce. The reviewer listener, reviewer
state, and fixed loopback LLM proxy listener are prepared before durable demo
activation. If either port is occupied or reviewer setup fails, no active
instance is committed and no trusted token or OpenCode instructions are
printed.

## Read routes

All supported routes return JSON except the SSE stream and console HTML:

- `GET /` — dependency-free reviewer console.
- `GET /healthz` — `{ "ok": true }` liveness response.
- `GET /api/bootstrap` — active story evidence, reviewer nonce, and accepted
  origin.
- `GET /api/stories` — zero or one active display-safe native story.
- `GET /api/stories/{story_id}` — active story snapshot.
- `GET /api/stories/{story_id}/events?after_seq={sequence}` — at most 256
  verified events strictly after the sequence.
- `GET /api/stories/{story_id}/operations/{operation_id}` — display-safe
  operation plus `approval_version` from the same verified read transaction.
- `GET /api/stories/{story_id}/report` — current Rust-owned report claims.
- `GET /api/stories/{story_id}/evidence/verify` — structural verification only.

`GET /api/bootstrap` returns:

```json
{
  "schema_version": "1.0.0",
  "mode": "live",
  "active_story_id": "UUIDv7",
  "reviewer_nonce": "URL-safe base64 without padding",
  "accepted_origin": "http://127.0.0.1:8088",
  "evidence": {
    "story": {},
    "events": [],
    "replay_frames": []
  }
}
```

Bootstrap carries `Cache-Control: no-store, no-cache, must-revalidate,
private`, `Pragma: no-cache`, and `Expires: 0`. Only the singleton active
Native story with active, unexpired authority is readable. Unknown and
same-database nonactive story identifiers are hidden as not found. Operation
responses never include private arguments or the complete approval binding.
The evidence verification response labels its scope `structural`; it does not
claim report-semantic verification or mutate evidence status.

The console HTML is also non-cacheable and carries both
`Content-Security-Policy: frame-ancestors 'none'` and
`X-Frame-Options: DENY`, plus a restrictive inline-only policy. A foreign page
therefore cannot frame the loopback reviewer controls for clickjacking.

## Reviewer decision

The only supported write is:

```text
POST /api/approvals/{approval_id}/decision
Origin: <exact accepted_origin>
X-Runwarden-Reviewer-Nonce: <reviewer_nonce>
Content-Type: application/json
```

Its exact body is:

```json
{
  "decision": "approve",
  "reviewer": "local-reviewer",
  "reason": "Reviewed the exact frozen Runwarden operation",
  "expected_approval_version": 0,
  "expected_operation_version": 2
}
```

`decision` is `approve` or `deny`. `reviewer` and `reason` must be nonempty
after trimming and are bounded to 256 and 4096 bytes respectively. The request
body is limited to 16 KiB. Unknown, missing, duplicate, or replacement fields
are rejected. The approval identifier appears only in the URL; callers cannot
supply operation arguments, binding material, authority, policy, environment,
root, or transport controls.

The request requires exactly one byte-for-byte matching `Origin` and reviewer
nonce header. Missing, foreign, malformed, duplicate, `null`, and preflight
requests fail closed without permissive CORS response headers. Browser code
uses a relative same-origin URL and lets the browser supply `Origin`; it does
not send the accepted origin as a destination.

The state layer rechecks the singleton active story, immutable approval
binding, authority and approval expiry, plus both compare-and-swap versions in
one immediate SQLite transaction. Approval commits `Pending -> Approved` and
`AwaitingApproval -> Approved`; denial commits the two corresponding terminal
states. The response contains the updated ids, states, versions, and
side-effect state from that transaction.

An HTTP approval does not acquire an execution lease, consume the approval, or
invoke a provider. The already waiting original MCP call observes the committed
decision, acquires the one-shot lease, and consumes approval only when the
separate execution-start transaction commits. No second provider call is
required. A stale version returns conflict; the browser refreshes and requires
a new click rather than automatically replaying a write. A lost HTTP response
is treated as unknown by the UI until state is re-read.

## Resumable SSE

Connect with:

```text
GET /events?story_id={story_id}&after_seq={sequence}
Accept: text/event-stream
Last-Event-ID: {previous committed sequence}
```

`story_id` is required and `after_seq` defaults to zero. One valid decimal
`Last-Event-ID` takes precedence over the query cursor. Malformed or duplicate
headers and malformed/unknown query fields return a JSON `422` before the
stream begins.

SQLite is the source of truth. The server reads verified events in pages of at
most 256, polls every 100 ms when caught up, and sends a keepalive comment every
15 seconds. Each event is:

```text
id: <committed story sequence>
event: story_event
data: <complete display-safe StoryEvent JSON>
```

Dropping the response stops its producer. A one-slot channel applies
backpressure so the server does not prefetch another page for a slow client.
One serialized SSE event may be at most 256 KiB. An oversized verified event is
not truncated and does not advance the cursor: the server logs only safe ids
and byte counts, closes the stream, and leaves the event available through the
paginated JSON events route.

The browser bootstraps committed evidence first, then opens SSE after the last
seen sequence. Browser reconnection supplies `Last-Event-ID`, closing both the
disconnect gap and the bootstrap-to-stream race. The console deduplicates
sequences, displays exact Rust event fields, and refreshes affected operation
snapshots; it does not infer allow, deny, approval, or side-effect policy.

## Errors and outcome semantics

JSON errors use a bounded envelope:

```json
{"error":{"code":"stable_code","message":"bounded public message"}}
```

- `403` — origin, nonce, or preflight rejected.
- `404` — malformed, unknown, or cross-story entity hidden.
- `409` — inactive/expired reviewer context or version/state conflict.
- `422` — malformed query or decision body.
- `500` — verified state integrity failure.
- `503` — state storage unavailable.

Journal details and private provider input are never included. Provider
completion is reported only after its terminal journal commit. Once execution
has started, an unprovable result becomes `outcome_unknown`; neither HTTP,
SSE, status, nor resume silently repeats the side effect.
