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
- `GET /api/trace/verify` hash-chain verification for the LLM proxy trace and
  MCP provider-call trace from `.runwarden/events.jsonl`
- `GET /healthz`

MCP writes pending approval records and provider-call events under
`RUNWARDEN_STATE_DIR` when set, otherwise `.runwarden` under its current
directory. For the two-terminal demo, export `RUNWARDEN_STATE_DIR` to the repo
state directory before launching the agent.

The console polls pending approvals and trace verification while interactive,
so Evidence Chain updates after model or provider events are written.

### Native Reviewer JSON API

The same loopback-only Axum listener also exposes the story-native reviewer
read surface:

- `GET /api/bootstrap`
- `GET /api/stories`
- `GET /api/stories/{story_id}`
- `GET /api/stories/{story_id}/events?after_seq={sequence}`
- `GET /api/stories/{story_id}/operations/{operation_id}`
- `GET /api/stories/{story_id}/report`
- `GET /api/stories/{story_id}/evidence/verify`
- `POST /api/approvals/{approval_id}/decision`

Only the singleton active native story is readable. All responses are built
from `StateStore` display-safe snapshots; operation responses add the durable
approval version from the same verified read transaction for compare-and-swap,
but never expose private arguments or the complete approval binding. Readers
preserve the actual canonical major-1 story version; current Rust writers still
emit only `SchemaVersion::current()`. The evidence route performs only
`StoryEvidenceView::verify_structure` in this phase and labels its scope
`structural`; it does not perform report-semantic verification or change the
story evidence status.

At server construction Rust creates a 32-byte in-memory reviewer nonce. The
bootstrap response returns its URL-safe base64 encoding and the exact accepted
loopback origin, and carries `Cache-Control: no-store, no-cache,
must-revalidate, private`, `Pragma: no-cache`, and `Expires: 0`. The nonce is
not written to SQLite or static HTML and is invalid after restart.

The decision POST accepts the approval id only in the URL and the exact JSON
fields `decision`, `reviewer`, `reason`, `expected_approval_version`, and
`expected_operation_version`. It requires an exact `Origin` match and
`X-Runwarden-Reviewer-Nonce`; missing, foreign, `null`, malformed, duplicate,
and preflight requests fail closed without permissive CORS headers. The state
layer checks the active story, immutable binding, expiry, and both versions in
the same immediate SQLite transaction before it records an approve or deny
event. Approval does not execute or consume the operation; execution-start is
still the one-shot authorization boundary.

The dependency-free `console.html` continues to use the legacy polling routes
until the later live-console migration. Its file-backed approval records are
compatibility display state and cannot authorize a native operation.

## Static Mode

`runwarden demo --all --output artifacts/demo --json` writes
`artifacts/demo/reviewer-console.html` with scenario events embedded as JSON.
Only the five official scenario `webui.json` files generated for that run are
embedded; stale or example scenario outputs under the same directory are not
included. The static page does not submit approval decisions.

Each official scenario directory also receives a sibling `story.json`. It is
the Rust adapter's redacted `LegacyDerived` projection and remains
`EvidenceStatus::Incomplete`; the current static console continues to embed
the retained legacy `webui.json` until the story-native console migration.
To keep the generated story set exact, `--all` unlinks only direct
`story.json` file/symlink leaves in immediate ordinary nonofficial child
directories. It preserves those directories, all other files, nested stories,
and every child symlink directory without following it.

## Policy Boundary

The browser uses DOM text APIs and `fetch`; it must not reimplement allow,
deny, egress, provider, report, artifact, or trace verification policy.
Denied and review-blocked state comes from Rust-produced event JSON.
Defense-layer labels are produced by Rust event JSON (`defense_layer`) and the
browser displays them without reclassifying provider ids.
The browser does not convert legacy traces into native story events or mint
`obs_*` references; the Rust adapter owns the `story.json` projection.
