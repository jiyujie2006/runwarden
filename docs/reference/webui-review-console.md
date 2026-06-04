# WebUI Review Console

The Reviewer Console is a dependency-free static workbench for approval review,
trace status, provider state, reports, artifacts, and assurance results. It
displays Rust-owned state and submits decisions to the Local API.

## UI Contract

The UI requires:

- Responsive desktop and mobile layout.
- Persistent Runwarden section rail with brand marker and command bar.
- Mobile sticky top navigation that does not overlay review content.
- Module headers with state badges for empty, partial, success, loading, and
  error states.
- Visible details drawer for high-risk approvals.
- Keyboard-focusable approval rows inside a `role="list"` queue.
- `aria-current` and `aria-controls="approval-details"` on selected approval
  rows.
- Reviewer reason before approve or deny.
- Minimum 44 px action targets.
- Keyboard focus styling.
- No inline script execution in the TypeScript package renderer.
- HTML escaping for dynamic approval and bind text.
- Relative workspace artifact paths only.

## Policy Boundary

Module state classes, risk chips, command-bar labels, and pending counts are
presentation of Rust-owned state only. WebUI code must not reimplement allow,
deny, approval, provider, report, artifact, or egress policy in TypeScript.

The TypeScript renderer emits static HTML without a script tag. The Rust CLI/API
launch bundle may add `data-local-api-url` and defer-load
`reviewer-console.js` so browser forms can call Rust approval endpoints.

## Launch Bundle

Run:

```bash
runwarden ui --bind 127.0.0.1 --port 8088 --artifacts artifacts --json
```

Generated `launch_url` values point at `reviewer-console.html`. Windows launch
URLs use browser-openable `file:///C:/...` paths rather than canonical `\\?\`
paths. `local_api_url` reports the configured API origin separately.

Pending approvals are rendered with provider, action, actor, authz, argument
hash, risk chip, pending count, reviewer controls, and escaped detail
attributes. When the Local API is running and the reviewer supplies the launch
token, approval forms submit approve or deny decisions to
`/approvals/{id}/{decision}` with JSON reviewer and reason payloads.

Reports, artifact manifests, and assurance result files already present under
the artifact root are summarized in their workbench modules.
