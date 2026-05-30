# WebUI Review Console

The Reviewer Console is a dependency-free static workbench for approval review, trace status, provider state, reports, artifacts, and assurance results.

The UI contract requires:

- responsive desktop and mobile layout
- a persistent Runwarden section rail with brand marker plus a command bar
  that states the local review surface and approval-gated side-effect posture
  and collapses to a sticky top navigation rail on mobile without overlaying
  review content
- module headers with state badges so empty, partial, success, and error
  surfaces are distinguishable without duplicating policy decisions in
  TypeScript
- module state classes, risk chips, and the `approval-gated` command-bar text
  are presentation of Rust-owned state only; WebUI code must not use them to
  reimplement allow, deny, approval, provider, or egress policy
- visible details drawer for high-risk approvals
- keyboard-focusable approval rows inside a `role="list"` queue, with
  `aria-current` state and `aria-controls="approval-details"`; the Rust launch
  script may update the details drawer from escaped row data attributes when a
  reviewer selects a different pending approval
- reviewer reason before approve or deny
- minimum 44 px action targets
- keyboard focus styling
- no inline script execution; generated bundles may link the local
  `reviewer-console.js` companion script
- the TypeScript package renderer emits static HTML without a script tag. The
  Rust local API/CLI launch bundle may add `data-local-api-url` and defer-load
  `reviewer-console.js` so browser forms can call the Rust approval endpoints.
- escaped bind text in generated HTML
- launch bundles written only to relative workspace artifact paths
- generated `launch_url` values point at the written `reviewer-console.html`
  file; Windows launch URLs use browser-openable `file:///C:/...` paths rather
  than canonical `\\?\` paths; `local_api_url` reports the configured local API
  origin separately
- pending approval records are rendered with provider, action, actor, authz,
  argument hash, risk chip, pending count, reviewer controls, and escaped
  presentation-only detail attributes. When the local API is running and the
  reviewer supplies the launch token, approval forms submit approve or deny
  decisions to `/approvals/{id}/{decision}` with JSON reviewer/reason payloads.
- reports, artifact manifests, and assurance result files already present under
  the artifact root are summarized in their workbench modules

The CLI can write a launch bundle with `runwarden ui --artifacts artifacts --json`.
