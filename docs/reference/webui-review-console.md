# WebUI Review Console

The Reviewer Console is a dependency-free static workbench for approval review, trace status, provider state, reports, artifacts, and assurance results.

The UI contract requires:

- responsive desktop and mobile layout
- visible details drawer for high-risk approvals
- reviewer reason before approve or deny
- minimum 44 px action targets
- keyboard focus styling
- no inline script execution; generated bundles may link the local
  `reviewer-console.js` companion script
- escaped bind text in generated HTML
- launch bundles written only to relative workspace artifact paths
- generated `launch_url` values point at the written `reviewer-console.html`
  file; `local_api_url` reports the configured local API origin separately
- pending approval records are rendered with provider, action, actor, authz,
  argument hash, and reviewer controls. When the local API is running and the
  reviewer supplies the launch token, approval forms submit approve or deny
  decisions to `/approvals/{id}/{decision}` with JSON reviewer/reason payloads.
- reports, artifact manifests, and assurance result files already present under
  the artifact root are summarized in their workbench modules

The CLI can write a launch bundle with `runwarden ui --artifacts artifacts --json`.
