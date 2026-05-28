# WebUI Review Console

The Reviewer Console is a dependency-free static workbench for approval review, trace status, provider state, reports, artifacts, and assurance results.

The UI contract requires:

- responsive desktop and mobile layout
- visible details drawer for high-risk approvals
- reviewer reason before approve or deny
- minimum 44 px action targets
- keyboard focus styling
- no inline script execution
- escaped bind text in generated HTML
- launch bundles written only to relative workspace artifact paths

The CLI can write a launch bundle with `runwarden ui --artifacts artifacts --json`.
