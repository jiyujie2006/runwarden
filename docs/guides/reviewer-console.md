# Reviewer Console Guide

The Reviewer Console is a Rust-served security workbench for humans. It
displays Rust-produced event JSON and can write reviewer approval decisions.
It is not a policy engine.

## Local Build

Build the workspace first:

```bash
cargo build --workspace
```

Generate demo JSON:

```bash
target/debug/runwarden demo --all --output artifacts/demo --json
```

Open the static console:

```bash
xdg-open artifacts/demo/reviewer-console.html
```

For interactive review, run `target/debug/runwarden demo` and open
`http://127.0.0.1:8088`.

## Review Workflow

1. Open the generated static HTML.
2. Inspect scenario id, provider-call count, denial count, trace status,
   timeline events, and pending review queue in the generated HTML.
3. Use the adjacent demo JSON files for metrics, report claims, and cited
   `obs_*` refs.
4. Open the generated report path for the trace-backed narrative.

Approval decisions are submitted from the browser by updating
`.runwarden/approvals/*.json`; MCP consumes matching approvals on retry.

## Security Rules

- The browser UI may only mutate approval files through Rust HTTP handlers.
- High-risk review states come from Rust-produced demo JSON.
- `--output` must be a relative workspace path. Absolute paths, parent
  traversal, and symlink escapes are rejected before writing.
- The WebUI displays Rust-owned state; it must not reimplement provider,
  approval, egress, or report policy.

Maintained reference: [WebUI Review Console](../reference/webui-review-console.md).
