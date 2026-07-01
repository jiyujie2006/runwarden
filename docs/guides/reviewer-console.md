# Reviewer Console Guide

The Reviewer Console is a static security workbench for humans. It displays
Rust-produced demo JSON and does not submit approval decisions. It is not a
policy engine.

## Local Build

Build the workspace first:

```bash
cargo build --workspace
```

Generate demo JSON:

```bash
target/debug/runwarden demo run \
  --scenario prompt-injection-file-exfil \
  --output artifacts/demo/prompt-injection-file-exfil \
  --json
```

Build the static console:

```bash
target/debug/runwarden ui build \
  --input artifacts/demo \
  --output artifacts/reviewer-console.html \
  --json
```

The JSON response includes `html_path`, `launch_url`, `local_api_url: null`,
and `side_effect_executed: true`.

## Review Workflow

1. Open the generated static HTML.
2. Inspect scenario id, provider-call count, denial count, trace status,
   timeline events, and pending review queue in the generated HTML.
3. Use the adjacent demo JSON files for metrics, report claims, and cited
   `obs_*` refs.
4. Open the generated report path for the trace-backed narrative.

Approval decisions are not submitted from WebUI. Use the CLI path:

```bash
target/debug/runwarden approval pending --json
target/debug/runwarden approval approve <approval_id> \
  --reviewer reviewer_alice --reason "reviewed scope and risk" --json
```

## Security Rules

- The browser UI must not mutate authority directly.
- High-risk review states come from Rust-produced demo JSON.
- `--output` must be a relative workspace path. Absolute paths, parent
  traversal, and symlink escapes are rejected before writing.
- The WebUI displays Rust-owned state; it must not reimplement provider,
  approval, egress, or report policy in TypeScript.

Maintained reference: [WebUI Review Console](../reference/webui-review-console.md).
