# Reviewer Console Guide

The Reviewer Console is a static security workbench for humans. It displays
Rust-owned state and submits reviewer decisions through the token-protected
Local API. It is not a policy engine.

## Local Launch

Build the workspace first:

```bash
cargo build --workspace
```

Generate a static launch bundle:

```bash
target/debug/runwarden ui \
  --bind 127.0.0.1 \
  --port 8088 \
  --artifacts artifacts \
  --json
```

The JSON response includes:

- `launch_url`: `file://` URL for `reviewer-console.html`.
- `script_path`: local companion script used by browser forms.
- `local_api_url`: Local API origin that approval forms call.

Start the Local API when browser approval submission is needed:

```bash
target/debug/runwarden api serve \
  --bind 127.0.0.1 \
  --port 8088 \
  --json
```

## Review Workflow

1. Create or load a manifest-backed session.
2. Inspect the status strip for risk, trace integrity, pending approvals, and
   gate status.
3. Check Agent Boundary and Provider Registry before reviewing actions.
4. Open a pending approval row.
5. Inspect provider, action, risk, target, side effects, actor, authz,
   argument hash, and related `obs_*` references in the details drawer.
6. Enter the Local API launch token in Settings.
7. Approve or deny with reviewer identity and reason.

## Security Rules

- Approval mutations go through Local API launch-token, Host, and Origin checks.
- The browser UI must not mutate authority directly.
- High-risk approvals require visible context before the reviewer can approve
  or deny.
- `--artifacts` must be a relative workspace path. Absolute paths, parent
  traversal, and symlink escapes are rejected before writing.
- The WebUI displays Rust-owned state; it must not reimplement provider,
  approval, egress, or report policy in TypeScript.

Maintained reference: [WebUI Review Console](../reference/webui-review-console.md).
