# Security Policy

Runwarden is intended to enforce a hard boundary between AI agents and raw
tools. Until the first public release, report security issues privately to the
repository owner.

## Security-Sensitive Invariants

- Agents only see the Runwarden skill and `runwarden-mcp`.
- Raw shell, filesystem, browser, HTTP, and downstream MCP access are not
  exposed by default.
- Runwarden-only agent configs may use empty `args: []`, but must reject
  malformed or non-empty `args` and any `env`, `cwd`, `url`, or `transport`
  override.
- Rust kernel code owns authorization and enforcement decisions.
- TypeScript code must not duplicate allow/deny logic.
- Provider calls must pass through kernel session, scoped-root, egress, authz,
  approval, budget, and trace enforcement before side effects.
- Reports must cite verified `obs_*` events.
- External MCP adapters must enforce trusted roots, command allowlists, private
  egress denial, frame/output limits, and timeout cleanup before side effects.
- Artifact and UI writers must reject absolute output paths, parent traversal,
  and symlink escapes.

## Review Expectations

Security-boundary changes should include tests for the allow path and the deny
or requires-review path. Update the matching `docs/reference/` page with any
behavioral change.
