# Security Policy

Runwarden is intended to enforce a hard boundary between AI agents and raw tools.
Until the first public release, report security issues privately to the repository owner.

Security-sensitive invariants:

- Agents only see the Runwarden skill and `runwarden-mcp`.
- Raw shell, filesystem, browser, HTTP, and downstream MCP access are not exposed by default.
- Runwarden-only agent configs must not redirect `runwarden-mcp` through
  malformed/non-empty `args` or `env`, `cwd`, `url`, or `transport` overrides.
- Rust kernel code owns authorization and enforcement decisions.
- TypeScript code must not duplicate allow/deny logic.
- Reports must cite verified `obs_*` events.
- External MCP adapters must enforce trusted roots, command allowlists, private
  egress denial, frame/output limits, and timeout cleanup before side effects.
- Artifact and UI writers must reject absolute output paths, parent traversal,
  and symlink escapes.
