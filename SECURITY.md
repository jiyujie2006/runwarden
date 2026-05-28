# Security Policy

Runwarden is intended to enforce a hard boundary between AI agents and raw tools.
Until the first public release, report security issues privately to the repository owner.

Security-sensitive invariants:

- Agents only see the Runwarden skill and `runwarden-mcp`.
- Raw shell, filesystem, browser, HTTP, and downstream MCP access are not exposed by default.
- Rust kernel code owns authorization and enforcement decisions.
- TypeScript code must not duplicate allow/deny logic.
- Reports must cite verified `obs_*` events.

