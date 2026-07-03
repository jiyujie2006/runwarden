# Agent Instructions

Runwarden is a Rust-owned security kernel with TypeScript integration surfaces.
Keep security decisions in Rust crates; TypeScript packages may present,
validate, or call contracts but must not duplicate allow/deny policy logic.

Use these gates: `bash scripts/pr_fast_gate.sh`,
`bash scripts/release_gate_local.sh`, and `cargo test --workspace`.

Before changing provider, report, artifact, approval, or MCP behavior, read the
matching reference page under `docs/reference/` and update it with the code
change. Keep `docs/README.md` as the documentation index.

Preserve these invariants:

- Agents see only `runwarden-mcp`; raw shell, filesystem, browser, HTTP, and
  downstream MCP tools stay behind Runwarden providers.
- Runwarden-only agent configs allow `args: []` but must reject non-empty or
  malformed `args` and any `env`, `cwd`, `url`, or `transport` override.
- Provider calls must go through kernel session, scoped-root, egress, authz,
  approval, budget, and trace enforcement before side effects.
- External MCP stdio adapters require a trusted runtime root, exact command
  allowlisting, no shell or `-c`, bounded output, and process-tree cleanup.
- HTTP/SSE adapters must deny hostname resolutions to private or local
  addresses before connecting.
- Reports must cite verified `obs_*` events that support the claim semantics.
- Artifact/UI output paths must be relative workspace paths; reject traversal,
  absolute paths, and symlink escapes.
