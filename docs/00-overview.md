# Overview

Runwarden makes agent tool use auditable and enforceable by routing all tool calls
through a Rust security kernel.

The v1 workspace contains:

- `runwarden-mcp`: the only MCP server agents should see.
- `runwarden`: the human control plane CLI.
- `runwarden-kernel`: authority, contracts, enforcement, trace, approval, and
  artifact primitives.
- `runwarden-providers`: provider runtime isolation, first-party provider
  catalog, input inspection, and evidence inspection.
- `runwarden-assurance`: report lint/render/scaffold, eval, cert, bench, audit,
  accountability, artifact sealing, and artifact verification.
- TypeScript packages for SDK access, config checks, MCP helpers, and reviewer
  console rendering.

The local release gate is `scripts/release_gate_local.sh`. It runs formatting,
clippy, Rust tests, TypeScript tests/builds, strict repository checks, cert, and
bench evidence.
