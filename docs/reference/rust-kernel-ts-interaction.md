# Rust Kernel and TypeScript Interaction

Rust remains the source of truth for security contracts and policy decisions.

The active TypeScript surface in the contest edition is `packages/webui`. It renders Rust-produced demo JSON and must not duplicate:

- allow/deny policy
- provider risk decisions
- approval requirements
- egress decisions
- report citation semantics

JSON schemas under `schemas/` are generated from Rust contract types where possible. TypeScript may define presentation types for demo JSON but those types are not authoritative policy.
