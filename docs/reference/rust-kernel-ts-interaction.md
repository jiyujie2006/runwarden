# Rust Kernel and TypeScript Interaction

Rust remains the source of truth for security contracts and policy decisions.

The contest edition no longer has an active TypeScript package. The reviewer
console is Rust-served HTML/JS and must not duplicate:

- allow/deny policy
- provider risk decisions
- approval requirements
- egress decisions
- report citation semantics

JSON schemas under `schemas/` are generated from Rust contract types where possible. Any future TypeScript may present or validate Rust-produced data, but must not become authoritative policy.
