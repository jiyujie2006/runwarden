# Rust Kernel and TypeScript Interaction

Runwarden treats Rust as the source of truth for security contracts. The kernel emits checked JSON schemas, and TypeScript packages consume generated declarations from those schema artifacts.

The supported pipeline is:

1. Rust contract types live in `crates/runwarden-kernel/src/contracts`.
2. `cargo run -p runwarden-kernel --example generate_schemas` refreshes `schemas/*.schema.json`.
3. `node packages/agent-sdk/scripts/generate-contracts.mjs` refreshes `packages/agent-sdk/src/generated/contracts.ts`.
4. `scripts/check_ts_contracts.sh` fails CI if generated TypeScript declarations drift from Rust schemas.

TypeScript code must import generated contract types such as `PolicyDecision`,
`ExecutionStatus`, `ExecutionMode`, `ErrorKind`, `OperationStatus`,
`OperationError`, `OperationResultForProviderOutcome`, and `ApprovalState` from
`@runwarden/agent-sdk`; it must not duplicate these unions or operation-result
shapes manually.

TypeScript packages also must not duplicate Rust-owned allow/deny policy
checks. For agent-config certification, TypeScript may invoke
`runwarden cert agent-config <path> --json` and format the returned Rust
`AgentConfigCertReport`; the safe/unsafe decision remains in
`runwarden_assurance::cert::certify_agent_config`.
