# Agent Security Kernel

The Rust kernel is the source of truth for Runwarden security decisions. CLI,
MCP, browser code, and any future TypeScript presentation code may display
state or call contracts, but they must not duplicate allow/deny policy.

## Enforcement Path

`KernelEnforcer` evaluates provider calls before trusted side effects:

1. Validate that the provider exists in the kernel registry.
2. Validate that the session allowlist permits the provider.
3. Validate scoped roots and reject root escape.
4. Validate network egress and deny private or local targets.
5. Validate argument byte budgets.
6. Require an active assessment when the policy requires one.
7. Validate actor-bound authz state.
8. Require and consume a bound approval for high-risk providers.
9. Return a `ProviderOutcome` with separate policy decision and execution
   status.

Every denial, rejection, or review block must report
`side_effect_executed: false`.

## Authority and Approval

High-risk approval records are single-use. A matching approval binds:

- session id
- provider id
- action
- argument hash
- authz id
- actor id

Session-derived authz grants are actor-bound, so another actor cannot reuse the
same authz id. Reviewer decisions are represented as Rust-owned
`ApprovalRecord` values.

## Trace and Reports

Trace events are append-only and hash-chain verified. Trace export supports
provider, event type, `obs_*` prefix, offset/limit, and byte-budget filters.

Reports cannot render successfully unless every claim cites known `obs_*`
references that support the claim semantics. Claims may use structured support
fields for exact provider, event type, decision, execution status, and
side-effect assertions.

## External Providers

External and demo providers are kernel-managed provider manifests. A manifest
binds:

- downstream identity and tool identity
- provider kind and class
- transport
- permissions
- egress policy
- side effects and risk
- schema pin
- evidence and authority requirements

Stdio MCP adapters require a trusted runtime root, exact command allowlisting,
no shell-capable command or `-c`, bounded output, timeout cleanup, and
process-tree cleanup. HTTP and SSE adapters reject private or local address
resolutions before connecting.

## Maintained References

- [Provider Model](reference/provider-model.md)
- [Provider Manifest](reference/provider-manifest.md)
- [Provider Contract](reference/provider-contract.md)
- [Authority and Session](reference/authority-and-session.md)
- [Evidence and Accountability](reference/evidence-and-accountability.md)
- [Threat Model](reference/threat-model.md)
