# Agent Security Kernel

The Rust kernel owns manifests, sessions, provider registry lookup, policy gates,
scope gates, egress gates, budget gates, approval gates, trace writing, redaction,
and report citation enforcement.

Implemented enforcement path:

1. Validate provider exists in the kernel registry.
2. Validate the session allowlist permits the provider.
3. Validate scoped roots and reject root escape before side effects.
4. Validate network egress and deny private/metadata addresses.
5. Validate argument budgets.
6. Require an active assessment.
7. Validate authz state.
8. Require and consume a bound approval for high-risk providers.
9. Return a `ProviderOutcome` with separate policy decision and execution status.

Every denial returns `side_effect_executed: false` and a stable `ErrorKind`.
High-risk approval records are single-use and bind session, provider, action,
argument hash, authz, and actor.

Trace events are append-only, hash-chain verified, and queryable with provider,
event-type, `obs_*` prefix, offset/limit, and byte-budget bounds before export
or report use. Reports cannot render successfully unless every claim cites known
`obs_*` references.

External providers are modeled as kernel-managed provider manifests. Each
manifest binds downstream identity, tool identity, transport, declared
permissions, egress policy, side effects, risk, and a SHA-256 schema pin. The
provider contract detects schema rug-pulls when the observed schema digest
differs from the pin, and high-risk or side-effecting providers require approval
gates, trace, redaction, and resource limits before execution.
