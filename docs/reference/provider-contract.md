# Provider Contract

Provider contracts bind provider identity, schema pins, observed schema digest, declared risk, side effects, and enforcement requirements.

Contracts require:

- kernel mediation
- schema pins
- resource limits
- trace output
- egress policy for network-active providers
- approval gates when risk or side effects require them
- `side_effect_executed=false` for denied or review-blocked calls

External MCP contracts bind execution to the manifest transport. Request transport overrides are denied unless they match exactly.

## Authenticated extraction binding

Before typed policy, the authoritative Rust extractor creates a process-local
`ResourceBindingProof`. Its key comes from the operating-system CSPRNG, remains
in shared zeroizing memory, and is separated from the verifier installed in
the session context. A domain-separated HMAC commits the full canonical
provider contract, provider id, action, Canonical JSON v1 arguments, typed
resource claim, Rust-derived reserved charge, and enforcement mode. The proof
has no clone, debug, serialization, or public field surface. Policy recomputes
the complete tuple and uses constant-time tag verification; all mismatches use
one stable failure. This pre-policy proof establishes extraction provenance but
does not authorize a side effect.

## Frozen native execution permit

The native provider boundary defines an opaque, process-local
`ExecutionPermit`. A trusted Rust runtime creates a 256-bit key from the
operating-system CSPRNG; issuer and verifier share it through zeroizing memory
and expose no key, tag, serialization, or debug representation. Permit claims
are authenticated with HMAC-SHA-256 over a versioned domain separator plus
Canonical JSON v1.

The claims bind story, session, operation, lease, provider, action, canonical
argument and resource-claim hashes, policy snapshot, provider-contract hash,
the Rust-derived reserved `BudgetCharge`, expiry, and durable execution-start
version. Validation authenticates the MAC with constant-time
`Mac::verify_slice`, requires `now < expires_at`, recomputes argument and claim
digests and the current canonical Rust catalog contract with the same
domain-separated kernel helper as typed policy evaluation, rejects
`OpaqueLegacy`, and compares every frozen binding. Stable
provider result codes use the kernel `EventCode` vocabulary; malformed text is
never copied into redacted result evidence. Result fields are private and the
typed validator rejects contradictory execution status, side-effect state,
output, receipt, budget, and error-code combinations. Executed outcomes require
a positive call charge no greater than the permit reservation;
`OutcomeUnknown` claims no output or receipt and conservatively charges the
entire reservation.

Permit validation is intentionally not a durable start transition or a replay
store. Plan 4 will be the only issuer call site, after
`mark_execution_started`; `DefaultProviderExecutor` will atomically claim the
operation and return reconciliation state instead of repeating a backend side
effect. A restarted authority cannot validate an old process permit and must
recover the already-started operation rather than issue another capability.
