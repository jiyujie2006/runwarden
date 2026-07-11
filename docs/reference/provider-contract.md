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

`PolicyEvaluation` records whether that proof verified and carries a separate,
non-authorizing `proposal_commitment`. The commitment uses its own domain and
binds the canonical provider contract and id, action, complete arguments,
claim, and charge. Monitor-only assurance recomputes it so a self-consistent
request changed after policy evaluation cannot be attributed to the old
decision.

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

## Default executor and monitor-only boundary

`DefaultProviderExecutor` receives its `PermitVerifier` only through a trusted
`ExecutorConfig`. The verified sandbox root, trusted runtime root, output cap,
and timeout are private after construction and exposed only through read-only
getters; the two canonical roots must exist, be absolute, and not overlap.
Debug output redacts the verifier. Execution performs canonical catalog and
permit validation before business I/O, verifies the configured roots still
have their startup identity, then rederives the exact argument-to-claim mapping
with a trusted logical root/namespace/classification scope. It never treats
server-owned fields copied from the claim as configuration. The local file,
email, memory, knowledge, and simulated-network bodies are crate-private; no
generic public execution wrapper remains. Generic file operations also reject
the private backing prefixes used by email, stores, and Runwarden state.

Email is the first replay-reconciled business effect. Its canonical receipt
binds operation id, complete argument hash, canonical recipients, subject and
body hashes, and recorded time. Unique fsynced temporary files plus atomic
`hard_link` creation ensure concurrent executors converge on one receipt.
Exact duplicates return the same typed receipt, changed arguments return a
zero-charge binding conflict, and malformed or internally contradictory
receipt state returns `OutcomeUnknown` with the full reserved budget. Safe
provider outputs never contain file contents, message plaintext, or store
values.

A bounded process registry claims each operation id across executor instances.
Its binding includes the complete frozen request and the pinned physical roots;
completed or uncertain tombstones do not expire with the permit. Exact replay
returns the cached redacted result without repeating an effect, while a changed
binding or a second physical root fails closed. This is process-local defense
in depth; the SQLite lease and operation journal remain the durable owner.

`MonitorOnlyObserver` is a separate stateless unit type, not an executor. It
holds no permit, verifier, approval, lease, filesystem, process, network, or
tool delegate. It checks request self-commitments, the canonical catalog
contract, all ten contest provider/action/claim shapes, verified extraction
status, evaluation hashes and charge, and the full proposal commitment.
Syntactically valid proposals are reported as counterfactual
`simulated_would_execute` for every shadow policy decision; malformed or
uncatalogued proposals are `not_executable`. Neither result is execution
evidence.
