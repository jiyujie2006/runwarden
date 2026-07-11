# Provider Contract

Provider contracts bind provider identity, schema pins, observed schema digest,
declared risk, side effects, and enforcement requirements. For an external
adapter, the canonical contract also commits the manifest schema version,
transport, declared permissions, allowed origins, exact command allowlist,
working root, and schema-pin algorithm and digest. Changing any of that
execution material changes the provider-contract hash and invalidates both
registration and an already-issued execution permit.

Contracts require:

- kernel mediation
- schema pins
- resource limits
- trace output
- egress policy for network-active providers
- approval gates when risk or side effects require them
- `side_effect_executed=false` for denied or review-blocked calls

External MCP contracts bind execution to the manifest transport. There is no
request transport, command, argument-vector, working-directory, environment,
header, timeout, or output-limit override surface.

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
store. The native runtime is the only issuer call site, after
`mark_execution_started`; `DefaultProviderExecutor` atomically claims the
operation and returns reconciliation state instead of repeating a backend side
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

Email is the first replay-reconciled business effect. Its canonical v2 receipt
binds operation id, canonical recipients, subject and body hashes, recorded
time, and a domain-separated digest of the complete frozen execution request:
story, session, provider, action, argument and resource-claim commitments,
policy snapshot, provider contract, and reserved budget. Unique fsynced
temporary files plus atomic `hard_link` creation ensure concurrent executors
converge on one receipt. Exact duplicates return the same typed receipt,
changed bindings return a zero-charge conflict, and malformed or internally
contradictory receipt state returns `OutcomeUnknown` with the full reserved
budget. Safe provider outputs never contain file contents, message plaintext,
or store values.

A bounded process registry claims each operation id across executor instances.
Its binding includes the complete frozen request and the pinned physical roots;
completed or uncertain tombstones do not expire with the permit. Exact replay
returns the cached redacted result without repeating an effect, while a changed
binding or a second physical root fails closed. This is process-local defense
in depth; the SQLite lease and operation journal remain the durable owner.

Recovery uses `ProviderExecutor::reconcile(&ProviderExecutionRequest)` and
returns `ProviderReconciliationOutcome`, which contains the typed
`ReconciliationResult` and an optional opaque `CleanupToken`. An operation id
alone is never sufficient. The default executor first verifies pinned roots,
the current canonical catalog contract, canonical argument and claim hashes,
the exact provider/action/claim family, trusted extraction scope, positive
single-call reservation, and any cached complete binding. It then invokes only
a provider-specific evidence reader; reconciliation never dispatches a
business tool. Email completion requires the v2 receipt to match the complete
frozen request. A missing exact email receipt may be `NotExecuted` only when no
conflicting process record exists. Providers without durable evidence return
`Unknown`, never `NotExecuted` based on an empty email-receipt path or process
memory.

Email reconciliation may rebuild one cleanup capability without retaining
process memory. The candidate must be a bounded, canonical regular file in
`mail/tmp`, carry the exact operation-prefixed random name, hash to the verified
receipt, and, on Unix, share the receipt's device/inode hard-link identity.
Substituted same-content copies, symlinks, malformed candidates, and binding
changes return `Unknown` with no cleanup capability. Cleanup remains a separate
post-journal action and never changes the truthful reconciliation result.
Every Unix cleanup token also commits the device/inode identity observed when
the executor created or recovered that file. This lets the winning receipt hard
link and a concurrently created losing temp inode be finalized without
authorizing a later same-content replacement. Platforms without a stable file
identity do not receive cleanup capabilities in this build.

The contest threat model makes `mail/` provider-private: the generic file
provider rejects that prefix, external process adapters are disabled, and no
same-UID out-of-band writer may mutate it concurrently. Final deletion checks
the token-bound identity immediately before unlinking. Strict protection
against a hostile host process racing that final pathname check requires a
future handle-based deletion sandbox; such host compromise is not represented
as an in-process cleanup guarantee.

External MCP manifests can be offered only through the consuming
`DefaultProviderExecutor::with_external_mcp` registration method. Admission
first requires a provider already present in the Rust catalog and exact
equality with its manifest-derived canonical contract. The only transport
entry point is crate-private and is named only by the default executor; public
manifest loading and certification cannot execute an adapter. If a transport
is admitted in a future release, the adapter must revalidate the exact permit
before inspecting transport configuration or performing filesystem, DNS,
socket, or process work, and the executor operation registry remains the
replay owner.

No external MCP transport is admitted in the current contest build. The stdio
validator still requires one bare downstream command equal to the downstream
identity, `working_root="."`, an executable non-symlink file directly under
the pinned trusted runtime root, and no declared network or credential
capability. It then returns `stdio_isolation_unavailable`: path trust,
environment scrubbing, a fixed cwd, output limits, and process-group cleanup
cannot enforce scoped-root and egress policy against a compromised downstream
process. Re-enabling stdio requires mandatory namespaces, filesystem and
syscall confinement, resource ownership that covers daemonization, and
deadline-safe output collection; there is no unsandboxed fallback.

HTTP and legacy SSE are also explicitly quarantined. Static validation accepts
only canonical public plaintext-HTTP origin shapes and forbids process
controls, but registration returns `network_adapter_not_enabled`. Activation
requires a server-owned endpoint distinct from business arguments, complete
MCP response correlation/state handling, one absolute DNS/connect/read
deadline, TLS for HTTPS, and deny-by-default special-address handling. A future
catalog entry cannot accidentally activate the current placeholders.

`MonitorOnlyObserver` is a separate stateless unit type, not an executor. It
holds no permit, verifier, approval, lease, filesystem, process, network, or
tool delegate. It checks request self-commitments, the canonical catalog
contract, all ten contest provider/action/claim shapes, verified extraction
status, evaluation hashes and charge, and the full proposal commitment.
Syntactically valid proposals are reported as counterfactual
`simulated_would_execute` for every shadow policy decision; malformed or
uncatalogued proposals are `not_executable`. Neither result is execution
evidence.
