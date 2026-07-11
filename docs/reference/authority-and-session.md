# Authority and Session

Sessions and approval records define the runtime policy envelope for provider calls.

## Sessions

Sessions are now internal to demo/check flows. A session derived from an
assessment manifest carries provider allowlist, scoped roots, budgets, actor
id, authz state, and active-assessment state used by `KernelEnforcer`.

The reviewer-facing `AuthoritySnapshot` preserves that boundary as typed Rust
data: provider, file, network, email, store, code, input, evidence, and artifact
authority are separate fields rather than caller-defined JSON. Native snapshot
views reject unknown fields. `max_argument_bytes` and `max_wall_time_ms` are
per-operation ceilings; call, file-byte, and network-byte budgets are cumulative
session counters; model call/input/output budgets are reserved separately by
the model proxy.

Static demo story generation creates one typed UUIDv7 session id before the
legacy `SessionManifest` and reuses it for kernel calls, the
`AuthoritySnapshot`, and every `SecurityOperation`. The story projection reads
only trusted assessment/session fields. It does not copy provider-supplied
authority or absolute scoped-root paths. Authority classes and budgets that
the legacy manifest cannot prove remain empty or zero.

The five current demo assessments have a trusted `demo-agent` actor but no
configured authz id or expiry. Their incomplete legacy story snapshots use
`legacy-not-configured`, `not_configured`, and the Unix epoch as explicit
absence sentinels. Agent and model identity fields use `legacy-unavailable`;
these values are not fabricated identities or authorization grants.

MCP callers do not create or mutate that envelope through tool arguments.
`runwarden-mcp` builds any inline kernel policy from server-owned defaults and
rejects agent-supplied session, assessment, authz, budget, root, and
approval-like fields such as `session_allowed_providers`, `active_assessment`,
`authz_grants`, `budget`, `budgets`, `root`, `root_path`, `sandbox_root`,
`authz_id`, and `approval_id`.

## Approval Records

The native SQLite journal binds a reviewer decision to one immutable operation,
not to a reusable permission. `DurableApprovalBinding` contains the story,
session, and operation ids; actor and authz ids; provider and action; canonical
resource-claim and complete-argument hashes; the applicable data
classification; Rust-derived, sorted, unique risk tags; the policy snapshot
hash; and `maximum_consumptions` fixed to one. Resource variants without a data
classification, such as code execution, use `None` rather than inventing one.

The binding is encoded with Canonical JSON v1 and its SHA-256 digest is stored
as `binding_hash`. `OneShotConsumption` serializes only as the JSON integer
`1`; custom Rust deserialization and the SQLite table constraint reject zero,
larger or negative values, floating-point and string forms, null, and a missing
field. Approval expiry must be later than creation and no later than the
immutable session expiry.

Creating an approval requires the operation to have a stored
`RequiresReview` policy decision and state `AwaitingApproval`. Reviewer and
expiry transitions use versioned compare-and-swap on both records in one
`BEGIN IMMEDIATE` transaction:

- approval moves `Pending -> Approved` while the operation moves
  `AwaitingApproval -> Approved`;
- approval moves `Pending -> Denied` while the operation moves
  `AwaitingApproval -> DeniedByReviewer` with
  `BlockedBeforeExecution`;
- at or after the deadline, approval and operation both move to `Expired`, and
  the side effect remains blocked before execution.

A stale approval or operation version, changed binding, expired authority, or
illegal state rolls back the whole transition. Every successful transition
also appends one typed event and one replay frame before commit. Reviewer
reason text is display metadata in the safe approval projection; the sealed
approval event contains only a reviewer-id hash and never the raw reason.

### Native execution leases

The native journal has two explicit lease authorizations. A direct-policy
lease requires a persisted `Allowed` decision in `PolicyEvaluated` and forbids
an approval row. A reviewed lease requires the exact approved record, binding,
and approval version. Both paths are restricted to enforced stories.

Before reserving a lease, the same transaction re-reads the singleton active
instance and immutable session. Story, session, instance id, instance-token
hash, active authz state, policy snapshot, and expiry must all match. It then
CAS-reserves call, file-byte, and network-byte budget against committed plus
already-reserved usage. Overflow, exhaustion, or a concurrent budget version
change leaves the operation, approval, and counters unchanged.

Lease acquisition moves the operation to `ExecutionLeased`; a reviewed
approval moves `Approved -> Leased`. This is still not permission to invoke a
provider. `mark_execution_started` revalidates the durable lease and current
active-instance binding in a second immediate transaction, consumes a reviewed
approval with `Leased -> Consumed`, moves the operation to `Executing`, and
commits a `provider_execution_started` event. Only its successful return is an
execution authorization boundary. A second start conflicts instead of
consuming or executing twice.

Result persistence requires the exact lease id and owner, the committed start
event, executing state, and expected operation version. Actual budget charge
must not exceed the reservation; unused reserved units are released and actual
units become committed in the same transaction as the redacted provider
result and terminal event. A proven `NotExecuted` or
`FailedBeforeSideEffect` result has zero actual charge and releases the full
reservation. Once execution has started, later session
deactivation does not prevent truthful result persistence.

`ApprovalView` is a typed, display-safe projection carried by a
`SecurityOperation`. It can expose the typed approval and lease identifiers,
state, binding digest, reviewer metadata, and expiry, but it is not itself an
authorization input. Provider execution continues to consume the Rust-owned
approval record and lease contract.

The native SQLite contracts above currently exist in `runwarden-state`; they
do not yet replace the contest edition's legacy interactive wiring.
`runwarden demo` and `runwarden-mcp` still exchange file-backed reviewer
records under `.runwarden/approvals` (or `RUNWARDEN_STATE_DIR`). That legacy
path binds session/provider/action/argument/authz/actor fields and must not be
described as having acquired a native SQLite execution lease until the runtime,
MCP, and WebUI migration is complete. The legacy in-memory authority path
rejects `ApprovalState::Leased` rather than treating it as an ordinary approval.
