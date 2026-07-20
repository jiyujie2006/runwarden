# Authority and Session

Sessions and approval records define the runtime policy envelope for provider calls.

## Pure Typed Policy Evaluation

`SessionContext::from_authority` constructs a typed-policy context from one
server-owned `AuthoritySnapshot`, the canonical Rust provider registry, the
story id, and the enforcement mode. Construction parses the policy snapshot digest and
commits the complete authority plus each allowlisted provider contract. Policy
evaluation rechecks those commitments, so mutating a public projection or
substituting a same-id provider with lower risk or fewer side effects fails at
the session or provider layer.

`evaluate_proposal` is a pure Rust function. Before resource authorization it
authenticates a process-local extraction binding for the exact provider,
action, canonical arguments, claim, provider contract, and proposed charge.
Changing any one of those values after extraction fails closed. It records
exactly six ordered checks—session, provider, authorization, typed resource,
budget, and approval—
and marks all checks after the first terminal result as not evaluated. It does
not read or consume an approval, reserve counters, execute a provider, or
weaken a denial in monitor-only mode. A provider that requires approval returns
`RequiresReview`; the durable journal remains the only component that can bind
and consume the resulting one-shot approval.

Resource authorization is variant-specific. File authority compares logical
root, component-aware relative prefix, access, and classification; network
authority is provider-specific and compares a canonical origin; email checks
every sorted canonical recipient; stores bind namespace, key prefix, and
access; code execution binds runtime, workspace, network capability, and every
limit; input inspection binds source and classification; evidence binds the
current story and an allowed operation; and artifact output binds a validated
relative prefix and format. Store `key_prefix` is deliberately a byte-prefix
for opaque key-value keys, not a filesystem-component prefix. `OpaqueLegacy`
is never executable.

The budget layer measures Canonical JSON v1 argument bytes, applies the
per-operation code wall-time ceiling, and uses checked arithmetic over
committed, concurrently reserved, and proposed call/file/network usage. Exact
limits pass; overflow or one unit over fails closed. Providers derive the
proposed charge from canonical arguments plus trusted per-call file and
response caps before sealing it into the extraction binding; callers cannot
substitute a smaller charge afterward. The returned usage version and
authenticated `BudgetCharge` are observations for the later SQLite CAS
reservation, not a reservation by themselves.

The resulting value also records `proposal_binding_verified` and a
domain-separated `proposal_commitment` over the canonical provider contract,
provider/action, complete arguments, claim, and charge. These fields let a
non-executing assurance observer prove that its counterfactual effect belongs
to the same proposal even when an earlier policy layer denied the request.

## Sessions

Sessions are now internal to demo/check flows. A session derived from an
assessment manifest carries provider allowlist, scoped roots, budgets, actor
id, authz state, and active-assessment state used by `KernelEnforcer`.

The reviewer-facing `AuthoritySnapshot` preserves that boundary as typed Rust
data: provider, file, network, email, store, code, input, evidence, and artifact
authority are separate fields rather than caller-defined JSON. Native snapshot
views reject unknown fields. `max_argument_bytes` and `max_wall_time_ms` are
per-operation ceilings; call, file-byte, and network-byte budgets are cumulative
session counters; model call/input/output budgets are accounted separately by
the model proxy through checked, versioned SQLite updates.

SQLite schema v2 creates exactly one zeroed `model_usage` row for every new or
migrated session. A redacted `model_calls` or `tool_proposals` row is evidence
input only: recording it does not reserve budget, authorize network egress, or
permit model forwarding. Those decisions remain bound to the active session
and the proxy's per-call Rust transaction.

The trusted interactive launcher canonicalizes the configured LLM upstream
and freezes its exact origin in a provider-specific `NetworkAuthority` before
the story and session are activated. The origin is not supplied by an agent
request and an empty network-authority set is a denial, not a default allow.
Every model-call begin transaction re-reads that immutable authority and
requires the exact provider/origin together with the active instance id,
startup instance-token hash, story/session binding, active authz state, and
session expiry. A startup snapshot alone cannot authorize a later forward.

That same immediate transaction performs checked CAS accounting for one model
call and the complete normalized input bytes before committing the model row
and request/filter evidence. The completion transaction performs the checked
output-byte accounting and commits the response/filter evidence before the
response may be released. Exhaustion, arithmetic overflow, stale usage
version, authority mismatch, deactivation, token replacement, or expiry leaves
the upstream untouched when detected before forwarding. Raw token, API key,
prompt, completion, filter evidence, and tool arguments never become authority
or budget material.

Proposal linkage is provenance, not authority. Resolver predicates and
composite foreign keys constrain candidates to the operation's exact story and
session. A link does not expand the provider allowlist, consume an approval,
reserve provider budget, or cross the provider execution-start boundary; the
operation still passes through the ordinary Rust policy, approval, lease,
budget, and execution enforcement.

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
hash; the frozen `proposal_commitment`; and `maximum_consumptions` fixed to
one. Resource variants without a data
classification, such as code execution, use `None` rather than inventing one.

The binding is encoded with Canonical JSON v1 and its SHA-256 digest is stored
as `binding_hash`. `OneShotConsumption` serializes only as the JSON integer
`1`; custom Rust deserialization and the SQLite table constraint reject zero,
larger or negative values, floating-point and string forms, null, and a missing
field. Approval expiry must be later than creation and no later than the
immutable session expiry.

The native runtime constructs this value with
`DurableApprovalBinding::from_operation`. The compatibility data structure
remains public, but approval persistence independently derives and validates
classification and sorted risk tags from the frozen typed claim, so
caller-supplied fields cannot grant authority. The builder also requires the
operation's story/session/provider/action/hashes and policy snapshot to match
the server-owned authority before returning.

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

Both authorization branches must repeat the exact frozen proposal commitment,
provider-contract hash, and Rust-derived budget charge stored at operation
creation. A smaller charge, replacement contract, or approval for another
commitment fails before any reservation or state transition.

Lease acquisition moves the operation to `ExecutionLeased`; a reviewed
approval moves `Approved -> Leased`. This is still not permission to invoke a
provider. `mark_execution_started_at` revalidates the durable lease and current
active-instance binding in a second immediate transaction, consumes a reviewed
approval with `Leased -> Consumed`, moves the operation to `Executing`, and
commits a `provider_execution_started` event. Only its successful return is an
execution authorization boundary. A second start conflicts instead of
consuming or executing twice. The runtime supplies its injected trusted clock
to this boundary; the compatibility `mark_execution_started` state API uses
system UTC.

Resume and reconciliation use the public `ExecutionRuntimeSnapshot` rather
than combining independent reads. It contains the exact lease-bearing
operation, persisted typed policy decision, exact `ExecutionLease`, and a
verified `execution_started` flag from one deferred SQLite transaction. Only
`ExecutionLeased` without a start event and `Executing` with exactly one start
event are valid snapshots. This does not broaden `execution_lease`, which
remains a pre-start-only compatibility query.

Result persistence requires the exact lease id and owner, the committed start
event, executing state, and expected operation version. Actual budget charge
must not exceed the reservation; unused reserved units are released and actual
units become committed in the same transaction as the redacted provider
result and terminal event. A proven `NotExecuted` or
`FailedBeforeSideEffect` result has zero actual charge and releases the full
reservation. Once execution has started, later session
deactivation does not prevent truthful result persistence.

Crash recovery preserves the same boundary without granting a second
execution. An expired lease with no start event can release its retained budget
reservation and restore its direct-policy or still-live reviewed pre-state; an
expired reviewed approval instead expires the approval and operation together.
Only expired `Executing` operations appear as minimal recovery candidates, and
Runwarden never retries them automatically. If no trustworthy result can be
reconciled, exact lease/version CAS records `OutcomeUnknown` immediately and
conservatively commits the full reservation. This truthful recovery path does
not require the crashed instance or session to remain active.

`ApprovalView` is a typed, display-safe projection carried by a
`SecurityOperation`. It can expose the typed approval and lease identifiers,
state, binding digest, reviewer metadata, and expiry, but it is not itself an
authorization input. Provider execution continues to consume the Rust-owned
approval record and lease contract.

The native SQLite contracts above are now consumed by production
`runwarden-mcp` through `runwarden-runtime`. MCP creates, waits for, reads, and
resumes the same operation; it never imports a file-backed approval as native
authority. Status and resume accept only the operation id, and the runtime
loads the frozen private request before any lease or execution transition.

The loopback reviewer API writes native decisions only through
`StateStore::decide_active_approval`. Its active-story lookup, immutable
binding validation, expiry check, and approval/operation version CAS occur in
one immediate transaction. A missing active context is a state conflict and
an approval belonging to another story is hidden as not found. The API returns
the updated display-safe approval and operation from that transaction;
approval still does not lease, consume, or execute the operation.

The dependency-free live console now reads native operation snapshots and
submits nonce-, origin-, and version-protected decisions to that boundary. The
original waiting MCP call observes the durable decision and resumes the same
operation. File-backed compatibility records cannot approve or consume a
native operation, and the legacy in-memory authority path rejects
`ApprovalState::Leased` rather than treating it as an ordinary approval. See
[Reviewer HTTP and SSE API](reviewer-http-sse-api.md) and
[Native Operation Journal](operation-journal.md).
