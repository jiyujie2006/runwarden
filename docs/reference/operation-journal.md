# Native Operation Journal

`runwarden-state` is the Rust-owned durable authority for native Security Story
operations. It stores the authorization decision, one-shot approval, execution
lease, budget reservation, redacted result, sealed event, and replay frame in a
single SQLite database. TypeScript and browser surfaces may display this state;
they do not reproduce its allow, deny, lease, recovery, or budget decisions.

## Ownership and durability

The Rust crate owns every v1 table:

| Tables | Rust-owned purpose |
| --- | --- |
| `stories`, `sessions`, `active_instances` | story/session authority and the singleton live runtime |
| `operations`, `resource_claims`, `policy_checks` | immutable invocation binding, private arguments, redacted operation state, and policy evidence |
| `approvals` | reviewer-bound one-shot decisions and lease consumption |
| `budget_usage`, `budget_reservations` | CAS-protected reserved and committed resource accounting |
| `events`, `story_frames`, `report_claims` | sealed observations, replay snapshots, and report support |
| `exports` | native export publication journal |

Every `StateStore` connection enforces WAL mode, `synchronous=FULL`, foreign
keys, a bounded 5,000 ms busy timeout, and the strict v1 schema. The state
directory, database, WAL, and shared-memory sidecars must remain owner-only;
symlinks and unsupported permission models fail closed. File hardening opens
the verified parent directory and uses a directory-relative no-follow chmod,
then verifies that the file retained its device/inode identity. It never opens
the SQLite shared-memory sidecar, whose process-scoped locks must remain owned
exclusively by SQLite.
WAL and shared-memory sidecars may disappear when the last concurrent SQLite
connection closes; a verified sidecar disappearing during hardening is treated
as its normal lifecycle, while the main database or a replaced path still
fails closed. SQLite integers that represent Rust `u64` values use checked
conversions.

The contract-freeze build deliberately does not guess proposal bindings for an
older development database that lacks these fields: such a shape fails strict
schema validation and must be archived and reinitialized. Provider contracts
and proposed charges cannot be reconstructed safely inside the state crate,
so an in-place permissive backfill would weaken old approvals.

Full provider arguments live only in `operations.private_arguments_json`.
The same row freezes the provider-contract hash, conservative `BudgetCharge`,
and their domain-separated proposal commitment. Those fields are immutable,
are included in the invocation binding, and are recomputed by trusted
snapshots. Policy, approval, lease, request reconstruction, and permit issuance
must all refer to that exact proposal, so an upgrade cannot reinterpret an old
allow or approval.
Snapshots, approvals, events, frames, recovery candidates, and JSONL export use
typed redacted views or hashes. Recovery errors and reason codes must not carry
raw provider exceptions or private input.

The runtime reads an operation and its persisted policy decision through the
typed `StateStore::operation_runtime_snapshot` query. One SQLite snapshot
verifies the complete story evidence chain and rejects a proposed operation
with a decision or any post-policy operation missing one; runtime and UI code
do not infer allow from state names or check text. The narrower
`StateStore::policy_decision` query delegates to the same verified snapshot.

The native runtime builds reviewer bindings with
`DurableApprovalBinding::from_operation`. The compatibility structure remains
public, so `create_approval` still independently derives and validates the
expected classification and risk tags before accepting it. If a policy write
commits `AwaitingApproval` before the approval response is observed, a retry
first reads the operation-bound approval and creates one only when it is
absent. A concurrent insert or commit-then-response-loss is accepted only
after the exact durable binding can be read back. Reusing an `InvocationKey`
with different provider arguments returns the identity of the conflicting
operation and never starts a second proposal.

At runtime startup, active instance, verified story, and live session are
loaded from one deferred SQLite snapshot using only the SHA-256 hash of the
inherited process token. The raw token is neither serialized nor retained in
the runtime context.

## Authorization and execution boundaries

Lease acquisition is an immediate transaction. It verifies the complete story
evidence, immutable session and policy snapshot, singleton active-instance
identity and token hash, operation/approval versions, lease-id uniqueness, and
cumulative budget before reserving resources. A direct policy allow has no
approval row. A reviewed operation consumes exactly the bound approval.
Before any reservation is created, released, or committed, the journal
recomputes Reserved and Committed totals from every canonical reservation row
and requires them to equal the CAS-protected aggregate counters. Reservation
timestamps are monotonic and included in settlement/release CAS predicates, so
counter-only or clock-forward tampering fails before partial mutation. Read-only
budget snapshots load the session, reservation aggregate, and aggregate counter
row in one deferred SQLite transaction, so a concurrent reservation commit
cannot be mistaken for journal corruption.

`ExecutionLeased` is not provider authorization. Immediately before a side
effect, `mark_execution_started` revalidates the active instance and lease,
moves the operation to `Executing`, consumes any reviewed approval, and commits
`provider_execution_started` with its replay frame. Only that successful return
authorizes the provider adapter to proceed.

The runtime calls the timestamped start form with its injected trusted clock;
the state transaction checks that time against the story clock, active session,
and exact lease expiry. The compatibility state entry point uses system UTC.

Runtime resume and reconciliation read `ExecutionLeased` and `Executing`
through `StateStore::execution_runtime_snapshot`. One deferred SQLite snapshot
verifies the complete story evidence, exact typed policy decision, durable
lease (including approval and budget-reservation binding), and the unique
execution-start event. `ExecutionLeased` must have no start event and
`Executing` must have exactly one; any other state or torn relationship fails
closed. The older `execution_lease` query deliberately keeps its pre-start-only
semantics and still returns a lease only for `ExecutionLeased`.

Two concurrent resumes may observe `Executing` immediately before the winner
commits its terminal result. If that transition invalidates the exact execution
snapshot, the loser re-reads through the runtime's bounded state-machine loop
and returns the committed terminal view. Persistent snapshot or evidence
failure still exhausts the bounded loop without a provider dispatch.

The active-instance check protects lease acquisition and start. Once start is
durable, session or process loss must not prevent truthful result persistence
or conservative reconciliation. Result recording therefore requires the exact
lease identity and version but does not require the old process to remain
active.

`runwarden-runtime` drives this state machine without trusting a browser or
agent transition request. Approval waiting is bounded by a monotonic wall-time
deadline while durable expiry is judged by the injected trusted clock. Pending
rows are polled without creating another operation; at the exact expiry the
runtime performs the approval/operation versioned expiry CAS. Reviewer denial,
expiry, and timeout all return the same operation id without an executor call.

The reviewer HTTP boundary calls `StateStore::decide_active_approval`, not the
runtime invoke path. That entry point checks the singleton active story/session
inside the same immediate transaction as binding, expiry, and both entity
versions. No active context conflicts, and a valid approval id from another
story is returned as not found. A successful decision returns the updated
approval and operation from that transaction; it does not acquire a lease or
cross the execution-start boundary.

Reviewer operation reads load the display-safe operation and approval CAS
version from one deferred, evidence-verified snapshot. Supported canonical
major-1 story versions remain readable, while every current story mutation and
event/replay-frame append requires `SchemaVersion::current()`; this binary does
not mint evidence under a future minor version.

Before leasing or resuming, the runtime reloads private arguments and
authoritatively re-extracts the typed claim, safe projection, canonical
argument hash, provider contract hash, policy snapshot, and conservative
budget charge. Every value must equal the frozen journal operation. A live
pre-start lease is reusable only by its exact process owner; a foreign owner
conflicts, and an expired unstarted lease is version-released before any new
reservation. Only persisted `Allowed` in enforced mode or the exact approved
record can acquire a lease. Monitor-only operations never reach this path.

After the durable start CAS, provider results are validated against the lease
reservation and mapped conservatively: completed results become `Completed`;
proven pre-effect failures become `Failed`; executed errors remain executed
failures; running, simulated, invalid, or uncertain results become
`OutcomeUnknown`. If the result write fails, the runtime attempts the exact
lease/version unknown-outcome CAS and always returns a post-execution error,
never an unverified success response. Cleanup is committed only after a
terminal journal state; otherwise its opaque token is retained for bound
reconciliation. A cleanup failure after a terminal commit is surfaced as the
structured `CleanupAfterCommit` runtime alert and never rewrites the truthful
operation result. If a result commit response is lost while cleanup also
fails, `JournalAndCleanupAfterExecution` reports both failures without
overwriting the durable terminal result.

## Crash recovery

Recovery never calls or retries a provider.

Runtime reconciliation is allowed only for an expired `Executing` snapshot.
It rebuilds the exact frozen request and passes it to the executor's read-only
evidence reconciler. Live executions remain `Executing`; terminal operations
are returned without a second operation, approval, lease, permit, or provider
call.

- An expired `ExecutionLeased` operation with no start event may be released by
  exact operation-version and lease-id CAS. Its reservation becomes
  `Released`, retained under the original lease id, and reserved counters are
  decremented without advancing committed counters. A direct allow returns to
  `PolicyEvaluated`. A reviewed approval returns to `Approved` only if its
  original expiry is still live; otherwise both approval and operation become
  `Expired` and the side effect remains blocked.
- `recovery_candidates(now)` returns only expired `Executing` operations with
  exactly one verified start event. Each candidate contains only operation id
  and version plus lease id, owner, and expiry, ordered by expiry and operation
  id. Discovery is read-only and does not expose arguments or instance-token
  material. It may still identify a structurally valid frozen story for
  operator visibility; candidate discovery does not itself authorize a write.
- If reconciliation cannot prove a durable provider result,
  `mark_outcome_unknown` uses exact operation-version, lease-id, and owner CAS.
  It may run immediately after result persistence fails; lease expiry is not a
  prerequisite. It commits the full reservation, records no output, leaves a
  consumed approval consumed, and atomically sets operation, provider result,
  and side-effect state to `OutcomeUnknown` with a bounded stable reason code.

Every recovery write verifies the complete event/frame chain and permits only
native stories whose evidence remains `Pending`. It then mutates budget,
approval, and operation rows and appends one typed `ProviderExecution` event
and replay frame in the same transaction. A stale candidate loses to a
concurrently committed provider result; partial budget, approval, operation,
event, or frame state is rolled back.

## Verified JSONL compatibility

`export_legacy_jsonl(story_id)` is a read-only compatibility encoder. In one
consistent transaction it loads and verifies the entire native
`StoryEvidenceView`, then emits every canonical `StoryEvent` as one compact
UTF-8 JSON object followed by `\n`. An empty event chain produces empty bytes.
The API returns `Vec<u8>` and deliberately accepts no output path.

This stream is not the retained MCP `.runwarden/events.jsonl` compatibility
format. The latter contains legacy provider envelopes and `TraceEvent` values
and remains a read-only report-lint evidence source. `.runwarden/approvals` is
also compatibility data and is no longer used by the live reviewer console or
production MCP. Neither filesystem surface acquires native journal authority
merely because a native compatibility export exists. The live boundary is
specified in [Reviewer HTTP and SSE API](reviewer-http-sse-api.md).
