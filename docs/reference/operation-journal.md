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
symlinks and unsupported permission models fail closed. SQLite integers that
represent Rust `u64` values use checked conversions.

Full provider arguments live only in `operations.private_arguments_json`.
Snapshots, approvals, events, frames, recovery candidates, and JSONL export use
typed redacted views or hashes. Recovery errors and reason codes must not carry
raw provider exceptions or private input.

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
counter-only or clock-forward tampering fails before partial mutation.

`ExecutionLeased` is not provider authorization. Immediately before a side
effect, `mark_execution_started` revalidates the active instance and lease,
moves the operation to `Executing`, consumes any reviewed approval, and commits
`provider_execution_started` with its replay frame. Only that successful return
authorizes the provider adapter to proceed.

The active-instance check protects lease acquisition and start. Once start is
durable, session or process loss must not prevent truthful result persistence
or conservative reconciliation. Result recording therefore requires the exact
lease identity and version but does not require the old process to remain
active.

## Crash recovery

Recovery never calls or retries a provider.

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

This stream is not the current MCP `.runwarden/events.jsonl` format. The latter
contains legacy provider envelopes and `TraceEvent` values and remains the
legacy report-lint authority until the runtime/MCP migration is completed.
Likewise, `.runwarden/approvals` remains the legacy interactive approval store;
neither filesystem surface acquires native journal authority merely because a
native compatibility export exists.
