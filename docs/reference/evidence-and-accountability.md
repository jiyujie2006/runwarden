# Evidence and Accountability

Every meaningful Runwarden decision should be traceable to an observation id.
Contest reports are accepted only when claims cite references that start with
`obs_`, exist in the verified trace, and support the claim semantics.

## Claim Support

Report claims may include structured support:

- `provider`
- `event_type`
- `decision`
- `execution_status`
- `side_effect_executed`
- `simulated`

When present, lint validates those fields against the cited trace event. Claims
without structured support use text semantics only for clearly completed,
allowed, denied, blocked, rejected, or review-blocked behavior. A plain
`completed` claim requires the cited trace payload to state
`execution_status=completed`; the event type alone is not sufficient. An
`allowed` claim can be supported by an allowed/completed decision.

Denied, blocked, rejected, and review-blocked text claims without structured
support pass only when the cited trace payload states
`side_effect_executed=false`. If a claim needs different semantics, it must use
structured support that explicitly matches the trace fields.
Simulated replay observations must state `simulated=true` in structured
support; they do not support plain completed or allowed claims for trusted
external side effects.

The kernel's Security Story v1 contract represents each native report claim
with typed `ObservationId` references and a `ReportClaimSupport` expectation.
An observation id is `obs_` followed by a canonical lowercase, hyphenated
UUIDv7 with the RFC 4122 variant; alternate UUID spellings are rejected at the
JSON boundary.
Its optional expectation fields are `provider`, `event_kind`, `policy_decision`,
`operation_state`, `side_effect_state`, and `simulated`; at least one must be
present with a non-null value, and unknown fields are rejected. The generated
schema carries both boundaries. There is deliberately no caller-supplied
`supported` boolean. P6 adds the assurance consumer that resolves every cited
observation and computes support from verified event semantics. Until that
integration, the existing legacy assurance path consumes the legacy report
support fields listed above, not native `StoryClaim` or `ReportClaimSupport`
values.

Native story and operation views reject unknown JSON fields. A
`SecurityStory` contains the current aggregate and an event count, not copied
historical events or an embedded export signature. `StoryReplayFrame` binds the
current aggregate snapshot and frame metadata with Canonical JSON v1 hashes;
ordered sealed events and persistence remain separate trace/journal contracts.

The demo legacy adapter does not translate legacy `obs_ref` or `trace_event`
fields into native observations. Its stories have `LegacyDerived` provenance,
`Incomplete` evidence, zero native events, no final event hash, empty report
claims, and empty observation-reference lists. Passing the legacy report/trace
checks does not upgrade that native evidence status.

Full provider arguments are private operation material. A story event is built
only from its Rust allowlisted payload variant and is redacted before hashing:
argument bytes are represented only by `argument_hash`, while output and other
content are represented by their typed hashes. Raw prompts, arguments, headers,
queries, bodies, outputs, and arbitrary JSON objects cannot enter the sealed
story-event payload. The event envelope also rejects unknown fields, and hash
verification independently requires `event_type` to match the typed payload
kind so a caller cannot bless a semantic mismatch by recomputing the hash.

`StoryEvidenceView` transfers the aggregate story, ordered sealed events, and
one replay frame per event. Export verification recomputes each event from the
same canonical RFC3339 material, verifies its event and frame chains, and
requires every replay frame to retain the same unmodified event hash. Each
frame aggregate count must match its sequence, and each frame aggregate's
`final_event_hash` must match that frame's event hash. The exported story's
`final_event_hash` must be absent for an empty chain or exactly equal the last
sealed event hash. Export does not redact again or replace hashes after sealing.

## Native Approval And Execution Evidence

Native SQLite approval creation, reviewer approval or denial, and expiry each
commit exactly one `StoryEventPayload::ApprovalLifecycle` event and one replay
frame in the same transaction as the approval and operation state changes.
The allowlisted payload contains only the typed approval id and state plus an
optional SHA-256 reviewer-id commitment. Pending and expiry events omit the
reviewer commitment; approval and denial events hash the reviewer id's UTF-8
bytes. Raw reviewer reasons never enter an event payload or journal error,
although the reviewer-authored reason is visible in the display-safe
`ApprovalView` captured by replay frames.

Lease acquisition and execution start use typed `ProviderExecution` events
with stable status codes `execution_lease_acquired` and
`provider_execution_started`. The latter is the durable start-intent boundary:
an operation cannot persist a provider result without a verified matching
start event. Completion or failure records the typed provider execution status,
authoritative side-effect state, safe output hash, and an email receipt hash
when that output variant supplies one. Full provider arguments remain only in
private operation material and are absent from approvals, leases, events,
frames, and errors.

Crash recovery advances this same chain. Releasing an unstarted lease records
`execution_lease_released`, or `execution_lease_expired` when its reviewed
approval has also expired. A started execution that cannot prove a durable
provider result records `outcome_unknown`; it claims no output or receipt and
commits the complete reservation. Recovery candidate reads verify the entire
story but expose only operation/version and lease identity/expiry metadata.

Every approval, lease, start, and result mutation first verifies the existing
story evidence and then advances the story event/frame chain atomically. A
failed binding check, stale version, exhausted budget, changed active instance,
or repeated start creates no partial state or orphan event. Approval lifecycle
events carry the operation id, so their `obs_*` ids appear in that operation's
ordered observation references.

Standalone native observations use the same atomic event/frame helper through
`StateStore::append_event` while evidence is `Pending`; non-native or
non-pending stories are rejected so a verified chain head cannot drift. The
public method admits only model-call,
tool-proposal, causal-link, input-consumed, sandbox-decision, and
monitor-observation payloads; state-owning operation, policy, approval,
execution, and evidence-verification payloads must accompany their dedicated
Rust transaction. Duplicate event or observation ids conflict without opening
a sequence gap, and timestamps cannot move the story clock backwards.
Stores targeting the same journal coordinate full-chain append verification
inside one process, while SQLite `BEGIN IMMEDIATE` plus a bounded pre-input
retry remains the cross-process serialization authority. No transaction,
event, frame, or provider side effect is retried after input consumption.

Resumable `events_after` and `replay_frames` reads accept only limits from 1 to
10,000 and return rows strictly after the supplied sequence. They verify the
entire evidence view inside one read transaction before slicing the requested
page, so corruption in an earlier event, frame, snapshot, or story-version link
still fails a later-page read. Frame snapshots never embed historical event
arrays or private operation arguments.

These native journal events are the durable `runwarden-mcp` operation evidence.
They remain distinct from the legacy interactive demo's `events.jsonl` and
file-backed approval flow; documentation and contest evidence must identify
which source produced an observation rather than treating the two stores as
interchangeable.
`StateStore::export_legacy_jsonl` returns a deterministic newline-terminated
native `StoryEvent` stream only after verifying the complete story, event, and
frame chains in one transaction. It accepts no path and never reads private
operation material. Despite its compatibility name, its rows are not the
legacy MCP provider envelopes described below.

Scenario replay trace payloads include the provider call arguments that led to
the cited decision so judges can inspect the attempted target without executing
the provider.

LLM proxy model-call traces are written as sealed JSONL `TraceEvent` records.
Each line includes `previous_hash` and `event_hash`; CLI trace verification
accepts this JSONL form and rejects malformed or unsigned legacy lines.

MCP report lint temporarily uses the legacy provider-call trace store as a
read-only compatibility evidence source, not inline trace events supplied by
an agent. Provider-call events are read from
`RUNWARDEN_STATE_DIR/events.jsonl` when configured, otherwise from
`.runwarden/events.jsonl` relative to the MCP process. This file cannot approve,
lease, resume, or execute a native operation; Plan 6 moves report support to
verified native story evidence.
