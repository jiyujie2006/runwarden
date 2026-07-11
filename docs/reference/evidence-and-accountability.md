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

Scenario replay trace payloads include the provider call arguments that led to
the cited decision so judges can inspect the attempted target without executing
the provider.

LLM proxy model-call traces are written as sealed JSONL `TraceEvent` records.
Each line includes `previous_hash` and `event_hash`; CLI trace verification
accepts this JSONL form and rejects malformed or unsigned legacy lines.

MCP report lint uses the server-owned provider-call trace store, not inline
trace events supplied by an agent. Provider-call events are read from
`RUNWARDEN_STATE_DIR/events.jsonl` when configured, otherwise from
`.runwarden/events.jsonl` relative to the MCP process.
