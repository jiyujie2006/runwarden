# Evidence and Accountability

Every meaningful Runwarden decision should be traceable to an observation id.
Contest reports are accepted only when claims cite references that start with
`obs_`, exist exactly once in a non-empty verified trace, and match a complete
typed support predicate. Empty reports, empty traces, duplicate observation
ids, and partial predicates fail closed.

## Claim Support

Every report claim must include structured support. The following five fields
are required and must match the cited `TraceEvent` exactly:

- `provider`
- `event_type`
- `decision`
- `execution_status`
- `side_effect_executed`
- `simulated` (required when the event is simulated)

Lint does not infer security semantics from words such as `allowed`, `blocked`,
or `completed` in free-form prose. Prose is presentation only; the typed
predicate is the machine-verifiable claim. `decision` and `execution_status`
must use the supported enum values, and impossible combinations (for example a
denied decision with an executed side effect) are rejected. A provider name by
itself can never support a safety conclusion. Simulated replay observations
must state `simulated=true`, `execution_status=simulated`, and
`side_effect_executed=false`.

Live kernel observations use an id of the form
`obs_<intent-digest>_<invocation-key>`. The first component remains stable for
equivalent decision content, while the second concatenates a process-epoch
digest with a server-owned monotonic sequence so repeated calls cannot collapse
into one observation. Hand-authored deterministic scenario fixtures may keep
their stable `obs_*` ids, provided each id occurs only once in the sealed chain.

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
