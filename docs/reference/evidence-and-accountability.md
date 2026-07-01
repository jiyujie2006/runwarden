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
`completed` claim requires a completed event type or
`execution_status=completed`; an `allowed` claim can be supported by an
allowed/completed decision.

Denied, blocked, rejected, and review-blocked text claims without structured
support pass only when the cited trace payload states
`side_effect_executed=false`. If a claim needs different semantics, it must use
structured support that explicitly matches the trace fields.
Simulated replay observations must state `simulated=true` in structured
support; they do not support plain completed or allowed claims for trusted
external side effects.

Scenario replay trace payloads include the provider call arguments that led to
the cited decision so judges can inspect the attempted target without executing
the provider.

LLM proxy model-call traces are written as sealed JSONL `TraceEvent` records.
Each line includes `previous_hash` and `event_hash`; CLI trace verification
accepts this JSONL form and rejects malformed or unsigned legacy lines.
