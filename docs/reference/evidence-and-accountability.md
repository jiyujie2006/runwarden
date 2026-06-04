# Evidence and Accountability

Every meaningful Runwarden decision should be traceable to an observation id.
Reports are accepted only when claims cite `obs_*` references that exist in the
verified trace and support the claim semantics.

## Observation Semantics

Provider policy observation ids are derived from pre-side-effect decision
material:

- trace event type
- decision
- session id
- provider
- action
- argument hash
- gate
- reason
- error kind
- authz id
- actor id
- approval id

Repeated provider calls with different sessions or arguments therefore produce
different `obs_*` ids even when the policy decision is the same.

## Report Claims

A claim that says a provider completed must cite a completed or allowed
observation. This completed semantic is checked before denial keywords, so text
such as "completed and was not denied" does not require a denial observation.

A claim that says a provider was denied, blocked, or rejected must cite an
observation with matching event type or decision payload.

Report claims may include an optional `support` object with explicit expected
trace fields:

- `provider`
- `event_type`
- `decision`
- `execution_status`
- `side_effect_executed`

When present, lint validates those fields against the verified cited event.
Claims without structured support use text semantics only when the text
positively states completed, allowed, denied, blocked, or rejected behavior.
Unstructured neutral text is rejected even when it cites an existing `obs_*`
reference.

## Accountability Summary

Accountability summaries preserve:

- requester or actor id
- authorization id
- approval id
- reviewer
- report claim id
- side-effect state

Denials must state `side_effect_executed: false` unless a lower-level failure
happened after execution began.
