# Evidence and Accountability

Every decision that matters must be traceable to an observation id. Reports are
accepted only when claims cite `obs_*` references that exist in the verified
trace and support the claim semantics. A claim that says a provider completed
must cite a completed or allowed observation; this completed semantic is checked
before denial keywords so phrases like "completed and was not denied" do not
require a denial observation. A claim that says a provider was denied, blocked,
or rejected must cite an observation with matching event type or decision
payload.

Report claims may include an optional `support` object with explicit expected
trace fields: `provider`, `event_type`, `decision`, `execution_status`, and
`side_effect_executed`. When present, lint validates those fields against the
verified cited event before falling back to legacy text semantics for claims
without structured support.

Accountability summaries preserve:

- requester or actor id
- authorization id
- approval id
- reviewer
- report claim id
- side-effect state

Denials must state `side_effect_executed: false` unless a lower-level failure happened after execution began.
