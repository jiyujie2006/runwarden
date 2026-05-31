# Evidence and Accountability

Every decision that matters must be traceable to an observation id. Reports are
accepted only when claims cite `obs_*` references that exist in the verified
trace and support the claim semantics. A claim that says a provider completed
must cite a completed or allowed observation; this completed semantic is checked
before denial keywords so phrases like "completed and was not denied" do not
require a denial observation. A claim that says a provider was denied, blocked,
or rejected must cite an observation with matching event type or decision
payload.

Provider policy observation ids are derived from the pre-side-effect decision
material, including the trace event type, decision, session id, provider,
action, argument hash, gate, reason, error kind, authz id, actor id, and
approval id. Repeated provider calls with different sessions or arguments
therefore produce different `obs_*` ids even when the policy decision is the
same.

Report claims may include an optional `support` object with explicit expected
trace fields: `provider`, `event_type`, `decision`, `execution_status`, and
`side_effect_executed`. When present, lint validates those fields against the
verified cited event. Claims without structured support use legacy text
semantics only when the text positively states completed/allowed or
denied/blocked/rejected behavior that the cited event supports. Unstructured
neutral text is rejected even when it cites an existing `obs_*` reference.

Accountability summaries preserve:

- requester or actor id
- authorization id
- approval id
- reviewer
- report claim id
- side-effect state

Denials must state `side_effect_executed: false` unless a lower-level failure happened after execution began.
