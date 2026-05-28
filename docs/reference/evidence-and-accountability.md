# Evidence and Accountability

Every decision that matters must be traceable to an observation id. Reports are
accepted only when claims cite `obs_*` references that exist in the verified
trace and support the claim semantics. A claim that says a provider was denied,
blocked, rejected, or completed must cite an observation with matching event
type or decision payload.

Accountability summaries preserve:

- requester or actor id
- authorization id
- approval id
- reviewer
- report claim id
- side-effect state

Denials must state `side_effect_executed: false` unless a lower-level failure happened after execution began.
