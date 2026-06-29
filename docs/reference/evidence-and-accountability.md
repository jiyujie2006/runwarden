# Evidence and Accountability

Every meaningful Runwarden decision should be traceable to an observation id. Contest reports are accepted only when claims cite `obs_*` references that exist in the verified trace and support the claim semantics.

## Claim Support

Report claims may include structured support:

- `provider`
- `event_type`
- `decision`
- `execution_status`
- `side_effect_executed`
- `simulated`

When present, lint validates those fields against the cited trace event. Claims without structured support use text semantics only for clearly completed, allowed, denied, blocked, or rejected behavior.

Denied and review-blocked side-effect-capable operations must state `side_effect_executed=false`.
Simulated replay observations must state `simulated=true` in structured
support; they do not support plain completed or allowed claims for trusted
external side effects.

Scenario replay trace payloads include the provider call arguments that led to
the cited decision so judges can inspect the attempted target without executing
the provider.
