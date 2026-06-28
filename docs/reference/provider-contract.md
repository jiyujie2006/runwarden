# Provider Contract

Provider contracts bind provider identity, schema pins, observed schema digest, declared risk, side effects, and enforcement requirements.

Contracts require:

- kernel mediation
- schema pins
- resource limits
- trace output
- egress policy for network-active providers
- approval gates when risk or side effects require them
- `side_effect_executed=false` for denied or review-blocked calls

External MCP contracts bind execution to the manifest transport. Request transport overrides are denied unless they match exactly.
