# Evaluation Results

Evaluation baselines and release evidence are produced by `runwarden eval all`,
`runwarden eval agent-native`, `runwarden cert all`, and `runwarden bench run`.

Implemented assurance metrics:

- `trace_completeness`: expected `obs_*` references cited by the report divided
  by all expected `obs_*` references.
- `report_citation_accuracy`: report claims with at least one known `obs_*`
  citation divided by all report claims.

The strict gate fails when either metric is below `1.0`, or when report lint
finds an uncited claim or an unknown `obs_*` reference.

Implemented benchmark metrics:

- `scenario_count`: number of scenario directories under `scenarios/`.
- `expected_denial_cases`: expected denial fixtures used for provider mediation.
- `provider_mediation_rate`: expected external-tool denials that are mediated
  through the Runwarden provider boundary.
- `policy_denial_correctness`: expected-denial fixtures whose decision is
  `denied`.

Current release baseline:

```bash
target/debug/runwarden bench run --json
```

The expected baseline is `provider_mediation_rate == 1.0` and
`policy_denial_correctness == 1.0`.

Agent-native evaluation checks the default safe and unsafe agent configs:

- runwarden-only configs must expose only `runwarden-mcp`.
- unsafe raw filesystem/shell configs must be blocked as raw tool exposure.
- release baseline expects `raw_tool_block_rate == 1.0` and
  `runwarden_only_allow_rate == 1.0`.
