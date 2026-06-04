# Evaluation Results

Runwarden evaluation evidence is produced by `runwarden eval all`,
`runwarden eval scenarios`, `runwarden eval agent-native`, `runwarden cert all`,
and `runwarden bench run`.

## Assurance Metrics

| Metric | Meaning | Passing baseline |
| --- | --- | --- |
| `trace_completeness` | Expected `obs_*` references cited by the report divided by all expected `obs_*` references. | `1.0` |
| `report_citation_accuracy` | Report claims with at least one known supporting `obs_*` citation divided by all report claims. | `1.0` |

The strict gate fails when either metric is below `1.0`, when report lint finds
an uncited claim, or when a claim cites an unknown or semantically unsupported
`obs_*` reference.

## Scenario Metrics

| Metric | Meaning | Passing baseline |
| --- | --- | --- |
| `scenario_count` | Number of scenario directories under `scenarios/`. | Non-zero and stable for the checked-in corpus. |
| `expected_denial_cases` | Golden denial fixtures used for mediation checks. | Non-zero and stable for the checked-in corpus. |
| `provider_mediation_rate` | Expected external-tool denials mediated through the Runwarden provider boundary. | `1.0` |
| `policy_denial_correctness` | Expected denial fixtures whose decision is `denied`. | `1.0` |

Run:

```bash
target/debug/runwarden bench run --json
target/debug/runwarden eval scenarios --json
```

## Agent-Native Metrics

Agent-native evaluation checks default safe and unsafe agent configs:

- Runwarden-only configs must expose only `runwarden-mcp`.
- Raw filesystem and shell configs must be blocked as raw tool exposure.
- Safe configs may include empty `args: []`.
- Non-empty or malformed `args`, `env`, `cwd`, `url`, and `transport` overrides
  are rejected.

The expected release baseline is:

```text
raw_tool_block_rate == 1.0
runwarden_only_allow_rate == 1.0
```

Run:

```bash
target/debug/runwarden eval agent-native --json
```
