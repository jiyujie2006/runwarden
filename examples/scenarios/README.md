# Scenario Examples

Scenario examples show expected provider calls, denials, obs refs, and reports.
The authoritative checked-in corpus lives under `scenarios/`.

## Scenario Contract

Each scenario includes:

- `README.md`
- `manifests/assessment.toml`
- `benign/request.md`
- `attacks/prompt-injection.md`
- `agent/script.json`
- `expected/denials.json`
- `expected/provider-calls.json`
- `expected/obs-refs.json`
- `expected/report.json`
- `expected/eval-baseline.json`

Validate all scenario golden corpora:

```bash
runwarden eval scenarios --json
```

Maintained reference: [First Scenario](../../docs/reference/first-scenario.md).
