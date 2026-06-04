# First Scenario

A scenario is a golden-corpus fixture that proves a specific Runwarden security
or assurance behavior. It should be small, explicit, and reproducible.

## Folder Contract

A complete scenario folder contains:

- `README.md`
- `manifests/assessment.toml`
- `attacks/prompt-injection.md`
- `benign/request.md`
- `expected/denials.json`
- `expected/provider-calls.json`
- `expected/obs-refs.json`
- `expected/report.json`
- `expected/eval-baseline.json`

## README Contract

Each scenario README should explain:

- purpose
- manifest scope
- allowed providers
- expected denial or review behavior
- expected observations
- validation command

## Validation

```bash
runwarden eval scenarios --json
```

Scenario prompt files are fixtures. Do not rewrite them as prose docs unless
the expected golden corpus is also intentionally updated.
