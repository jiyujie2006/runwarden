# First Scenario

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

Run `runwarden eval scenarios --json` to validate the checked-in scenario golden corpora.
