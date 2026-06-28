# First Scenario

A scenario is a reproducible golden-corpus fixture for one attack chain.

## Folder Contract

- `README.md`
- `manifests/assessment.toml`
- `benign/request.md`
- `attacks/prompt-injection.md`
- `agent/script.json`
- `expected/provider-calls.json`
- `expected/denials.json`
- `expected/obs-refs.json`
- `expected/report.json`
- `expected/eval-baseline.json`

## Main Scenarios

- `prompt-injection-file-exfil`
- `tool-hijack-email-api`
- `memory-knowledge-poisoning`
- `environment-local-web-risk`

Validate with:

```bash
runwarden eval scenarios --json
```
