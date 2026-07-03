# First Scenario

A scenario is a reproducible golden-corpus fixture for one attack chain.

## Folder Contract

- `README.md`
- `manifests/assessment.toml`
- `benign/request.md`
- `attacks/<scenario-name>.md` (e.g. `attacks/path-escape.md`)
- `agent/script.json`
- `expected/provider-calls.json`
- `expected/denials.json`
- `expected/obs-refs.json`
- `expected/report.json`
- `expected/eval-baseline.json`

`expected/provider-calls.json` records the scripted provider, action,
decision, execution status, side-effect state, `obs_ref`, reason, and replay
arguments. `expected/report.json` must cite the matching `obs_*` refs.

## Main Scenarios

- `prompt-injection-file-exfil`
- `tool-hijack-email-api`
- `memory-knowledge-poisoning`
- `environment-local-web-risk`
- `path-escape-file-boundary`

Additional scenario experiments belong under `examples/scenarios/` until they
are intentionally promoted. The contest bundle includes only the five main
scenarios above.

Validate with:

```bash
runwarden check --strict --json
runwarden demo --scenario prompt-injection-file-exfil --output artifacts/demo/prompt-injection-file-exfil --json
```
