# Contest Gate Installation

The contest edition does not publish a Local API, SDK, or release artifact
bundle. The retained local verification entry point is:

```bash
bash scripts/release_gate_local.sh
```

## Named Binaries

- `runwarden`
- `runwarden-mcp`
- `runwarden-kernel`

## Generated Review Outputs

The local contest gate may write:

- deterministic demo artifacts under `artifacts/demo/`
- a Markdown report under `artifacts/reports/contest-report.md`
- static reviewer console HTML at `artifacts/reviewer-console.html`

These outputs are review evidence, not installable product artifacts.
