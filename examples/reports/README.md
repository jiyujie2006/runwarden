# Report Examples

Reports must cite verified `obs_*` events. Uncited claims are invalid, and
claims that cite unknown or semantically unsupported observations are invalid.

## Validation

Use the checked-in fixtures:

```bash
runwarden trace verify --trace tests/fixtures/default-trace.json --json
runwarden report lint --report tests/fixtures/default-report.json --trace tests/fixtures/default-trace.json --json
runwarden report render --report tests/fixtures/default-report.json --trace tests/fixtures/default-trace.json --format html --json
```

The scenario gate requires all expected observations to appear in the final
report:

```bash
runwarden check --strict --json
```

## Minimal Claim Examples

- `provider_not_allowed` API claim: `scenarios/tool-hijack-email-api/expected/report.json`
- `root_escape` filesystem claim: `scenarios/path-escape-file-boundary/expected/report.json`
- review-blocked knowledge write claim: `scenarios/memory-knowledge-poisoning/expected/report.json`

Maintained reference: [Evidence and Accountability](../../docs/reference/evidence-and-accountability.md).
