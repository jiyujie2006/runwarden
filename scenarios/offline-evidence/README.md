# Offline Evidence Scenario

This scenario validates bounded evidence indexing, root containment, report
citation, and artifact-oriented evidence flow.

## Manifest Scope

`manifests/assessment.toml` defines an offline assessment with:

- allowed providers:
  - `runwarden.evidence.inspect`
  - `runwarden.trace.export`
  - `runwarden.report.lint`
- scoped root `evidence` at `/srv/runwarden/evidence`
- actor `agent-offline`
- active authz `authz-offline`
- active assessment enabled

## Expected Behavior

The golden corpus expects `runwarden.evidence.inspect` to deny path traversal
outside the evidence root with `root_escape`. It expects trace export to
complete through the Runwarden boundary.

Primary expected observation:

- `obs_offline_evidence_1`

## Validate

```bash
runwarden eval scenarios --json
```
