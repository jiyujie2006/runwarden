# Government Office Assistant Scenario

This scenario validates accountability and data-class controls for
public-sector assistant workflows.

## Manifest Scope

`manifests/assessment.toml` defines an offline assessment with:

- allowed providers:
  - `runwarden.input.inspect`
  - `runwarden.report.lint`
  - `external.api.request`
- actor `agent-government`
- active authz `authz-government`
- active assessment enabled

## Expected Behavior

The golden corpus expects `external.api.request` to deny an unapproved
government data endpoint with `egress_denied`. It also expects input inspection
to complete through the Runwarden boundary.

Primary expected observation:

- `obs_government_office_assistant_1`

## Validate

```bash
runwarden eval scenarios --json
```
