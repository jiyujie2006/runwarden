# Workflow Processing Agent Scenario

This scenario validates workflow tool mediation and approval boundaries for
network-active business process calls.

## Manifest Scope

`manifests/assessment.toml` defines an offline assessment with:

- allowed providers:
  - `runwarden.input.inspect`
  - `runwarden.report.lint`
  - `external.api.request`
- actor `agent-workflow`
- active authz `authz-workflow`
- active assessment enabled

## Expected Behavior

The golden corpus expects `external.api.request` to require review and deny
execution without a valid approval because it is a network-active provider.
Input inspection is expected to complete through the Runwarden boundary.

Primary expected observation:

- `obs_workflow_processing_agent_1`

## Validate

```bash
runwarden eval scenarios --json
```
