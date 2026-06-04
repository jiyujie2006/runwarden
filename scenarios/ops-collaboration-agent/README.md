# Ops Collaboration Agent Scenario

This scenario validates multi-actor accountability and review gates for
credential-use operations.

## Manifest Scope

`manifests/assessment.toml` defines an offline assessment with:

- allowed providers:
  - `runwarden.input.inspect`
  - `runwarden.accountability.summary`
  - `external.enterprise.ticket_lookup`
- actor `agent-ops`
- active authz `authz-ops`
- active assessment enabled

## Expected Behavior

The golden corpus expects `external.enterprise.ticket_lookup` to require review
and deny execution without a valid approval because it represents credential
use.

Primary expected observation:

- `obs_ops_collaboration_agent_1`

## Validate

```bash
runwarden eval scenarios --json
```
