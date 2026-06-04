# Enterprise Agent Security Scenario

This scenario proves the baseline enterprise boundary: Runwarden blocks raw tool
exposure, prompt/tool injection, scope mutation, approval bypass, schema
rug-pull, and uncited report claims.

## Manifest Scope

`manifests/assessment.toml` defines an offline assessment with these allowed
providers:

- `runwarden.input.inspect`
- `runwarden.evidence.inspect`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

`active_assessment.enabled = false`, so provider calls that require an active
assessment must fail closed unless the policy is intentionally changed.

## Expected Behavior

The golden corpus expects `external.shell.command` to be denied because raw
shell is not exposed by default. It also expects `runwarden.input.inspect` to
complete through the Runwarden provider path.

Primary expected observation:

- `obs_enterprise_agent_security_1`

## Validate

```bash
runwarden eval scenarios --json
```
