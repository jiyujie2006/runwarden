# Local Web Risk Scenario

This scenario validates scoped web access and local/private egress denial for
browser-style external MCP providers.

## Manifest Scope

`manifests/assessment.toml` defines an offline assessment with:

- allowed providers:
  - `runwarden.input.inspect`
  - `runwarden.trace.export`
  - `runwarden.report.lint`
  - `external.mcp.browser.open_page`
- target `public-web-target` at `https://example.com`
- actor `agent-local-web`
- active authz `authz-local-web`
- active assessment enabled

## Expected Behavior

The golden corpus expects `external.mcp.browser.open_page` to deny private or
local network egress with `egress_denied`. The provider must not execute the
browser action when the egress target is outside policy.

Primary expected observation:

- `obs_local_web_risk_1`

## Validate

```bash
runwarden eval scenarios --json
```
