# Provider Examples

Example provider manifests live here. Every external provider must declare risk,
side effects, schemas, authority requirements, and evidence contract before it
can be used behind the Runwarden boundary.

## Checked-In Examples

- `external.mcp.browser.open_page.json`: external MCP browser tool manifest.
- `kernel.toml`: example kernel/provider catalog configuration.

Validate the example manifest:

```bash
runwarden cert provider-manifest --manifest examples/providers/external.mcp.browser.open_page.json --json
```

## First-Party Provider Catalog

The provider registry currently exposes these first-party provider IDs:

- `runwarden.input.inspect`
- `runwarden.evidence.inspect`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.scaffold`
- `runwarden.report.lint`
- `runwarden.report.render`
- `runwarden.audit.summary`
- `runwarden.accountability.summary`
- `runwarden.cert.all`
- `runwarden.eval.all`
- `runwarden.eval.agent-native`
- `runwarden.bench.run`

## External Provider Families

The checked-in external provider families are:

- `external.mcp.browser.open_page`
- `external.mcp.filesystem.read_file`
- `external.api.request`
- `external.scanner.run`
- `external.shell.command`
- `external.plugin.security_scan`
- `external.skill.assessment_helper`
- `external.enterprise.ticket_lookup`

External provider execution is selected from registry metadata and manifest
fields. Do not use provider id prefixes as the source of truth for dispatch.

Maintained references:

- [Provider Model](../../docs/reference/provider-model.md)
- [Provider Manifest](../../docs/reference/provider-manifest.md)
- [Provider Integration](../../docs/reference/provider-integration.md)
