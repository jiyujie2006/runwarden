# Provider Examples

Example provider manifests live here. Every external provider must declare risk,
side effects, schemas, authority requirements, and evidence contract.

Checked-in examples:

- `external.mcp.browser.open_page.json`: external MCP browser tool manifest.
- `kernel.toml`: example kernel/provider catalog configuration.

The provider registry currently exposes these mediated provider IDs:

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
- `external.mcp.browser.open_page`
- `external.mcp.filesystem.read_file`
- `external.mcp.api.request`
- `external.mcp.scanner.run`
- `external.shell.command`
- `external.plugin.security_scan`
- `external.skill.assessment_helper`
- `external.enterprise.ticket_lookup`
