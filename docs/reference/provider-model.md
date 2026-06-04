# Provider Model

Providers are the only callable tools visible to agents. First-party providers
are implemented by Runwarden; external providers are described by manifests and
executed only through mediated adapters.

## Provider Record

Provider records define:

- `provider_id`
- `provider_class`
- `kind`
- `risk`
- `side_effects`
- schema pin
- evidence contract
- authority requirements

Runtime dispatch must use provider registry metadata. `provider_class` selects
first-party versus external execution, and `kind` selects the mediated adapter
family such as `mcp`, `api`, `scanner`, or `shell`.

String family prefixes such as `external.mcp.*` are descriptive naming
conventions, not the source of truth for execution.

## First-Party Providers

The checked-in first-party catalog includes:

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

The checked-in external provider catalog includes:

- `external.mcp.browser.open_page`
- `external.mcp.filesystem.read_file`
- `external.api.request`
- `external.scanner.run`
- `external.shell.command`
- `external.plugin.security_scan`
- `external.skill.assessment_helper`
- `external.enterprise.ticket_lookup`

High-risk, network-active, credential, destructive, report-claim, and
artifact-writing providers require approval before trusted side effects.
