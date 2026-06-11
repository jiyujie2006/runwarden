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

Provider calls submitted through the CLI, Local API, and `runwarden-mcp` are
mediated by the Runwarden platform executor. The executor appends a
`provider_call_requested` event before policy evaluation, applies
session-derived or surface-default kernel policy, writes
completion/denial/review events, and persists a provider-call record under the
surface platform root at `.runwarden/provider-calls/`.

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
When such a call lacks a usable matching approval, the platform executor returns
`requires_review`, writes or returns a pending approval record, and preserves
`side_effect_executed: false`.

Provider adapters that reject an approved call must return provider-shaped
denial output so the executor records the public error kind instead of collapsing
the failure to `internal`. For example, `runwarden.report.render` citation
failures are recorded as `report_citation_invalid` with execution status
`failed`, and `runwarden.eval.agent-native` inline `agent_configs` must contain
at least one well-formed case or fail with `argument_schema_invalid`.
