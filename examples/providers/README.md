# Provider Examples

Example provider manifests live here. Every external provider must declare risk,
side effects, schemas, authority requirements, and evidence contract before it
can be used behind the Runwarden boundary.

## Checked-In Examples

- `external.mcp.browser.open_page.json`: external MCP browser tool manifest.
- `kernel.toml`: example kernel/provider catalog configuration.

Validate provider behavior through the active contest checks:

```bash
cargo test --workspace
target/debug/runwarden check --strict --json
```

## First-Party Provider Catalog

The contest provider registry exposes these first-party provider IDs:

- `runwarden.input.inspect`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

## External And Demo Provider Families

The contest catalog models these mediated external/demo provider families:

- `external.mcp.browser.open_page`
- `external.mcp.filesystem.read_file`
- `external.mcp.filesystem.write_file`
- `external.email.send`
- `external.api.request`
- `external.memory.read`
- `external.memory.write`
- `external.knowledge.read`
- `external.knowledge.write`

External provider execution is selected from registry metadata and manifest
fields. Do not use provider id prefixes as the source of truth for dispatch.

Maintained references:

- [Provider Model](../../docs/reference/provider-model.md)
- [Provider Manifest](../../docs/reference/provider-manifest.md)
- [Provider Integration](../../docs/reference/provider-integration.md)
