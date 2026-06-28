# Provider Model

Providers are the only callable tool surface. First-party providers are implemented by Runwarden. Demo and external providers represent filesystem, browser, email, API, memory, knowledge, and downstream MCP capabilities behind kernel mediation.

## First-Party Catalog

- `runwarden.input.inspect`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

## Demo And External Catalog

- `external.mcp.browser.open_page`
- `external.mcp.filesystem.read_file`
- `external.mcp.filesystem.write_file`
- `external.email.send`
- `external.api.request`
- `external.memory.read`
- `external.memory.write`
- `external.knowledge.read`
- `external.knowledge.write`

High-risk, network-active, file-writing, credential, destructive, report-claim, and artifact-writing providers require approval before trusted side effects.
