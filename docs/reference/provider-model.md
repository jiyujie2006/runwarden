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

In contest replay, external providers are simulated after Rust policy allows
the call. The simulation result is still emitted as provider evidence, but
`event_type=provider_simulated_replay`, `execution_status=simulated`,
`simulated=true`, and `side_effect_executed=false` mean no trusted external
effect was performed.
Review-blocked and denied external providers also report
`side_effect_executed=false`.
