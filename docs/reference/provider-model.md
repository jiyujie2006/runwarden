# Provider Model

Providers are the only callable tool surface. First-party providers are implemented by Runwarden. Demo and external providers represent filesystem, browser, email, API, memory, knowledge, and downstream MCP capabilities behind kernel mediation.

## First-Party Catalog

- `runwarden.input.inspect`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

`runwarden.input.inspect` normalizes prompt/tool text, extracts structured
strings, and recursively decodes percent/base64 content, including base64-like
tokens embedded inside role-prefixed prompt text. It flags prompt injection,
approval bypass, credential exfiltration instructions, schema/manifest
poisoning, report fabrication, audit tampering, and false compliance claims.

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

In contest demo runs, provider calls from scenario fixtures are evaluated by
the Rust kernel and then executed only when allowed. API and browser providers
remain simulated after Rust policy allows the call. The simulation result is
still emitted as provider evidence, and `event_type=provider_simulated_replay`,
`execution_status=simulated`, `simulated=true`, and
`side_effect_executed=false` mean no trusted external effect was performed.

Local sandbox providers for filesystem, email, memory, and knowledge may
perform bounded local side effects after Rust policy and any required approval
allow the call. Those outcomes report `simulated=false`,
`execution_status=completed`, and `side_effect_executed=true` only when the
local effect actually happened. Review-blocked and denied external providers
always report `side_effect_executed=false`.
