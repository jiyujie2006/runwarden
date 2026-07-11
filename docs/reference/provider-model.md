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

Reviewable local-business evidence is kept in the scenario fixtures:
`tool-hijack-email-api` shows email review and API denial,
`path-escape-file-boundary` shows filesystem root escape denial, and
`memory-knowledge-poisoning` shows memory/knowledge review and denial without
network egress.

## Typed Resource Claims

The native extractor derives exactly one kernel `ResourceClaim` from an exact
provider id and action before policy evaluation. The provider-specific
extractor registry maps filesystem calls to `File`, API and browser calls to
`Network`, email to `Email`, memory and knowledge calls to `Memory`, and input
inspection to `InputInspection`. Unknown provider/action pairs fail closed;
the native path does not infer authority by searching arbitrary argument-key
names.

Runwarden-owned configuration supplies filesystem roots, memory and knowledge
namespaces, and the default data classification. Provider arguments cannot
override those values. Policy-envelope and execution-control fields, unknown
fields, missing required values, and values with the wrong JSON shape are
rejected before a claim is created.

The runtime constructor returns an authoritative extractor and a separate
kernel verifier. Only that extractor holds the process-local signing
capability. Its `extract_bound` operation performs strict extraction,
conservative Rust budget derivation, and HMAC sealing as one step. The opaque
result binds the canonical provider contract, provider id, action, complete
arguments, typed claim, reserved charge, and enforcement mode. It has no
clone, debug, or serialization surface. The ordinary `contest_default`
registry remains useful for schema tests and display projections, but cannot
mint a proof accepted by typed policy.

Canonical claims use slash-separated validated relative file paths with `.`
components removed; sorted, deduplicated email recipients with only the ASCII
domain lowercased; uppercase
HTTP methods and canonical HTTP(S) origins; non-empty store keys; and a SHA-256
commitment to inspected input bytes with the trusted `tool_input` source. A
caller-supplied input source is rejected rather than used as provenance.
Content, request bodies, URL paths and
queries, and store values remain private arguments and are additionally bound
by the execution permit's canonical argument digest. Executors must rederive
the same claim from those private arguments and require exact equality with the
permit-bound claim before any side effect.
