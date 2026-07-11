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

Native provider execution occurs only after the Rust policy, durable lease,
execution-start, and authenticated permit gates allow it. API and browser
providers remain simulated at that boundary; `execution_status=simulated` and
`side_effect_executed=false` mean no trusted external effect was performed.
The legacy scenario and MCP adapters do not currently reach this boundary and
therefore block external execution as described below.

The native executor implements bounded local filesystem, email, memory, and
knowledge effects after an authenticated execution permit. Filesystem output
is byte/hash metadata, email output is an immutable receipt hash, and store
output is a key hash plus version; sensitive plaintext is not copied into
provider evidence. Memory and knowledge reads declare `FileRead` because their
bounded local backing files consume the file-byte reservation. API and browser
remain typed simulations and never open a socket. Review-blocked and denied
operations always remain pre-effect.

At trusted executor construction time, an operator may offer an exact
catalogued external MCP manifest to the consuming registration API.
Registration is not agent-controlled and cannot add a provider: the complete
manifest-derived contract must equal the Rust catalog contract, and the
execution permit binds transport, permissions, origin allowlist, command
allowlist, working root, and schema pin as well as
provider/action/arguments/claim/budget. In the current build, registration
then fails closed for every transport. File-only stdio reports
`stdio_isolation_unavailable`; network-capable stdio is rejected; HTTP/SSE are
not enabled. This preserves the single executor boundary without granting a
compromised downstream process ambient Runwarden privileges. API and browser
calls remain non-networking simulations.

The compatibility MCP and CLI paths do not yet mint native permits. They now
return `native_executor_required`, `execution_status=not_executed`, and
`side_effect_executed=false` for external providers instead of calling a
legacy local dispatcher. Plan 4 connects durable policy, approval, lease,
execution-start, permit issuance, executor dispatch, and result persistence as
one operation.

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

`runwarden-providers::project_safe_arguments` is the shared Rust projection
used before durable proposal storage. It copies only typed non-secret claim
metadata and replaces file content, email subject/body, network body, store
key/value, and code source with SHA-256 digests. Claim/argument confusion and
opaque legacy claims fail instead of falling back to raw JSON. Runtime, MCP,
and browser code must not recreate this redaction mapping.
