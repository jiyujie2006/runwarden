# Provider Manifest

Provider manifests describe external providers and bind identity, transport,
permissions, egress policy, side effects, risk, and schema pins.

The checked schema is `schemas/provider-manifest.schema.json`.

## Requirements

External provider manifests must:

- set `provider_class = external`
- use a `provider_id` that starts with `external.`
- declare provider kind and transport
- declare downstream identity and tool identity
- declare permissions and egress origins
- use a SHA-256 schema pin
- match the observed schema digest to the pinned schema

External provider dispatch uses manifest and registry `provider_class` plus
`kind`, not provider id family prefixes.

## MCP Transport Rules

Recognized MCP contract shapes are `stdio`, `http`, and `sse`. There is no
adapter request object and no caller-supplied transport: transport, command,
working root, origins, permissions, and schema pin are part of the canonical
catalog contract and execution-permit hash. Manifests without an explicit
transport are denied during static validation.

`https` MCP manifests are not certified until a trusted TLS adapter exists.
HTTP and SSE static validation accepts only canonical `http://` origin shapes,
but both transports return `network_adapter_not_enabled`; no socket is opened.

Stdio MCP manifests cannot require egress or credential controls:
network-active risk, `network` or `credential_use` side effects, or non-empty
`allowed_origins` fail certification with
`stdio_egress_controls_unsupported`; native registration rejects the catalog's
network-capable stdio browser before spawn.

Stdio has no request argument-vector, command, cwd, or environment surface.
Static validation requires one bare command equal to downstream identity,
`working_root="."`, and an executable non-symlink regular file directly below
the trusted runtime root. Because an enabled stdio transport would create a
process independently of the business effect, the manifest must also declare
both the `process_spawn` permission and `ProcessSpawn` side effect.

Stdio registration currently ends with `stdio_isolation_unavailable`, even
after all static checks pass. Process-group cleanup is insufficient against a
compromised process that daemonizes or ignores typed claims. Execution remains
disabled until mandatory OS filesystem/network/syscall isolation and a
resource owner for the whole process tree are installed.

`load_provider_manifest` and `certify_external_provider_manifest` are read-only
lint surfaces. A passing certification report is not registration or execution
authority. Only the default executor owns the crate-private transport entry,
and the current transport admission checks all fail closed.

## Contest Checks

Manifest contracts are exercised through provider catalog tests, kernel policy
tests, and scenario/demo execution:

```bash
cargo test --workspace
target/debug/runwarden check --strict --json
```
