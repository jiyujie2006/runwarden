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

MCP transports supported by the local adapter are `stdio`, `http`, and `sse`.
Execution uses the manifest transport. If a request includes `transport`, it
must exactly match the manifest transport. Manifests without an explicit
transport are denied before adapter execution.

`https` MCP manifests are not certified by the local adapter until a trusted
HTTPS client adapter exists. HTTP and SSE execution currently accept only
`http://` adapter URLs, still requiring exact origin allowlisting and
private/local resolution denial before connecting.

Stdio MCP manifests cannot require egress or credential controls:
network-active risk, `network` or `credential_use` side effects, or non-empty
`allowed_origins` fail certification with
`stdio_egress_controls_unsupported` and execution returns `egress_denied`
before spawn.

Stdio MCP adapter requests cannot supply command arguments. Fixed adapter
arguments must live inside a dedicated trusted wrapper or manifest-owned
executable so allowlisted commands cannot be redirected outside the trusted
runtime root.

Stdio execution is only allowed on platforms where Runwarden can clean up the
adapter process tree.

Adapter execution receives an already-loaded `ProviderManifest`;
`manifest_path` on `ExternalMcpAdapterRequest` is not resolved by the local
executor and is not part of scoped-root, approval, or digest binding today.

## Contest Checks

Manifest contracts are exercised through provider catalog tests, kernel policy
tests, and scenario/demo execution:

```bash
cargo test --workspace
target/debug/runwarden check --strict --json
```
