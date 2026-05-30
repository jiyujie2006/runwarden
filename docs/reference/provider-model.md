# Provider Model

Providers are the only callable tools visible to agents. First-party providers are implemented in Runwarden, while external providers are described by manifests and executed only through mediated adapters.

Provider records define:

- `provider_id`
- `provider_class`
- `kind`
- `risk`
- `side_effects`
- schema pin
- evidence contract
- authority requirements

The `external.` provider id prefix is the external-provider namespace used by
manifest certification. Runtime dispatch must use provider registry metadata:
`provider_class` selects first-party versus external execution, and `kind`
selects the mediated adapter family such as `mcp`, `api`, `scanner`, or
`shell`. String family prefixes such as `external.mcp.*` are descriptive naming
conventions, not the source of truth for execution.

High-risk, network-active, credential, destructive, and artifact-writing providers require approval before trusted side effects.
