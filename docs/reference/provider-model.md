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

High-risk, network-active, credential, destructive, and artifact-writing providers require approval before trusted side effects.
