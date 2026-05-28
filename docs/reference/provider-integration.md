# Provider Integration

External providers must ship a manifest and pass provider certification before use.

Minimum requirements:

- `provider_class = external`
- `provider_id` starts with `external.`
- schema pin uses SHA-256
- observed schema matches the pinned schema
- transport is explicit
- downstream identity and tool identity are declared
- permissions and egress origins are declared

MCP transports supported by the local adapter are `stdio`, `http`, and `sse`.
