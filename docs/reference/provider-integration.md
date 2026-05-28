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

Stdio MCP adapters require:

- a trusted runtime root from the request or manifest
- an exact command allowlist match
- no shell-capable command (`sh`, `bash`, `cmd`, `powershell`, `pwsh`, etc.)
- no `-c` argument
- bounded stdout/stderr and timeout cleanup of the spawned process group

HTTP and SSE adapters require allowed origins and deny hostname resolutions to
private, loopback, link-local, carrier-grade NAT, unique-local, or unspecified
addresses before connecting. Literal private IPs must still pass the kernel
egress policy for mediated calls.
