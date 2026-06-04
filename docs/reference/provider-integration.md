# Provider Integration

External providers must ship a manifest and pass provider certification before
use. They are integrated as Runwarden providers, not exposed directly to agents.

## Minimum Requirements

- `provider_class = external`
- `provider_id` starts with `external.`
- schema pin uses SHA-256
- observed schema matches the pinned schema
- transport is explicit
- downstream identity and tool identity are declared
- permissions and egress origins are declared
- side effects and risk are declared

## MCP Adapters

MCP transports supported by the local adapter are `stdio`, `http`, and `sse`.
Execution uses the manifest transport. If a request includes `transport`, it
must exactly match the manifest transport. Manifests without an explicit
transport are denied before adapter execution.

If a request supplies `manifest_path`, the CLI resolves relative paths from the
adapter request file and binds the resolved path into kernel scoped-root,
approval, and digest checks before execution.

## Stdio Requirements

Stdio MCP adapters require:

- a trusted runtime root from the request or manifest
- an exact command allowlist match
- no shell-capable command such as `sh`, `bash`, `cmd`, `powershell`, or `pwsh`
- no request-supplied command arguments
- fixed adapter arguments baked into a trusted wrapper or manifest-owned
  executable
- process-tree cleanup support before spawn
- bounded stdout/stderr
- cleanup of the spawned process group on timeout, output limit failure,
  stdin/pre-wait failure, and normal completion

## HTTP and SSE Requirements

HTTP and SSE adapters require allowed origins and deny hostname resolutions to
private, loopback, link-local, carrier-grade NAT, unique-local, or unspecified
addresses before connecting. Literal private or local IP hosts are denied by
the adapter with the same egress-denied outcome before a socket connection is
attempted.
