# Provider Integration

External capabilities are integrated as Runwarden providers, never exposed directly to agents.

## Requirements

- provider identity and class are declared in Rust-owned registry or manifest
- schema pin uses SHA-256
- transport is explicit for external MCP adapters
- downstream identity and tool identity are declared
- permissions, egress origins, risk, and side effects are declared
- provider calls pass kernel session, scoped-root, egress, authz, approval, budget, and trace checks before side effects

## MCP Adapters

MCP adapters support `stdio`, `http`, and `sse` contracts. Stdio adapters require a trusted runtime root, exact command allowlisting, no shell-capable command, no request-supplied command arguments, bounded output, and process-tree cleanup. HTTP/SSE adapters deny hostname resolutions to private or local addresses before connecting.
