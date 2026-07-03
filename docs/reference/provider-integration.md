# Provider Integration

External capabilities are integrated as Runwarden providers, never exposed directly to agents.

## Requirements

- provider identity and class are declared in Rust-owned registry or manifest
- schema pin uses SHA-256
- transport is explicit for external MCP adapters
- downstream identity and tool identity are declared
- permissions, egress origins, risk, and side effects are declared
- provider calls pass kernel session, scoped-root, egress, authz, approval, budget, and trace checks before side effects
- local filesystem tool paths stay relative to the sandbox root; absolute
  paths and parent traversal are rejected, and existing path components are
  canonicalized before read/write so symlink escapes cannot leave the root
- sandbox roots come from Runwarden-owned runtime configuration, not
  provider-call arguments
- MCP inline provider policy installs a server-owned sandbox root, manifest
  derived public egress host allowlist, private/local egress denial, and an
  argument-byte budget before approval or execution

## MCP Adapters

MCP adapters support `stdio`, `http`, and `sse` contracts. Stdio adapters require a trusted runtime root, exact command allowlisting, no shell-capable command, no request-supplied command arguments, bounded output, and process-tree cleanup. HTTP/SSE adapters deny hostname resolutions to private or local addresses before connecting.

Local filesystem reads canonicalize the requested file when it exists and
confirm the target remains under the sandbox root before reading. Writes may
create a nonexistent final file, but only after the deepest existing parent
path canonicalizes inside the sandbox root; symlinked parents that resolve
outside the root are denied before any side effect is reported.

The contest package does not invoke trusted downstream network adapters during
local demo runs. API and browser provider ids return simulated outcomes and
`obs_*` evidence. Local filesystem, email, memory, and knowledge providers use
the same Rust-owned manifest and policy contract, then perform only bounded
local sandbox side effects after the kernel and approval gates allow them.
