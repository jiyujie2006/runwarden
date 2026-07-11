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

MCP adapters support `stdio`, `http`, and `sse` contracts. Adapter execution is
valid only through `execute_mediated_external_mcp_adapter` after a kernel
`Allowed` provider outcome for the same manifest provider. Denied or
review-blocked outcomes return `execution_status=not_executed` and
`side_effect_executed=false` before adapter validation or transport execution.
Stdio adapters require a trusted runtime root, exact command allowlisting, no
shell-capable command, no request-supplied command arguments, bounded output,
and process-tree cleanup. HTTP/SSE adapters deny hostname resolutions to
private or local addresses before connecting.

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

## Native SQLite Execution Gate

`runwarden-state` now exposes the durable gate that a native runtime must pass
before invoking any provider. It does not accept approval, authority, active
instance, or budget material from provider arguments.

Lease acquisition has two non-interchangeable branches:

- `StoredPolicyAllow` requires an enforced story, a durable allowed policy
  decision in `PolicyEvaluated`, matching operation/session/resource/argument
  and policy commitments, and no approval row.
- `ReviewerApproval` requires the exact approved, unexpired, one-shot approval
  id and version, its canonical binding hash, and an `Approved` operation.

In either branch, one immediate transaction revalidates the server-owned
singleton active instance and session, exact instance-token hash, policy
snapshot, session and lease expiry, operation version, and cumulative budget.
It CAS-reserves call/file/network units, persists the lease binding and
pre-lease state, moves the operation to `ExecutionLeased`, and emits
`execution_lease_acquired`. Reviewed approval moves to `Leased`. A concurrent
caller receives a structured conflict and cannot create a second reservation.

Lease acquisition alone cannot authorize adapter or provider code.
`mark_execution_started` opens a second immediate transaction, re-reads the
active instance, requires the exact durable lease id/owner/expiry and instance
binding, consumes a reviewed approval once, moves the operation to `Executing`,
and commits `provider_execution_started`. A provider executor may be called
only after this method returns successfully.

Result persistence then requires executing state, the exact lease identity and
expected operation version, and a verified start event. Only coherent
Completed or Failed provider-result/side-effect combinations are accepted.
The journal releases the full reservation, commits no more than the recorded
actual charge, stores only the typed redacted result, and appends the terminal
event/frame atomically. Proven `NotExecuted` and `FailedBeforeSideEffect`
outcomes commit zero actual charge and release the complete reservation.
Post-start session deactivation cannot suppress a
truthful result write; uncertain post-effect recovery remains a separate
conservative recovery path.

This native gate is not yet wired into the current contest MCP/WebUI request
path. `runwarden-mcp` still uses the documented file-backed approvals and
legacy provider-call trace, and the existing demo adapters retain their stated
simulation/local-sandbox behavior. Until the runtime migration lands, the
presence of a SQLite approval or lease must not be presented as proof that the
current MCP process invoked a provider through this gate.
