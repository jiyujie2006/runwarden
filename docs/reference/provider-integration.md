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

The native executor does not invoke trusted downstream network adapters for
the contest API and browser providers; those ids return typed simulated
outcomes. Native local filesystem, email, memory, and knowledge providers use
the same Rust-owned catalog and typed-claim contract, then perform only bounded
local sandbox effects after the permit gate. The compatibility demo/MCP paths
remain disconnected from that executor and fail closed until Plan 4.

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

The provider crate now contains the state-independent half of that boundary:
`ProviderExecutionRequest`, HMAC-sealed `ExecutionPermit`, safe result and
cleanup contracts, and the `ProviderExecutor` trait. Requests retain private
arguments without a debug or serialization surface and carry canonical
argument/resource, policy, provider-contract, and reserved-budget bindings.
The process key comes from `getrandom`, is shared only by the Rust issuer and
verifier, and is zeroized after the final handle drops. The permit API is not
an MCP/CLI input and does not accept agent-selected authority, time, budget, or
approval material.

Before that request can reach policy or permit issuance, the native provider
path uses the Rust-owned `ResourceExtractorRegistry`. It selects an extractor
by the canonical catalog provider id, verifies the exact action, validates a
strict per-provider argument shape, and constructs a typed kernel
`ResourceClaim`. Filesystem roots, store namespaces, and classification come
only from `ResourceExtractionContext`, which the server builds from trusted
configuration. Arguments named like policy, authority, approval, budget,
runtime, transport, root, namespace, or classification controls fail closed.
Unsupported provider/action pairs and unknown argument fields do not fall back
to an opaque or guessed claim.

Production native orchestration must construct the authoritative registry and
install its separate `ResourceBindingVerifier` in the immutable session
context. The registry keeps the matching issuer private. `extract_bound`
derives `calls=1`, reserves the trusted per-call cap for declared file or
artifact effects, and reserves canonical request bytes plus a trusted response
cap for declared network effects. It then authenticates provider contract,
provider/action, complete arguments, claim, charge, and enforcement mode with a
domain-separated process-local HMAC. A display-only extraction, a proof from a
different process authority, a zero or substituted charge, or any post-
extraction value change fails before resource policy can allow the proposal.

Claim canonicalizers are exported for reuse by the corresponding native
executor. Relative file paths have `.` components removed and reject empty or
`..` components, platform prefixes, and backslashes; email domains alone are
ASCII-lowercased before sorting and deduplication; network targets must be
canonical HTTP(S) origins without userinfo; and memory/knowledge namespaces
cannot be caller-selected. The
permit separately commits the complete canonical argument object so data not
present in the least-authority claim remains bound to the approved operation.

The native default executor configuration canonicalizes two non-overlapping
existing directories: the local business-tool sandbox and the trusted runtime
root. It also freezes the trusted logical filesystem root, memory namespace,
knowledge namespace, and default classification used by extraction. Output and
timeout limits are positive and capped; all validated fields become private
after construction, and verifier material is redacted. After permit and
catalog validation, the executor reruns the canonical extractor with this
configured scope rather than values copied from the submitted claim. A claim
for another logical root, namespace, or classification is blocked before
business I/O.

On Unix, configuration pins the device/inode identity of both canonical roots;
every execution, reconciliation, and cleanup rejects a replaced root or a path
that now resolves elsewhere. Filesystem, email, memory, and knowledge
implementations are crate-private and reachable only from this executor. API
and browser implementations contain no network client and return typed
`Simulated` outcomes with zero actual charge.

Filesystem operations use bounded reads and atomic temporary-file writes,
reject absolute/traversing paths and symlink components, and return only byte
counts and content hashes. The generic file provider cannot read or write the
reserved `mail/`, `stores/`, or `.runwarden/` backing prefixes, so an approved
file write cannot forge another provider's state. Memory and knowledge use
separate directories and server-owned namespace hashes; values are not
returned in evidence, and reads declare and consume bounded file-byte budget.
Email
stores no subject or body plaintext. It creates one canonical, fsynced receipt
per operation with `hard_link`, binds the argument and message hashes, and
reconciles duplicate execution from that immutable receipt. A different
argument binding is blocked before execution; malformed or contradictory
receipt material becomes `OutcomeUnknown` with the full reservation charged.
Cleanup tokens name only a hash-bound temporary file below `mail/tmp` and are
usable only by the executor after the journal result disposition is known.
Cleanup verifies that the matching durable receipt still exists before
removing its temporary hard link.

The process registry keys replay protection by operation id across executor
instances and roots, binds the complete request plus pinned executor roots,
and retains completed/uncertain tombstones even after permit expiry. A renewed
permit therefore cannot repeat a file or store write, and routing one operation
to a different root is an integrity conflict. The registry has a fixed contest
capacity and fails closed when full; Plan 4 adds the durable journal as the
cross-process source of operation ownership and recovery.

Monitor-only assurance is deliberately outside this executor. It has no
delegate and never touches a configured root. A domain-separated proposal
commitment ties its observation to the exact policy-evaluated provider,
action, arguments, claim, contract, and charge; `proposal_binding_verified`
must also be true. Its simulated result models an unprotected baseline for A/B
evaluation and must never be reported as a trusted provider execution.

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
path. `runwarden-mcp` still uses the documented file-backed approval and trace
surfaces for compatibility, but it now fails closed for external provider
execution with `native_executor_required`; the CLI legacy scenario dispatcher
does the same. Neither path calls a local tool, claims a side effect, nor
persists approval consumption while the durable runtime is disconnected. The
old public generic business-tool dispatcher has been removed. Until the Plan 4
runtime migration lands, the presence of a SQLite approval, a file-backed
approval, or a policy `Allowed` decision must not be presented as proof that
the current MCP/CLI process invoked a provider through the native executor.
