# Threat Model

Runwarden assumes the agent, prompts, retrieved content, downstream tools, and
report drafts can be adversarial or compromised.

## Primary Threats

- Raw tool exposure bypassing the kernel.
- Prompt injection that changes scope, target, or approval intent.
- Tool injection through external MCP schema or identity drift.
- Root escape through crafted paths or symlinks.
- Private egress, loopback egress, metadata-service access, or credential
  exfiltration.
- Approval replay or approval binding mismatch.
- Uncited report fabrication.
- Trace tampering.
- Demo/report/UI output path escape.

## Mitigations

Runwarden mitigates these through:

- provider allowlists
- scoped roots
- private and local egress checks
- schema pins
- manifest and provider contract checks
- actor-bound authz
- bound single-use approval records
- trace hash-chain verification
- report citation linting
- relative output path enforcement for demo, report, and UI files

External MCP HTTP/SSE adapters deny private or local IP literals and
special-use origin shapes during static validation. They are not network-active
in the current build: registration returns `network_adapter_not_enabled`.
Stdio is also quarantined with `stdio_isolation_unavailable` because a trusted
path, scrubbed environment, cwd, timeout, and process-group cleanup cannot
confine a compromised downstream tool. There is no unsandboxed fallback;
activation requires the mandatory Linux isolation and resource ownership
described by the sandbox plan.
