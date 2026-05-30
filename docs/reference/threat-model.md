# Threat Model

Runwarden assumes the agent, prompts, retrieved content, downstream tools, and report drafts can be adversarial or compromised.

Primary threats:

- raw tool exposure bypassing the kernel
- prompt injection that changes scope or approvals
- external MCP schema or identity drift
- private egress and credential exfiltration
- uncited report fabrication
- trace tampering
- artifact leakage

The kernel mitigates these through allowlists, scoped roots, egress checks,
schema pins, approval records, trace verification, report linting, and artifact
redaction checks. External MCP HTTP/SSE adapters also deny private or local IP
literals and resolutions before connecting so downstream tool endpoints cannot
be used for loopback or metadata-service egress.
