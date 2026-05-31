# Provider Manifest

Provider manifests describe external providers and bind identity, transport, permissions, and schema pins.

The checked schema is `schemas/provider-manifest.schema.json`.
External provider dispatch uses the manifest and registry `provider_class` plus
`kind` fields, not provider id family prefixes. External MCP execution also
uses the manifest `transport`; request-supplied transport is accepted only when
it exactly matches the manifest, and missing manifest transport is denied.

Run:

```bash
runwarden cert provider-manifest --manifest examples/providers/external.mcp.browser.open_page.json --json
```

Certification fails on schema rug-pulls, unsupported transports, missing
identities, missing permissions, missing egress policy, or stdio MCP manifests
without an exact command allowlist and trusted working root. Stdio MCP adapter
requests cannot supply command arguments; any fixed adapter arguments must live
inside a dedicated trusted wrapper or manifest-owned executable so allowlisted
commands cannot be redirected outside the trusted runtime root. Stdio execution
is only allowed on platforms where Runwarden can clean up the adapter process
tree. When an adapter request supplies `manifest_path`, relative paths resolve
relative to that adapter request file and the resolved path is included in
scoped-root, approval, and digest binding before execution.
