# Provider Manifest

Provider manifests describe external providers and bind identity, transport, permissions, and schema pins.

The checked schema is `schemas/provider-manifest.schema.json`.

Run:

```bash
runwarden cert provider-manifest --manifest examples/providers/external.mcp.browser.open_page.json --json
```

Certification fails on schema rug-pulls, unsupported transports, missing identities, missing permissions, or missing egress policy.
