# JSON Contracts

Runwarden JSON contracts are stored under `schemas/` and are generated from
Rust types where possible. Rust is the source of truth.

The kernel also owns the typed `ResourceClaim`, `AuthoritySnapshot`,
`SecurityOperation`, `SecurityStory`, and `StoryReplayFrame` views. Native v1
views reject unknown fields so arbitrary JSON cannot become an unreviewed
security or export channel.

Canonical JSON v1 recursively sorts every object by UTF-8 key bytes, preserves
array order, and then emits compact `serde_json` bytes. Resource-claim digests
and replay-frame hashes call this single implementation; event sealing extends
the same module without defining a second canonicalizer.

## Schema Inventory

- `provider-call.schema.json`
- `provider-outcome.schema.json`
- `operation-result.schema.json`
- `approval-record.schema.json`
- `trace-event.schema.json`
- `assessment-manifest.schema.json`
- `session-manifest.schema.json`
- `provider-manifest.schema.json`
- `provider-contract.schema.json`
- `artifact-manifest.schema.json`
- `report.schema.json`

## Drift Checks

Schema drift is caught by:

```bash
cargo test -p runwarden-kernel --test contract_schemas
```

The contest edition has no active TypeScript package. Any future TypeScript may define
presentation-only demo JSON types and does not generate authoritative security
contracts.
