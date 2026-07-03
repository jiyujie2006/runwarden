# JSON Contracts

Runwarden JSON contracts are stored under `schemas/` and are generated from
Rust types where possible. Rust is the source of truth.

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
