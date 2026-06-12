# JSON Contracts

Runwarden JSON contracts are stored under `schemas/` and are generated from
Rust types where possible. Rust is the source of truth.

## Schema Inventory

- `provider-call.schema.json`
- `provider-outcome.schema.json`
- `operation-result.schema.json`
- `approval-record.schema.json`
- `trace-event.schema.json`
- `trace-query.schema.json`
- `trace-page.schema.json`
- `trace-export-page.schema.json`
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

TypeScript contract drift is caught by:

```bash
scripts/check_ts_contracts.sh
```

Do not hand-edit generated TypeScript contract declarations. Regenerate them
from Rust schemas through the pipeline documented in
[Rust Kernel and TypeScript Interaction](rust-kernel-ts-interaction.md).
