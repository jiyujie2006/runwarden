# JSON Contracts

Runwarden JSON contracts are stored under `schemas/` and are generated from Rust types where possible.

Important contracts:

- provider call
- provider outcome
- operation result
- approval record
- trace event
- assessment manifest
- session manifest
- provider manifest
- provider contract
- artifact manifest
- report

Schema drift is caught by `cargo test -p runwarden-kernel --test contract_schemas`.
