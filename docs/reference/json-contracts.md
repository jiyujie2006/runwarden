# JSON Contracts

Runwarden JSON contracts are stored under `schemas/` and are generated from
Rust types where possible. Rust is the source of truth.

The kernel also owns the typed `ResourceClaim`, `AuthoritySnapshot`,
`SecurityOperation`, `SecurityStory`, `StoryEvent`, `StoryReplayFrame`,
`StoryEvidenceView`, and `StoryBundleManifest` views. Native v1 views reject
unknown fields so arbitrary JSON cannot become an unreviewed security or
export channel.

The security-story schema writer version is `1.0.0`. Readers accept canonical
three-component versions with major version `1` through the validated Rust
`SchemaVersion` type and reject unsupported majors or non-canonical numeric
components. Generated schemas publish the accepted major-version shape.

Validated workspace-relative paths and SHA-256 digests also retain their wire
constraints in generated schemas. Paths are non-empty slash-separated relative
paths without absolute/platform prefixes, empty, `.` or `..` components;
digests use `sha256:` followed by exactly 64 lowercase hexadecimal characters.

Canonical JSON v1 recursively sorts every object by UTF-8 key bytes, preserves
array order, and then emits compact `serde_json` bytes. Resource-claim digests
and replay-frame hashes call this single implementation; event sealing extends
the same module without defining a second canonicalizer.

`StoryBundleManifest::signature_material()` uses the same canonicalizer after
sorting its typed payload-file entries by relative path. The manifest contains
the signature algorithm and key identifier but intentionally has no embedded
signature field: signature bytes are detached and therefore cannot sign
themselves. This contract does not implement key management, signing, export,
or filesystem writes.

For a story-only bundle, `scenario_assertions_verified` is `null`. It may be
`true` only when signed scenario assertion, evaluation, and input-manifest
extensions exist and a Rust verifier recomputes them. A value of `false` is not
exportable as verified evidence. Sorting does not itself prove uniqueness or
verification semantics: the Rust bundle verifier remains authoritative for
rejecting duplicate payload paths and invalid verification-summary combinations.

## Schema Inventory

- `security-story.schema.json`
- `security-operation.schema.json`
- `story-event.schema.json`
- `resource-claim.schema.json`
- `authority-snapshot.schema.json`
- `story-bundle-manifest.schema.json`
- `story-replay-frame.schema.json`
- `story-evidence-view.schema.json`
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

Regenerate every checked-in Rust-owned schema with:

```bash
cargo run -p runwarden-kernel --example generate_schemas
```

The contest edition has no active TypeScript package. Any future TypeScript may define
presentation-only bindings from these schemas and does not generate or duplicate
authoritative security contracts.
