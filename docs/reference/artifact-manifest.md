# Artifact Manifest

Artifact manifests list sealed artifacts and their redaction sidecars.

The checked schema is `schemas/artifact-manifest.schema.json`.

Run:

```bash
runwarden artifact submission --full --output artifacts --json
runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json
```

Verification rejects path escapes, symlink escapes, hash mismatches, missing
sidecars, stale sidecar hashes, and sidecars whose `artifact_id` or
`redacted_sha256` does not match the manifest entry and artifact bytes.

The Reviewer Console summarizes `artifact-manifest.json` entries by
`artifact_id` when generating a static UI bundle. Report and assurance module
summaries are derived from files already present under `reports/` and `release/`
inside the same relative workspace artifact root.
