# Artifact Manifest

Artifact manifests list sealed artifacts and their redaction sidecars. The
checked schema is `schemas/artifact-manifest.schema.json`.

## Generate and Verify

```bash
runwarden artifact submission --full --output artifacts --json
runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json
```

## Verification Rules

Verification rejects:

- path escapes
- symlink escapes
- hash mismatches
- missing sidecars
- stale sidecar hashes
- sidecars whose `artifact_id` or `redacted_sha256` does not match the manifest
  entry and artifact bytes

Artifact sealing fails closed before writing when content contains
case-insensitive secret-like markers such as `password=`, `api_key=`, token
assignments, bearer authorization headers, API key headers, or private key
markers. The local artifact leak scan uses the same marker families.

## Reviewer Console

The Reviewer Console summarizes `artifact-manifest.json` entries by
`artifact_id` when generating a static UI bundle. Report and assurance module
summaries are derived from files already present under `reports/` and
`release/` inside the same relative workspace artifact root.
