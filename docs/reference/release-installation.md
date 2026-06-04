# Release Installation

Release evidence is produced by `scripts/release_gate_local.sh`,
`scripts/generate_artifacts.sh`, and `.github/workflows/release.yml`.

## Named Binaries

- `runwarden`
- `runwarden-mcp`
- `runwarden-kernel`

Release workflows build named binaries from the Rust workspace and upload
release evidence artifacts.

## Release Artifacts

Release artifacts include:

- generated schemas
- submission artifacts
- SBOM
- provenance
- cert results
- bench results
- agent-native eval results
- scenario golden-corpus eval results
- sealed artifact manifest and redaction sidecars

## Local Evidence Command

```bash
bash scripts/release_gate_local.sh
```

Use [Release Process](../development/release-process.md) for the full local and
GitHub workflow.
