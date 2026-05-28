# Assessment Manifest

Assessment manifests are TOML files that define an evaluation or security assessment scope.

Core fields:

- `version`
- `name`
- `mode`
- `provider_allowlist`
- `roots`
- `targets`
- `budgets`
- `authorization`
- `actor`
- `active_assessment`

Use `runwarden session create --manifest <path> --session <id>` to derive a persisted session.
