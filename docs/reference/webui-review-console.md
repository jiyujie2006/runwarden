# WebUI Review Console

The contest WebUI is a dependency-free static renderer for Rust-produced demo JSON. It has no Local API dependency and does not submit approval decisions.

## UI Contract

The static console displays:

- scenario count
- provider call count
- denial count
- requires-review count
- blocked side-effect count
- trace status
- report claim count
- cited obs refs
- trace completeness and report citation accuracy

## Policy Boundary

WebUI code must not decide allow, deny, approval, egress, provider, report, or artifact policy. Rust-produced demo JSON is the source of truth; TypeScript maps it to labels and layout.

Build with:

```bash
runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json
```
