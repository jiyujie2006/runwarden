# WebUI Review Console

The contest WebUI is a dependency-free static renderer for Rust-produced demo JSON. It does not submit approval decisions.

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

WebUI code must not decide allow, deny, approval, egress, provider, report,
trace, or artifact policy. Rust-produced demo JSON is the source of truth;
TypeScript maps it to labels and layout. Trace status is read from
`trace_verification.verified`; the WebUI must not infer verification from trace
presence or report lint success.

Build with:

```bash
runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json
```

Run live replay with:

```bash
runwarden ui serve --live --demo artifacts/demo/prompt-injection-file-exfil --json
```

Live replay serves the static console at `/` and streams existing
`webui.json` provider-call records at `/events` as Server-Sent Events. The
stream is replay-only: events are Rust-produced demo state, and the WebUI does
not make approval, egress, provider, report, or artifact decisions.
