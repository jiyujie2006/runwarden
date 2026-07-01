# WebUI Review Console

The contest WebUI is a dependency-free static renderer for Rust-produced demo JSON. It does not submit approval decisions.

## UI Contract

`runwarden ui build` writes a minimal static console. It displays one section
per discovered `webui.json` with scenario id, provider-call count, denial
count, and trace status, then derives a provider-call timeline and pending
review queue from Rust-produced `provider_calls`. If no demo JSON is found, it
displays `No demo JSON loaded.`

The `packages/webui` view model supports suite counts, requires-review counts,
blocked side-effect counts, report claim counts, cited obs refs, trace
completeness, citation accuracy, timeline events, and review queue events.
Those fields are presentation-only.

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

Live replay serves the static console at `/` and streams existing `webui.json`
provider-call records at `/events` as Server-Sent Events. With `--llm-trace`,
it appends LLM-proxy `model_call` events from JSONL. The stream is replay-only:
events are Rust-produced demo/model-filter state, and the WebUI does not make
approval, egress, provider, report, or artifact decisions.

Live replay event fields, including provider, decision, and model names, are
rendered with DOM text APIs (`textContent`/text nodes), not as HTML. The live
console must not insert SSE JSON fields through HTML parsing APIs.
