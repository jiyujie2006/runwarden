# CLI Reference

`runwarden` is the contest control plane. It creates sessions, evaluates provider calls, verifies traces, lints and renders reports, evaluates scenario fixtures, runs deterministic demos, and builds a static reviewer console.

## Command Map

```bash
runwarden check --strict

runwarden session create --manifest scenarios/prompt-injection-file-exfil/manifests/assessment.toml --session demo --json
runwarden session inspect --session demo --json

runwarden provider list --session demo --json
runwarden provider call --session demo --provider runwarden.input.inspect --root workspace --input input.txt --json

runwarden approval pending --json
runwarden approval approve approval-1 --reviewer reviewer_alice --reason "reviewed scope and risk" --json
runwarden approval deny approval-1 --reviewer reviewer_alice --reason "out of scope" --json
runwarden authority create --approval approval-1 --session demo --provider external.api.request --action request --arguments '{"url":"https://api.example.com/upload"}' --json

runwarden trace verify --trace trace.json --json
runwarden trace export --trace trace.json --provider runwarden.input.inspect --compact-refs --json

runwarden report lint --report report.json --trace trace.json --json
runwarden report render --report report.json --trace trace.json --format markdown --json
runwarden report render --scenario-suite scenarios --format markdown --output artifacts/reports/contest-report.md --json

runwarden eval scenarios --json
runwarden demo run --scenario prompt-injection-file-exfil --output artifacts/demo/prompt-injection-file-exfil --json

runwarden ui build --input artifacts/demo --output artifacts/reviewer-console.html --json
runwarden ui serve --file artifacts/reviewer-console.html --json
runwarden ui serve --live --demo artifacts/demo/prompt-injection-file-exfil --json
```

## Provider Calls

Provider calls require `--session` and are evaluated by `KernelEnforcer` before execution. The CLI performs a pre-read policy check before binding file digests so traversal and scoped-root failures are denied before any file read.

Session-backed calls resolve relative provider paths under the selected session root. High-risk providers require a bound approval record before simulated or real side effects can run.

## Demo Runner

`runwarden demo run` loads a scenario, replays its deterministic agent script
through Rust-owned provider outcomes, writes `trace.json`,
`provider-calls.json`, `denials.json`, `report.json`, `metrics.json`, and
`webui.json`, and keeps denied/review-blocked calls at
`side_effect_executed=false`. `webui.json` includes Rust-produced
`trace_verification`; WebUI renderers must use that field for trace status.

## Live Replay Server

`runwarden ui serve --live --demo <relative-demo-dir>` starts a local replay
server for existing demo artifacts. The server serves the static reviewer
console at `/` and emits finite Server-Sent Events at `/events`; each
`provider_call` event is derived from `webui.json` provider-call records and
includes scenario, sequence, provider, action, decision, execution status,
`side_effect_executed`, and `obs_ref`. The server does not submit approvals or
execute providers.

## Output Paths

Demo, report, and UI output paths must be relative workspace paths. Absolute paths, parent traversal, and symlink components are rejected.
