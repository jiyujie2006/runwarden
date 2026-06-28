# CLI Reference

`runwarden` is the contest control plane. It creates sessions, evaluates provider calls, verifies traces, lints and renders reports, evaluates scenario fixtures, runs deterministic demos, and builds a static reviewer console.

## Command Map

```bash
runwarden check --strict

runwarden session create --manifest scenarios/prompt-injection-file-exfil/manifests/assessment.toml --session demo --json
runwarden session inspect --session demo --json

runwarden provider list --session demo --json
runwarden provider call --provider runwarden.input.inspect --input input.txt --json

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
```

Removed from the contest CLI: `agent *`, `cert *`, `bench *`, `artifact *`, `api serve`, and `release smoke`.

## Provider Calls

Provider calls are evaluated by `KernelEnforcer` before execution. The CLI performs a pre-read policy check before binding file digests so traversal and scoped-root failures are denied before any file read.

Session-backed calls resolve relative provider paths under the selected session root. High-risk providers require a bound approval record before simulated or real side effects can run.

## Demo Runner

`runwarden demo run` loads a scenario, replays its deterministic agent script through Rust-owned provider outcomes, writes `trace.json`, `provider-calls.json`, `denials.json`, `report.json`, `metrics.json`, and `webui.json`, and keeps denied/review-blocked calls at `side_effect_executed=false`.

## Output Paths

Demo, report, and UI output paths must be relative workspace paths. Absolute paths, parent traversal, and symlink components are rejected.
