# CLI Reference

`runwarden` is the human control plane. It creates sessions, evaluates provider
calls, manages approvals, verifies traces, lints and renders reports, verifies
artifacts, runs assurance gates, writes the Reviewer Console bundle, and starts
the Local API.

## Command Map

```bash
runwarden check --strict

runwarden agent generate-config --client claude --output examples/agent-configs/claude.runwarden-only.json
runwarden agent check-config --client claude --input examples/agent-configs/claude.runwarden-only.json --json

runwarden session create --manifest scenarios/enterprise-agent-security/manifests/assessment.toml --session enterprise_ops --json
runwarden session inspect --session enterprise_ops --json

runwarden provider list --session enterprise_ops --json
runwarden provider call --provider runwarden.input.inspect --input input.txt --json
runwarden provider call --provider runwarden.evidence.inspect --root evidence --json

runwarden approval pending --json
runwarden approval approve approval-1 --reviewer reviewer_alice --reason "reviewed scope and risk" --json
runwarden approval deny approval-1 --reviewer reviewer_alice --reason "scope is unclear" --json

runwarden authority create --approval approval-1 --session enterprise_ops --provider external.mcp.browser.open_page --action open_page --arguments '{"url":"https://example.com"}' --authz authz-1 --actor agent-1 --json
runwarden authority inspect approval-1 --json

runwarden trace verify --trace trace.json --json
runwarden trace export --trace trace.json --provider runwarden.input.inspect --offset 0 --limit 100 --compact-refs --json

runwarden report scaffold --trace trace.json --json
runwarden report lint --report report.json --trace trace.json --json
runwarden report render --report report.json --trace trace.json --format html --json

runwarden eval all --json
runwarden eval scenarios --json
runwarden eval agent-native --json

runwarden cert all --json
runwarden cert agent-config examples/agent-configs/claude.runwarden-only.json --json
runwarden cert provider-manifest --json
runwarden cert mcp --json
runwarden cert skill --json
runwarden cert workflow --json
runwarden cert script --json
runwarden cert package --json
runwarden cert release-artifact --json

runwarden bench run --json
runwarden artifact submission --full --output artifacts --json
runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json
runwarden release smoke --json

runwarden ui --bind 127.0.0.1 --port 8088 --artifacts artifacts --json
runwarden api serve --bind 127.0.0.1 --port 8088 --json
```

## Provider Calls

`provider list` without a session shows first-party providers plus certified
external provider families declared in the kernel-managed catalog. With a
session, it returns the session allowlist.

`provider call` submits the call to the Runwarden platform executor. The
executor evaluates kernel policy before execution, appends provider-call events,
persists a provider-call record under `.runwarden/provider-calls/`, and then
dispatches first-party providers or mediated external adapters. It supports
first-party trace, report, audit, accountability, cert, eval, and bench
providers, including `runwarden.eval.agent-native`.

Session-backed provider calls resolve relative `input_path`, `trace_path`, and
`report_path` under the same scoped root used by kernel root validation. For
example, `--session enterprise_ops --root safe --input input.txt` reads
`safe/input.txt`, not `./input.txt` from the CLI process directory.

External MCP request `manifest_path` values are promoted into kernel arguments,
resolved relative to the adapter request file when they are not absolute, and
root validated before digest binding or execution.

Review-required provider calls return a normalized `ProviderOutcome`, enqueue a
pending approval record when needed, and preserve `side_effect_executed: false`.

## Approval and Digest Binding

Approval-bound CLI provider calls bind file contents, not only file paths. For
`input_path`, `trace_path`, `report_path`, or external MCP manifest paths, the
CLI:

1. Runs kernel path policy before reading file contents.
2. Records a SHA-256 digest after the path is allowed.
3. Matches the approval binding.
4. Rechecks the digest after kernel allow and before persisting consumed
   approval state or executing the provider.

## Trace and Report Safety

Provider-call trace export fails closed on unverified trace input. If trace
hash-chain verification fails, `provider call --provider runwarden.trace.export`
returns a denied failed result with verification details and does not include
trace events in the provider output.

Report rendering succeeds only after report lint confirms cited observations
support the claims.

## Artifacts, UI, and API

Artifact and UI output arguments (`--output`, `--artifacts`) must be relative
workspace paths. Absolute paths, parent traversal, and symlink escapes are
rejected before writing bundles.

`runwarden ui` writes a static `reviewer-console.html` bundle and local
`reviewer-console.js` companion script. The JSON response includes file
`launch_url`, `script_path`, and `local_api_url`.

`runwarden api serve` starts the Local API used by the Reviewer Console and SDK.
Control-plane routes require launch token and Host/Origin checks.
