# CLI Reference

`runwarden` is the human control plane. It initializes, checks, certifies, runs
provider calls, manages sessions and approvals, verifies traces, renders reports,
and verifies artifacts.

Core commands:

```bash
runwarden check --strict
runwarden agent generate-config --client claude --output examples/agent-configs/claude.runwarden-only.json
runwarden agent check-config --client claude --input examples/agent-configs/claude.runwarden-only.json --json
runwarden session create --manifest scenarios/enterprise-agent-security/manifests/assessment.toml --session enterprise_ops --json
runwarden provider list --session enterprise_ops --json
runwarden provider call --provider runwarden.input.inspect --input input.txt --json
runwarden provider call --provider runwarden.evidence.inspect --root evidence --json
runwarden approval pending --json
runwarden approval approve approval-1 --reviewer reviewer_alice --reason "reviewed scope and risk" --json
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
runwarden artifact verify --json
runwarden release smoke --json
runwarden ui --bind 127.0.0.1 --port 8088 --artifacts artifacts --json
runwarden api serve --bind 127.0.0.1 --port 8088 --once --json
```

`provider call` also supports first-party trace, report, audit, accountability,
cert, eval, and bench providers, including `runwarden.eval.agent-native`.
When no session is supplied, `provider list` includes first-party providers and
the certified external provider families declared in the kernel-managed catalog.

Approval-bound CLI provider calls bind file contents, not only file paths. When
`input_path`, `trace_path`, `report_path`, or an external MCP manifest path is
part of the approved call, the CLI first runs kernel path policy without
reading file contents, records a SHA-256 digest before approval matching only
after that policy allows the path, then rechecks it after the kernel allows the
call and before persisting consumed approval state or executing the provider.

Session-backed provider calls resolve relative `input_path`, `trace_path`, and
`report_path` arguments under the same scoped root used by kernel root
validation before digest binding and provider execution. External MCP request
`manifest_path` values are also promoted into kernel arguments, resolved
relative to the adapter request file when they are not absolute, and root
validated before digest binding or execution. For example, a call with
`--session enterprise_ops --root safe --input input.txt` reads `safe/input.txt`,
not `./input.txt` from the CLI process directory. No-session provider calls
keep normal CLI path resolution.

Provider-call trace export fails closed on unverified trace input. If trace
hash-chain verification fails, `provider call --provider runwarden.trace.export`
returns a denied failed result with verification details and does not include
trace `events` in the provider output.

Artifact and UI output arguments (`--output`, `--artifacts`) must be relative
workspace paths. Absolute paths, parent traversal, and symlink escapes are
rejected before writing bundles.

`runwarden ui` writes a dependency-free static `reviewer-console.html` bundle
with a local `reviewer-console.js` companion script. The JSON response includes
file `launch_url` and `script_path` values plus a separate `local_api_url` for
the configured API origin. The generated console snapshots pending approval
records from `.runwarden/approvals`, sessions from `.runwarden/sessions`, and
report/artifact/assurance summaries from the artifact root.
