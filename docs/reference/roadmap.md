# Roadmap

Runwarden currently implements a contest-focused red-team range prototype with
trace-backed review outputs.

## Completed

- Kernel-owned provider mediation.
- External MCP stdio, HTTP, and SSE adapter safeguards.
- Session and bound approval commands.
- Four-scenario contest corpus and eval gate.
- Deterministic demo runner.
- Scenario-suite report rendering.
- Static WebUI reviewer-console rendering.
- Narrow agent-visible MCP tool list.

## Next Depth

Future work should focus on:

- richer demo provider adapters
- larger adversarial eval suites
- real LLM adapters behind the same provider policy path
- deeper reviewer-console workflows for large traces and approval queues
- stronger scenario authoring tools

Keep roadmap items evidence-oriented. When an item moves to completed, add the
command, test, or output that proves it.
