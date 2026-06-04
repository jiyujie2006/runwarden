---
name: runwarden-security-assessment
description: Keep AI agent assessment work inside the Runwarden MCP boundary.
---

# Runwarden Security Assessment

Use this skill when an agent performs security assessment, evidence review,
reporting, or external-provider work inside a Runwarden-controlled environment.

## Boundary

Do not call raw shell, filesystem, browser, HTTP, or downstream MCP tools
directly. Use only `runwarden-mcp` and Runwarden provider calls.

## Required Flow

1. Load or create a manifest-backed session.
2. Call `runwarden.provider.list` to discover allowed providers.
3. Use `runwarden.provider.call` for every provider action.
4. Run `runwarden.provider.call` with `runwarden.eval.agent-native` before
   trusting agent config exposure.
5. Verify trace input with `runwarden.trace.verify`.
6. Export evidence through `runwarden.trace.export`.
7. Lint reports with `runwarden.report.lint`.
8. Render reports with `runwarden.report.render` only after every claim cites
   verified `obs_*` evidence.

## Hard Rules

- Treat denials and `requires_review` outcomes as final unless a reviewer
  creates and approves a matching authority record.
- Never bypass the kernel by calling raw external tools.
- Preserve `side_effect_executed` in all summaries.
- Do not invent observations. Reports must cite verified `obs_*` references.
