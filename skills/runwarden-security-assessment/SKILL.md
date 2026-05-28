---
name: runwarden-security-assessment
description: Run an agent-native security assessment through the Runwarden MCP boundary.
---

# Runwarden Security Assessment

Use `runwarden-mcp` for every provider action. Do not call raw shell, filesystem,
browser, HTTP, or downstream MCP tools directly.

Required flow:

1. Load or create a manifest-backed session.
2. Call `runwarden.provider.list`.
3. Use `runwarden.provider.call` for every provider action.
4. Run `runwarden.provider.call` with `runwarden.eval.agent-native` before
   trusting an agent config.
5. Export trace through `runwarden.trace.export`.
6. Lint report with `runwarden.report.lint`.
7. Render report with `runwarden.report.render` only after every claim cites
   verified `obs_*`.
