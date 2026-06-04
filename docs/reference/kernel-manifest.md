# Kernel Manifest

Kernel manifests are represented by assessment and session manifests. Together
they define the policy envelope used by `KernelEnforcer`.

## Policy Fields

Important runtime fields:

- provider allowlist
- scoped roots
- targets
- budgets
- actor
- authorization
- active assessment

## Assessment to Session

The assessment manifest is the human-authored TOML input. The session manifest
is the runtime policy input derived from that assessment.

```bash
runwarden session create --manifest <assessment.toml> --session <id> --json
runwarden session inspect --session <id> --json
```

Session-backed provider calls use the session's allowlist, roots, authz, actor,
and active-assessment state before side effects.
