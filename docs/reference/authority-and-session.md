# Authority and Session

Sessions and approval records define the runtime policy envelope for provider calls.

## Sessions

`runwarden session create` derives a session from an assessment manifest. A session carries provider allowlist, scoped roots, budgets, actor id, authz state, and active-assessment state used by `KernelEnforcer`.

## Approval Records

Approval records bind a reviewer decision to one exact provider call:

- session id
- provider id
- action
- argument hash
- authz id
- actor id

High-risk provider calls consume matching approved records once. File-backed calls bind SHA-256 digests after kernel path policy allows the path and verify those digests again before approval consumption or execution.
