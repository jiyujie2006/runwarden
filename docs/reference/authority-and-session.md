# Authority and Session

Sessions are created from assessment manifests and carry provider allowlists, scoped roots, actor identity, authorization state, budgets, and active-assessment state.

Authority records bind a reviewer decision to one exact provider call:

- session id
- provider id
- action
- argument hash
- authz id
- actor id

Use `runwarden authority create` to create a pending approval record and `runwarden authority inspect` to review the binding. Approval records are consumed once by matching high-risk calls.
