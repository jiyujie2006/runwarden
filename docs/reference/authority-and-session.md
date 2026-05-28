# Authority and Session

Sessions are created from assessment manifests and carry provider allowlists, scoped roots, actor identity, authorization state, budgets, and active-assessment state.

Session-derived authz grants are bound to the session actor. A call from another
actor with the same authz id is denied before side effects.

Authority records bind a reviewer decision to one exact provider call:

- session id
- provider id
- action
- argument hash
- authz id
- actor id

Use `runwarden authority create` to create a pending approval record and `runwarden authority inspect` to review the binding. Approval records are consumed once by matching high-risk calls.

The Reviewer Console launch bundle renders pending approval records with the
same binding fields so reviewers can inspect provider, action, actor, authz, and
argument hash before entering a reason and choosing approve or deny. The browser
submission path still requires the Runwarden launch token and calls the Local API
approval decision endpoints; the kernel-owned approval record remains the source
of truth.
