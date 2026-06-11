# Authority and Session

Sessions and authority records define the runtime policy envelope for provider
calls.

## Sessions

Sessions are created from assessment manifests and persisted in the local
Runwarden platform state under `.runwarden/sessions/`. A session carries:

- session id
- manifest hash
- provider allowlist
- scoped roots
- targets
- budgets
- actor id
- authz id and authz state
- active-assessment state

Create and inspect a session:

```bash
runwarden session create --manifest scenarios/enterprise-agent-security/manifests/assessment.toml --session enterprise_ops --json
runwarden session inspect --session enterprise_ops --json
```

Session-derived authz grants are bound to the session actor. A call from another
actor with the same authz id is denied before side effects.

## Authority Records

Authority records bind a reviewer decision to one exact provider call:

- session id
- provider id
- action
- argument hash
- authz id
- actor id

Approval records are persisted under `.runwarden/approvals/`.
Provider calls that require review create deterministic pending approval records
from the exact approval binding when no usable matching approval exists. File
arguments such as `input_path`, `trace_path`, `report_path`, and external MCP
`manifest_path` are digest-bound before approval matching so reviewer decisions
apply to the approved contents, not only the path strings.

Use:

```bash
runwarden authority create --approval approval-1 --session enterprise_ops --provider external.mcp.browser.open_page --action open_page --arguments '{"url":"https://example.com"}' --authz authz-1 --actor agent-1 --json
runwarden authority inspect approval-1 --json
runwarden approval approve approval-1 --reviewer reviewer_alice --reason "reviewed scope and risk" --json
```

Approval records are consumed once by matching high-risk calls after the
executor rechecks the bound file digests and before trusted provider execution.
Calls denied or review-required before approval consumption keep
`side_effect_executed: false` and do not consume approved records. If a mediated
adapter rejects an already approved request during final preparation, the
provider call is recorded with adapter denial semantics; the exact approval may
already be consumed because consumption happens after digest recheck and before
trusted execution.

## Reviewer Console

The Reviewer Console launch bundle renders pending approval records with the
same binding fields. Reviewers can inspect provider, action, actor, authz, and
argument hash before entering a reason and choosing approve or deny.

Browser submission still requires the Runwarden launch token and calls the Local
API approval decision endpoints; the kernel-owned approval record remains the
source of truth.
