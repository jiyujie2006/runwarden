# Reviewer Console Guide

The WebUI package renders a security workbench, not a security decision engine.
It displays the Rust API state and submits reviewer actions back to the Local
API.

Reviewer workflow:

1. Load a manifest-backed session.
2. Inspect the top status strip for risk, trace integrity, pending approvals,
   and gate status.
3. Check Agent Boundary and Provider Registry modules before reviewer action.
4. Open a pending approval row.
5. Review provider, risk, target, side effects, actor, authz, argument hash, and
   related `obs_*` references in the details drawer.
6. Approve or deny with a reviewer reason.

The WebUI must not mutate authority directly. Approval mutations go through the
Local API launch-token, Host, and Origin checks, then update kernel-owned
`ApprovalRecord` state.

For local review, generate the static launch bundle with:

```bash
runwarden ui --bind 127.0.0.1 --port 8088 --artifacts artifacts --json
```
