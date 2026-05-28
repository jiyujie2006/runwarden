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
6. Enter the Local API launch token in Settings.
7. Approve or deny with reviewer identity and reason.

The WebUI must not mutate authority directly. Approval mutations go through the
Local API launch-token, Host, and Origin checks, then update kernel-owned
`ApprovalRecord` state.

For local review, generate the static launch bundle with:

```bash
runwarden ui --bind 127.0.0.1 --port 8088 --artifacts artifacts --json
```

Open the returned `launch_url`; it points to the generated
`reviewer-console.html` file. The JSON also includes `script_path` for the local
`reviewer-console.js` companion script and `local_api_url` for the API endpoint
the browser forms submit to. `runwarden ui` writes the bundle but does not start
the Local API server; run `runwarden api serve --bind 127.0.0.1 --port 8088`
when browser approval submission is needed.

`--artifacts` must be a relative workspace path. The launch writer rejects
absolute paths, parent traversal, and symlink escapes before writing. The bind
value is escaped before it is embedded in the generated HTML.
