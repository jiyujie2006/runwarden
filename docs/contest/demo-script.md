# Demo Script

1. Run `bash scripts/release_gate_local.sh`.
2. Open `artifacts/reviewer-console.html`.
3. Show `prompt-injection-file-exfil`: input inspection, review hold, API denial.
4. Show `tool-hijack-email-api`: email `requires_review`, hidden API `denied`.
5. Show `path-escape-file-boundary`: filesystem `root_escape` denial.
6. Show `environment-local-web-risk`: localhost and metadata egress denial.
7. Open `artifacts/reports/contest-report.md` and point to cited `obs_*` refs.
8. Run `bash scripts/contest_bundle.sh` and inspect `artifacts/contest-bundle/manifest.json`.
