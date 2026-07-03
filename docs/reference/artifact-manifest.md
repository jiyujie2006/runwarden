# Artifact and Demo Output Paths

The contest edition does not expose `runwarden artifact *` as a primary workflow. Demo, report, and UI outputs still use the same path safety invariant:

- paths must be relative workspace paths
- parent traversal is rejected
- absolute paths are rejected
- symlinks are allowed only when their canonical target remains inside the
  workspace; symlink escapes are rejected before writing

Local provider filesystem tools use the same containment boundary: requested
paths are relative to the sandbox root, existing components are canonicalized
against that root before reads or writes, and writes may only create a missing
final file after the existing parent path is confirmed contained. The sandbox
root is selected by Runwarden-owned runtime configuration, not provider-call
arguments.

`runwarden demo --scenario` writes scenario JSON under the requested demo output directory. `runwarden demo --all` writes all scenario outputs plus `reviewer-console.html`. `runwarden report render --scenario-suite` writes the contest report when `--output` is supplied.

`runwarden demo` serves the interactive console from Rust and writes reviewer
approval state under `.runwarden/approvals`.
