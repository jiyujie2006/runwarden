# Artifact and Demo Output Paths

The contest edition does not expose `runwarden artifact *` as a primary workflow. Demo, report, and UI outputs still use the same path safety invariant:

- paths must be relative workspace paths
- parent traversal is rejected
- absolute paths are rejected
- symlink components are rejected before writing

Local provider filesystem tools use the same containment boundary: requested
paths are relative to the sandbox root, existing components are canonicalized
against that root before reads or writes, and writes may only create a missing
final file after the existing parent path is confirmed contained. The sandbox
root is selected by Runwarden-owned runtime configuration, not provider-call
arguments.

`runwarden demo run` writes scenario JSON under the requested demo output directory. `runwarden report render --scenario-suite` writes the contest report when `--output` is supplied. `runwarden ui build` writes a static reviewer console.

`runwarden ui serve --live --demo <relative-demo-dir>` reads existing demo
artifacts and rejects absolute paths, parent traversal, and symlink components
before serving replay events.
