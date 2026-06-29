# Artifact and Demo Output Paths

The contest edition does not expose `runwarden artifact *` as a primary workflow. Demo, report, and UI outputs still use the same path safety invariant:

- paths must be relative workspace paths
- parent traversal is rejected
- absolute paths are rejected
- symlink components are rejected before writing

`runwarden demo run` writes scenario JSON under the requested demo output directory. `runwarden report render --scenario-suite` writes the contest report when `--output` is supplied. `runwarden ui build` writes a static reviewer console.

`runwarden ui serve --live --demo <relative-demo-dir>` reads existing demo
artifacts and rejects absolute paths, parent traversal, and symlink components
before serving replay events.
