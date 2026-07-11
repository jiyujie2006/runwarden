# Artifact and Demo Output Paths

The contest edition does not expose `runwarden artifact *` as a primary workflow. Demo, report, and UI outputs still use the same path safety invariant:

- paths must be relative workspace paths
- parent traversal is rejected
- absolute paths are rejected
- symlinks are allowed only when their canonical target remains inside the
  workspace; symlink escapes are rejected before writing

The runtime helper for demo, report, and UI output paths is
`runwarden_kernel::artifact::resolve_workspace_relative_path`. CLI callers wrap
that Rust helper and keep command-specific error labels.

Typed artifact, receipt, and safe-operation contracts use
`WorkspaceRelativePath`. It serializes as a string, but construction and direct
JSON deserialization both require a non-empty, slash-separated relative path.
Absolute paths, platform prefixes, colons, backslashes, NUL, empty components,
JSON line terminators, and `.` or `..` components are rejected. This newtype
proves lexical safety only; filesystem writes must still use the stable-root
containment and symlink checks above. The generated schema applies the same
line-terminator and dot-component checks to every slash-separated component
and uses a strict ECMAScript absolute-end assertion.

The frozen `StoryBundleManifest` uses the same `WorkspaceRelativePath` for each
`BundleFileDigest`. Its detached-signature material sorts those validated paths
before canonical JSON encoding, so caller input order does not change the bytes
to be signed. This contract only describes payload paths and digests; it does
not create bundle files or replace the containment checks required by a future
exporter.

Local provider filesystem tools use an analogous Rust-owned sandbox containment
boundary, not the workspace artifact helper: requested paths are relative to
the sandbox root, existing components are canonicalized against that root
before reads or writes, and writes may only create a missing final file after
the existing parent path is confirmed contained. The sandbox root is selected by
Runwarden-owned runtime configuration, not provider-call arguments.

`runwarden demo --scenario` writes scenario JSON under the requested demo output directory. `runwarden demo --all` writes all scenario outputs plus `reviewer-console.html`. `runwarden report render --scenario-suite` writes the contest report when `--output` is supplied.

`runwarden demo` serves the interactive console from Rust and writes reviewer
approval state under `.runwarden/approvals`.
