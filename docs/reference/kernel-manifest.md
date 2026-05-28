# Kernel Manifest

Kernel manifests are represented by assessment and session manifests. They define the policy envelope used by `KernelEnforcer`.

Important fields:

- provider allowlist
- scoped roots
- targets
- budgets
- actor
- authorization
- active assessment

The session manifest is derived from the assessment manifest and is the runtime policy input.
