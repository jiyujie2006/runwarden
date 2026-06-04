# Contributing

Runwarden is a Rust-owned security kernel with TypeScript integration surfaces.
Keep security decisions in Rust crates. TypeScript packages may present,
validate, or call Rust-owned contracts, but must not duplicate allow/deny
policy.

## Local Gates

Run the fast local gate before opening a change:

```bash
bash scripts/pr_fast_gate.sh
```

The gate runs Rust formatting, clippy, dependency policy, Rust tests, generated
TypeScript contract drift checks, TypeScript tests, and TypeScript builds.

For release or security-boundary changes, run:

```bash
bash scripts/release_gate_local.sh
```

Install `cargo-deny` if the gate reports it is missing:

```bash
cargo install cargo-deny --version 0.19.6 --locked
```

## Security-Boundary Changes

Changes touching provider, report, artifact, approval, authority, MCP, Local
API, Reviewer Console, agent config, or release behavior require tests that
prove both allowed and denied behavior where applicable.

Before changing those surfaces:

1. Read the matching page under `docs/reference/`.
2. Update that page with the code change.
3. Keep `docs/README.md` as the documentation index.
4. Run the relevant gate.

## Documentation Changes

For documentation-only changes, keep commands executable and links local to the
repository. Run at least:

```bash
git diff --check
```

Run broader gates when docs change command examples, security invariants,
release process, artifact flow, or schema/contract behavior.
