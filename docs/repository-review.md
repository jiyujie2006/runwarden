# Repository Review

Review date: 2026-06-03

This review covers the checked-out `main` branch of `jiyujie2006/runwarden`.
It is a repository and documentation review, followed by local command
verification and a Windows test-failure fix where practical.

## Scope

Reviewed surfaces:

- Rust crates under `crates/`.
- TypeScript packages under `packages/`.
- Agent skill, example manifests, scenario golden corpora, schemas, scripts, and
  GitHub workflows.
- Top-level docs, `docs/`, `examples/*/README.md`, and scenario README files.

Not changed in the documentation optimization portion:

- Historical plan files under `docs/superpowers/plans/`.
- Scenario `benign/request.md` and `attacks/prompt-injection.md` prompt fixtures.

## Architecture Findings

Runwarden has a clear ownership model:

- Rust owns security decisions through `runwarden-kernel`,
  `runwarden-providers`, `runwarden-assurance`, `runwarden-cli`,
  `runwarden-mcp`, and `runwarden-api`.
- TypeScript packages provide integration, generated contracts, config command
  helpers, and static WebUI rendering. They do not own allow/deny decisions.
- The agent-facing surface is intentionally narrow: agents should receive
  `runwarden-mcp` and call `runwarden.provider.call` instead of raw shell,
  filesystem, browser, HTTP, or downstream MCP tools.
- Release assurance is layered: fast gates cover Rust and TypeScript tests,
  release gates add strict repository checks, cert, eval, scenarios, bench,
  release smoke, artifact verification, and leak scan.

The code and tests support the main documented invariants:

- Provider calls are checked against registry and session allowlists before
  side effects.
- Scoped roots, egress, budgets, active assessment, authz, and approval gates
  are enforced by the Rust kernel.
- High-risk approvals are bound to session, provider, action, argument hash,
  authz, and actor, and are single-use.
- Trace export and report rendering are evidence-gated.
- Artifact/UI output paths reject absolute paths, parent traversal, and symlink
  escapes.
- Runwarden-only agent configs allow empty `args: []` but reject redirects such
  as extra tools, non-empty or malformed args, `env`, `cwd`, `url`, or
  `transport`.

## Documentation Findings

Before this pass, the docs had the right facts but weak navigation:

- `README.md` mixed product overview, architecture, CLI reference, provider
  list, quick start, and status into one long page.
- `docs/README.md` was a flat list, so readers could not choose an operator,
  integrator, reviewer, or contributor path.
- Several reference pages were accurate but too terse to stand alone.
- Scenario and example README files did not explain what their manifests and
  expected outputs prove.
- The distinction between generated documentation, fixture prompts, historical
  plans, and maintained reference pages was implicit.

The optimized structure is:

- `README.md`: concise Chinese landing page and quick start.
- `docs/README.md`: grouped canonical documentation index.
- `docs/repository-review.md`: persistent review and audit snapshot.
- `docs/reference/*`: maintained behavior references for code-sensitive
  surfaces.
- `examples/*/README.md` and `scenarios/*/README.md`: executable examples and
  golden-corpus explanations.

## Residual Risks

- This pass fixed the observed Windows test failures but was not a complete
  code security audit. Security defects still require a separate code-focused
  review with targeted tests.
- The Windows `cargo test --workspace` failures found during review are fixed.
  The root causes were unescaped Windows paths in TOML/JSON test manifests,
  a platform-specific stdio adapter expectation, and a runtime path assertion
  that compared against Unix separators.
- Documentation can still drift if provider, report, artifact, approval, MCP,
  Local API, or WebUI behavior changes without updating the corresponding
  reference page.
- Full release verification depends on local availability of Rust, pnpm, and
  `cargo-deny`; missing tools should be treated as environment gaps, not proof
  that the repository is unhealthy.

## Recommended Review Cadence

For normal changes:

```bash
bash scripts/pr_fast_gate.sh
```

For security-boundary or release changes:

```bash
bash scripts/release_gate_local.sh
```

For documentation-only changes:

```bash
git diff --check
cargo test --workspace
pnpm test
```

Use the full release gate when docs change executable commands, release
processes, artifact flows, schemas, or security invariants.

## Verification Snapshot

Commands run during this pass:

| Command | Result | Notes |
| --- | --- | --- |
| `git diff --check` | Pass | Git reported line-ending warnings only. |
| Markdown local-link check | Pass | All local Markdown links resolve. |
| `pnpm test` | Pass | 30 TypeScript tests passed across SDK, WebUI, MCP helpers, and config tools. |
| `pnpm build` | Pass | All TypeScript workspace packages built. |
| `cargo run -p runwarden-cli -- check --strict` | Pass | Required docs/reference paths, schemas, provider catalog, scenario corpus, generated contracts, release scripts, and release surfaces are present. |
| `cargo test --workspace` | Pass | Workspace tests pass on Windows after fixing Local API scoped-root fixtures and related cross-platform provider tests. |
