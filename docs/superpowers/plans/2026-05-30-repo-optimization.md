# Repository Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Scan the full Runwarden repository, apply low-risk optimizations that preserve the Rust-owned security boundary, verify the result with project gates, and push the work to a new branch.

**Architecture:** Runwarden keeps security decisions in Rust crates. TypeScript packages may validate and call contracts, but must not duplicate allow/deny policy. Any change touching provider, report, artifact, approval, or MCP behavior must first read and update the matching `docs/reference/` page.

**Tech Stack:** Rust workspace crates, TypeScript packages managed by pnpm, shell gate scripts, and Markdown reference documentation.

---

### Task 1: Establish Baseline

**Files:**
- Read: `AGENTS.md`
- Read: `Cargo.toml`
- Read: `package.json`
- Read: `docs/README.md`

- [x] **Step 1: Confirm branch and clean state**

Run: `git status --short --branch`

Expected: branch is `codex/repo-optimization-20260530` and there are no unrelated uncommitted changes.

- [x] **Step 2: Inspect project surfaces**

Run: `rg --files -g 'Cargo.toml' -g 'package.json' -g 'docs/reference/*.md' -g 'scripts/*.sh' | sort`

Expected: output lists Rust crates, TypeScript packages, reference docs, and gate scripts.

- [x] **Step 3: Run a fast baseline gate**

Run: `bash scripts/pr_fast_gate.sh`

Expected: exit code 0. If it fails, record the failing command and decide whether it is pre-existing before implementing optimizations.

### Task 2: Parallel Repository Scans

**Files:**
- Read-only scan: `crates/`
- Read-only scan: `packages/`
- Read-only scan: `scripts/`, `.github/`, `docs/`, `examples/`, `schemas/`, `tests/`

- [x] **Step 1: Dispatch Rust scan agent**

Ask the agent to inspect `crates/` for correctness, maintainability, performance, and invariant risks. The agent must not edit files.

- [x] **Step 2: Dispatch TypeScript scan agent**

Ask the agent to inspect `packages/` and root TypeScript config for duplicated policy, stale generated contracts, build friction, and maintainability issues. The agent must not edit files.

- [x] **Step 3: Dispatch docs and gates scan agent**

Ask the agent to inspect `docs/`, `scripts/`, `.github/`, `examples/`, `schemas/`, and `tests/` for drift, missing index entries, flaky gates, and low-risk cleanup opportunities. The agent must not edit files.

- [x] **Step 4: Integrate findings**

For each proposed change, verify it is supported by file evidence, preserves AGENTS.md invariants, and has a bounded test command.

### Task 3: Implement Selected Optimizations

**Files:**
- Modify only files tied to verified findings.
- Update matching `docs/reference/` pages when changing provider, report, artifact, approval, or MCP behavior.

- [x] **Step 1: Add or adjust tests first for behavior changes**

For any behavior change, add a focused test that fails on the old behavior and passes on the new behavior.

- [x] **Step 2: Implement the smallest durable fix**

Keep security decisions in Rust crates. Do not duplicate allow/deny policy in TypeScript.

- [x] **Step 3: Run focused verification**

Run the narrowest relevant command, such as `cargo test -p <crate> <test-name>`, `pnpm --filter <package> test`, or a specific script.

Expected: exit code 0.

### Task 4: Review and Full Verification

**Files:**
- Review: all changed files in `git diff origin/main...HEAD`

- [x] **Step 1: Request reviewer subagent**

Give the reviewer the base SHA, head SHA, objective, AGENTS.md invariants, and the list of changed files.

- [x] **Step 2: Address critical and important feedback**

Fix valid critical and important findings before final gates.

- [x] **Step 3: Run required gates**

Run:

```bash
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
cargo test --workspace
pnpm test
pnpm build
```

Expected: every command exits 0.

### Task 5: Publish Branch

**Files:**
- Commit: all intentional changes

- [x] **Step 1: Inspect final diff**

Run: `git diff --stat origin/main...HEAD` and `git diff --check`

Expected: no whitespace errors and only intentional files changed.

- [x] **Step 2: Commit changes**

Run: `git add <files>` then `git commit -m "chore: optimize repository hygiene"`

Expected: commit created on `codex/repo-optimization-20260530`.

- [x] **Step 3: Push branch**

Run: `git push -u origin codex/repo-optimization-20260530`

Expected: remote branch is created and tracks local branch.
