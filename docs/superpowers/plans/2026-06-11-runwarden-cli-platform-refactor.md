# Runwarden CLI Platform Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor Runwarden into a local workspace CLI platform where humans use only `runwarden`, agents see only Runwarden's skill plus `runwarden-mcp`, and all downstream MCP, skill, shell, filesystem, browser, and HTTP capabilities execute through Runwarden providers.

**Architecture:** Add a deep Rust platform module that owns workspace state, provider catalog loading, provider-call orchestration, approval lifecycle, event logging, and downstream adapter dispatch. Keep `runwarden` as the human interface, keep `runwarden-mcp` as a thin agent transport shim, and route CLI, Local API, and MCP through the same platform interface. Store authoritative state under `.runwarden/` using append-only JSONL events plus JSON records for sessions, approvals, provider calls, catalogs, traces, and artifacts.

**Tech Stack:** Rust workspace crates (`runwarden-kernel`, `runwarden-providers`, `runwarden-assurance`, new `runwarden-platform`, `runwarden-cli`, `runwarden-api`, `runwarden-mcp`), TypeScript UI/package surfaces, JSON schemas, Markdown reference docs, shell gate scripts.

---

## Confirmed Design Decisions

- Humans use `runwarden` as the only product-facing command.
- Agents may see only Runwarden's own instruction skill and the `runwarden-mcp` server.
- Downstream MCP, downstream skills, shell, filesystem, browser, HTTP, and plugins are hidden behind Runwarden providers.
- Workspace state is authoritative under `.runwarden/`.
- Provider catalog registration and session allowlisting are separate.
- First version is local single-workspace, single-reviewer, no remote daemon, no SSO, no multi-reviewer quorum.
- Provider calls requiring approval return `requires_review` immediately; agents retry with an approval id after human approval.
- All provider calls write append-only JSONL events for later review.
- First-version shell is a structured generic shell provider, not raw shell-string execution.
- Downstream skills are managed context artifacts, not executable agent runtime skills.

## File Structure

- Create `crates/runwarden-platform/Cargo.toml`: shared Rust crate used by CLI, API, and MCP.
- Create `crates/runwarden-platform/src/lib.rs`: public platform interface.
- Create `crates/runwarden-platform/src/state.rs`: `.runwarden/` path layout, atomic JSON reads/writes, append-only event writer.
- Create `crates/runwarden-platform/src/events.rs`: event types and JSONL serialization.
- Create `crates/runwarden-platform/src/catalog.rs`: workspace provider catalog loading and certification entrypoints.
- Create `crates/runwarden-platform/src/executor.rs`: single provider-call orchestration path through kernel, approval, digest binding, execution, and events.
- Create `crates/runwarden-platform/src/shell.rs`: structured generic shell request validation and runtime preparation.
- Create `crates/runwarden-platform/src/skill.rs`: downstream skill metadata, digest, certification, and bounded context response.
- Modify `Cargo.toml`: add `crates/runwarden-platform` workspace member.
- Modify `crates/runwarden-cli/Cargo.toml`, `crates/runwarden-api/Cargo.toml`, `crates/runwarden-mcp/Cargo.toml`: depend on `runwarden-platform`.
- Modify `crates/runwarden-cli/src/main.rs`: route provider/session/approval/ui commands through platform; add provider onboarding commands.
- Modify `crates/runwarden-api/src/lib.rs`: use platform state instead of in-memory-only state for sessions, approvals, provider calls, and UI data.
- Modify `crates/runwarden-mcp/src/lib.rs`: keep MCP tool surface stable, but delegate provider/session/report/trace operations to platform.
- Modify `crates/runwarden-providers/src/lib.rs`: add manifest fields needed for fixed stdio args and managed skill context if missing.
- Modify `docs/reference/cli.md`, `docs/reference/mcp.md`, `docs/reference/provider-model.md`, `docs/reference/provider-integration.md`, `docs/reference/webui-review-console.md`, `docs/reference/agent-integration.md`, and `docs/README.md`.

### Task 1: Baseline And Reference Lock

**Files:**
- Read: `AGENTS.md`
- Read: `docs/reference/cli.md`
- Read: `docs/reference/mcp.md`
- Read: `docs/reference/provider-model.md`
- Read: `docs/reference/provider-integration.md`
- Read: `docs/reference/webui-review-console.md`
- Read: `docs/reference/agent-integration.md`

- [ ] **Step 1: Record current branch and dirty state**

Run: `git status --short --branch`

Expected: output may show existing user changes. Do not revert unrelated changes.

- [ ] **Step 2: Run focused baseline tests for existing surfaces**

Run:

```bash
cargo test -p runwarden-cli
cargo test -p runwarden-mcp
cargo test -p runwarden-api
cargo test -p runwarden-providers
```

Expected: each command exits 0, or any pre-existing failure is recorded before edits.

- [ ] **Step 3: Add a note to the implementation branch**

Create a local note in the PR description or commit message draft: "Provider, approval, MCP, CLI, and WebUI behavior changed; update matching docs/reference pages and docs/README.md."

### Task 2: Add The Platform Crate Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/runwarden-platform/Cargo.toml`
- Create: `crates/runwarden-platform/src/lib.rs`
- Create: `crates/runwarden-platform/src/state.rs`
- Create: `crates/runwarden-platform/src/events.rs`
- Test: `crates/runwarden-platform/tests/state_events.rs`

- [ ] **Step 1: Write failing state/event tests**

Create `crates/runwarden-platform/tests/state_events.rs` with tests that:

- create a temp workspace
- open platform state at that root
- create `.runwarden/`
- append two JSONL events
- read the file back and confirm two newline-delimited JSON objects
- reject absolute or traversal artifact paths using the same invariant as CLI/UI artifacts

Run: `cargo test -p runwarden-platform --test state_events`

Expected: FAIL because the crate and types do not exist.

- [ ] **Step 2: Add the crate and minimal interface**

Add `crates/runwarden-platform` to workspace members. Implement public types:

```rust
pub struct RunwardenPlatform {
    state: PlatformState,
}

impl RunwardenPlatform {
    pub fn open(workspace_root: impl Into<std::path::PathBuf>) -> Result<Self, PlatformError>;
    pub fn state(&self) -> &PlatformState;
}
```

Implement `PlatformState` methods:

```rust
impl PlatformState {
    pub fn ensure_layout(&self) -> Result<(), PlatformError>;
    pub fn append_event(&self, event: &PlatformEvent) -> Result<(), PlatformError>;
    pub fn sessions_dir(&self) -> std::path::PathBuf;
    pub fn approvals_dir(&self) -> std::path::PathBuf;
    pub fn provider_calls_dir(&self) -> std::path::PathBuf;
    pub fn provider_catalog_dir(&self) -> std::path::PathBuf;
    pub fn traces_dir(&self) -> std::path::PathBuf;
    pub fn artifacts_dir(&self) -> std::path::PathBuf;
}
```

- [ ] **Step 3: Verify**

Run: `cargo test -p runwarden-platform --test state_events`

Expected: PASS.

### Task 3: Move Session And Approval State Behind Platform

**Files:**
- Modify: `crates/runwarden-platform/src/state.rs`
- Modify: `crates/runwarden-platform/src/lib.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Test: `crates/runwarden-platform/tests/session_approval_state.rs`
- Test: existing `crates/runwarden-cli/tests/session_commands.rs`
- Test: existing `crates/runwarden-cli/tests/approval_commands.rs`

- [ ] **Step 1: Write platform tests for session and approval persistence**

Create tests that call platform methods:

```rust
platform.write_session(&session)?;
let loaded = platform.read_session("enterprise_ops")?;

platform.write_approval(&approval)?;
let pending = platform.list_approvals(ApprovalListFilter::Pending)?;
```

Expected behavior:

- records are stored under `.runwarden/sessions/*.json` and `.runwarden/approvals/*.json`
- unsafe ids containing `/`, `..`, or path separators are rejected
- pending approval lists are sorted by approval id for stable UI output

Run: `cargo test -p runwarden-platform --test session_approval_state`

Expected: FAIL until platform persistence exists.

- [ ] **Step 2: Implement platform session and approval methods**

Add methods:

```rust
pub fn write_session(&self, session: &SessionManifest) -> Result<(), PlatformError>;
pub fn read_session(&self, session_id: &str) -> Result<SessionManifest, PlatformError>;
pub fn list_sessions(&self) -> Result<Vec<SessionManifest>, PlatformError>;
pub fn write_approval(&self, approval: &ApprovalRecord) -> Result<(), PlatformError>;
pub fn read_approval(&self, approval_id: &str) -> Result<ApprovalRecord, PlatformError>;
pub fn list_approvals(&self, filter: ApprovalListFilter) -> Result<Vec<ApprovalRecord>, PlatformError>;
```

- [ ] **Step 3: Replace duplicate CLI helpers**

In `crates/runwarden-cli/src/main.rs`, replace local `read_all_sessions`, `write_session`, `read_all_approvals`, `read_approval`, and `write_approval` call sites with `RunwardenPlatform` methods.

- [ ] **Step 4: Verify**

Run:

```bash
cargo test -p runwarden-platform --test session_approval_state
cargo test -p runwarden-cli --test session_commands
cargo test -p runwarden-cli --test approval_commands
```

Expected: PASS.

### Task 4: Build One Provider-Call Executor

**Files:**
- Create: `crates/runwarden-platform/src/executor.rs`
- Modify: `crates/runwarden-platform/src/lib.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Modify: `crates/runwarden-api/src/lib.rs`
- Modify: `crates/runwarden-mcp/src/lib.rs`
- Test: `crates/runwarden-platform/tests/provider_executor.rs`
- Test: existing `crates/runwarden-cli/tests/provider_commands.rs`
- Test: existing `crates/runwarden-api/tests/local_api_server.rs`
- Test: existing `crates/runwarden-mcp/tests/e2e_agent_flow.rs`

- [ ] **Step 1: Write executor tests before moving code**

Create tests for:

- unregistered provider returns denied with `side_effect_executed: false`
- not-allowlisted provider returns denied
- high-risk provider returns `requires_review` and writes a pending approval
- allowed first-party provider executes once through the executor
- approved call consumes matching approval only after digest recheck
- denied or review-required calls append events and do not execute side effects

Run: `cargo test -p runwarden-platform --test provider_executor`

Expected: FAIL until executor exists.

- [ ] **Step 2: Add platform executor interface**

Implement:

```rust
pub struct ProviderExecutionRequest {
    pub call: ProviderCall,
    pub session: Option<SessionManifest>,
}

pub struct ProviderExecutionResult {
    pub outcome: ProviderOutcome,
    pub output: serde_json::Value,
}

impl RunwardenPlatform {
    pub fn submit_provider_call(
        &mut self,
        request: ProviderExecutionRequest,
    ) -> Result<ProviderExecutionResult, PlatformError>;
}
```

The implementation order must be:

1. append `provider_call_requested`
2. build kernel policy from session or CLI defaults
3. enforce registry, allowlist, root, egress, budget, authz, and approval
4. enqueue pending approval on `requires_review`
5. bind file digests before approved execution
6. execute first-party or external provider through adapter modules
7. append completion/failure event
8. persist provider-call record under `.runwarden/provider-calls/`

- [ ] **Step 3: Move duplicated execution logic behind executor**

Move common logic from CLI, API, and MCP into platform executor. CLI/API/MCP should format requests and responses only; they must not duplicate allow/deny policy.

- [ ] **Step 4: Verify**

Run:

```bash
cargo test -p runwarden-platform --test provider_executor
cargo test -p runwarden-cli --test provider_commands
cargo test -p runwarden-api --test local_api_server
cargo test -p runwarden-mcp --test e2e_agent_flow
```

Expected: PASS.

### Task 5: Add Workspace Provider Catalog Onboarding

**Files:**
- Create: `crates/runwarden-platform/src/catalog.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Modify: `docs/reference/provider-model.md`
- Modify: `docs/reference/provider-integration.md`
- Modify: `docs/reference/cli.md`
- Modify: `docs/README.md`
- Test: `crates/runwarden-platform/tests/provider_catalog.rs`
- Test: `crates/runwarden-cli/tests/provider_commands.rs`

- [ ] **Step 1: Write catalog tests**

Test these commands through CLI or platform helpers:

```bash
runwarden provider add mcp --id external.mcp.browser.open_page --transport stdio --command browser-mcp --tool open_page --runtime-root .
runwarden provider add skill --id external.skill.assessment_helper --path skills/runwarden-security-assessment/SKILL.md
runwarden provider inspect external.mcp.browser.open_page --json
runwarden provider cert external.mcp.browser.open_page --json
```

Expected:

- provider manifests are written under `.runwarden/provider-catalog/`
- invalid provider ids are rejected
- provider registration does not add the provider to any session allowlist
- manifest certification failures prevent registration unless an explicit `--write-uncertified` debug flag is supplied

- [ ] **Step 2: Implement catalog loading**

Effective provider registry must merge:

1. checked-in first-party providers
2. checked-in default external provider manifests
3. workspace provider manifests under `.runwarden/provider-catalog/`

Workspace manifests must not override first-party `runwarden.*` providers.

- [ ] **Step 3: Add CLI onboarding commands**

Add command groups:

```bash
runwarden provider add mcp ...
runwarden provider add skill ...
runwarden provider inspect <provider-id> --json
runwarden provider cert <provider-id> --json
runwarden session allow --session <id> --provider <provider-id>
runwarden session deny --session <id> --provider <provider-id>
```

- [ ] **Step 4: Update docs**

Update reference docs with the catalog/session split and examples. Keep `docs/README.md` as the index.

- [ ] **Step 5: Verify**

Run:

```bash
cargo test -p runwarden-platform --test provider_catalog
cargo test -p runwarden-cli --test provider_commands
```

Expected: PASS.

### Task 6: Implement Structured Generic Shell Provider

**Files:**
- Create: `crates/runwarden-platform/src/shell.rs`
- Modify: `crates/runwarden-providers/src/lib.rs`
- Modify: `docs/reference/provider-model.md`
- Modify: `docs/reference/provider-integration.md`
- Test: `crates/runwarden-platform/tests/shell_provider.rs`
- Test: `crates/runwarden-providers/tests/runtime_isolation.rs`

- [ ] **Step 1: Write shell tests**

Test provider id `external.shell.run` with structured arguments:

```json
{
  "command": "cargo",
  "args": ["test", "--workspace"],
  "cwd": ".",
  "timeout_ms": 30000,
  "stdout_limit_bytes": 1048576,
  "stderr_limit_bytes": 1048576
}
```

Expected:

- `cargo test --workspace`, `cargo check`, `pnpm test`, `pnpm build`, `git status`, `git diff`, and `rg` are allowed without approval when cwd stays inside workspace
- unknown non-shell commands return `requires_review`
- `sh`, `bash`, `cmd`, `powershell`, `pwsh`, `-c`, `/c`, shell strings, env injection, cwd escape, and excessive output/timeout are denied before side effects
- all results preserve `side_effect_executed`

- [ ] **Step 2: Implement shell validation**

Add structured parser and validation. Do not accept one-string shell commands. Do not invoke a shell.

- [ ] **Step 3: Connect shell provider to executor**

Executor must treat low-risk known shell calls as allowed and unknown valid shell calls as `requires_review`. Approved unknown calls execute only if the approval binding still matches command, args, cwd, actor, authz, and session.

- [ ] **Step 4: Verify**

Run:

```bash
cargo test -p runwarden-platform --test shell_provider
cargo test -p runwarden-providers --test runtime_isolation
```

Expected: PASS.

### Task 7: Implement Managed Downstream Skill Context

**Files:**
- Create: `crates/runwarden-platform/src/skill.rs`
- Modify: `crates/runwarden-providers/src/lib.rs`
- Modify: `docs/reference/provider-model.md`
- Modify: `docs/reference/provider-integration.md`
- Modify: `skills/runwarden-security-assessment/SKILL.md` only if the agent-facing instructions need new provider examples
- Test: `crates/runwarden-platform/tests/skill_provider.rs`

- [ ] **Step 1: Write skill provider tests**

Test that `runwarden provider add skill --path <SKILL.md>`:

- reads metadata and body
- records SHA-256 digest
- rejects traversal and absolute output paths
- returns bounded context via provider call
- does not install or expose the downstream skill directly to the agent

- [ ] **Step 2: Implement skill manifest and context response**

Skill provider output should include:

```json
{
  "provider": "external.skill.assessment_helper",
  "kind": "managed_skill_context",
  "digest": "sha256...",
  "content": "...bounded skill text...",
  "side_effect_executed": false
}
```

- [ ] **Step 3: Verify**

Run: `cargo test -p runwarden-platform --test skill_provider`

Expected: PASS.

### Task 8: Make `runwarden ui` The Simple Human Entry

**Files:**
- Modify: `crates/runwarden-cli/src/main.rs`
- Modify: `crates/runwarden-api/src/lib.rs`
- Modify: `packages/webui/src/index.ts` if rendering contract changes
- Modify: `docs/reference/webui-review-console.md`
- Modify: `docs/reference/cli.md`
- Test: `crates/runwarden-cli/tests/e2e_release_smoke.rs`
- Test: `crates/runwarden-api/tests/local_api_server.rs`
- Test: `tests/e2e/reviewer-console.spec.ts`
- Test: `tests/e2e/reviewer-console-approval.spec.ts`

- [ ] **Step 1: Write UI launch tests**

Expected behavior:

- `runwarden ui --json` starts or describes Local API, writes/serves reviewer console, returns launch URL and token handling
- UI reads pending approvals from `.runwarden/`
- approval decisions update `.runwarden/approvals` and append event log entries
- `runwarden api serve --dry-run` remains available for low-level debugging

- [ ] **Step 2: Implement `runwarden ui` orchestration**

Make `runwarden ui` the one-command human path. Keep `runwarden api serve` and `runwarden ui build` as explicit advanced/debug paths.

- [ ] **Step 3: Verify**

Run:

```bash
cargo test -p runwarden-cli --test e2e_release_smoke
cargo test -p runwarden-api --test local_api_server
pnpm test -- reviewer-console
```

Expected: PASS.

### Task 9: Thin MCP To Platform Transport

**Files:**
- Modify: `crates/runwarden-mcp/src/lib.rs`
- Modify: `docs/reference/mcp.md`
- Modify: `docs/reference/agent-integration.md`
- Test: `crates/runwarden-mcp/tests/jsonrpc.rs`
- Test: `crates/runwarden-mcp/tests/stdio_server.rs`
- Test: `crates/runwarden-mcp/tests/e2e_agent_flow.rs`
- Test: `crates/runwarden-mcp/tests/trace_export_contract.rs`

- [ ] **Step 1: Lock MCP surface tests**

Assert `tools/list` exposes only `runwarden.*` tools and does not expose downstream MCP, shell, filesystem, HTTP, browser, or downstream skill tools.

- [ ] **Step 2: Delegate MCP calls to platform**

Keep tool names stable:

- `runwarden.agent.bootstrap`
- `runwarden.provider.list`
- `runwarden.provider.call`
- `runwarden.provider.status`
- `runwarden.session.create_from_manifest`
- `runwarden.trace.verify`
- `runwarden.trace.export`
- `runwarden.report.lint`
- `runwarden.report.render`

Replace inline duplicated provider execution with platform calls.

- [ ] **Step 3: Verify**

Run:

```bash
cargo test -p runwarden-mcp
runwarden eval agent-native --json
```

Expected: PASS.

### Task 10: Documentation And Contract Refresh

**Files:**
- Modify: `docs/reference/cli.md`
- Modify: `docs/reference/mcp.md`
- Modify: `docs/reference/provider-model.md`
- Modify: `docs/reference/provider-integration.md`
- Modify: `docs/reference/webui-review-console.md`
- Modify: `docs/reference/agent-integration.md`
- Modify: `docs/reference/json-contracts.md` if schemas change
- Modify: `docs/README.md`
- Modify: schemas only if contract types change

- [ ] **Step 1: Update reference docs in the same commits as behavior changes**

Docs must describe:

- Runwarden as local CLI platform
- `.runwarden/` state layout
- provider catalog registration versus session allowlist
- non-blocking approval flow
- structured generic shell provider
- managed downstream skill context
- `runwarden ui` one-command human entry

- [ ] **Step 2: Refresh schemas if contract types changed**

Run: `cargo run -p runwarden-kernel --example generate_schemas`

Expected: schema files update only when Rust contract types changed.

- [ ] **Step 3: Verify docs index**

Run: `rg -n "provider catalog|external.shell.run|managed skill|runwarden ui|\\.runwarden" docs/README.md docs/reference`

Expected: each new concept appears in the relevant reference page and `docs/README.md` points readers to it.

### Task 11: Full Gates

**Files:**
- All changed files

- [ ] **Step 1: Run focused crate tests**

Run:

```bash
cargo test -p runwarden-platform
cargo test -p runwarden-cli
cargo test -p runwarden-api
cargo test -p runwarden-mcp
cargo test -p runwarden-providers
```

Expected: PASS.

- [ ] **Step 2: Run required project gates**

Run:

```bash
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
cargo test --workspace
pnpm test
pnpm build
```

Expected: every command exits 0.

- [ ] **Step 3: Final diff review**

Run:

```bash
git diff --check
git diff --stat
```

Expected: no whitespace errors; changed files match this plan's scope.

## Self-Review

- Spec coverage: covers the confirmed decisions from the grill session: single human `runwarden` entry, agent-only Runwarden skill and MCP, downstream provider onboarding, workspace state, session allowlist split, structured generic shell, managed skill context, non-blocking approval, JSONL events, and local MVP scope.
- Placeholder scan: no task depends on unspecified "later" work; every task has concrete files and verification commands.
- Type consistency: public names use `RunwardenPlatform`, `PlatformState`, `PlatformEvent`, `ProviderExecutionRequest`, and `ProviderExecutionResult` consistently across tasks.
