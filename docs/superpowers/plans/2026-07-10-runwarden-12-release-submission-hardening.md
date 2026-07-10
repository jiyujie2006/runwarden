# Release And Submission Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a clean-room-verifiable contest package that starts the live hero demo or a signed replay in minutes, contains no repository-relative assumptions, and presents one coherent eight-minute security narrative.

**Architecture:** Release mode builds pinned Rust binaries and deterministic WebUI assets, verifies six native stories plus evaluation/performance evidence, exports a Plan 6 `EvidenceArtifactKind::ContestSubmission`, and copies an explicit whitelist into a staging directory. Preflight validates live dependencies and the fallback bundle before presentation. Clean-room tests unpack the final replay archive outside the repository, clear ambient configuration, semantically verify every nested artifact, and run replay using included files only.

**Tech Stack:** Rust 1.95.0, Node 22.22.2, pnpm 11.9.0, OpenCode 1.17.13, bubblewrap 0.11.0 on primary Linux, GitHub Actions pinned to immutable SHAs.

## Global Constraints

- Primary live target is `x86_64-unknown-linux-gnu`.
- The only certified contest target is `x86_64-unknown-linux-gnu`. Other
  platforms may open the static HTML viewer, but are not advertised as native
  replay-verification or sandbox targets.
- Offline replay never depends on repository `target/debug`, user XDG config,
  CDN, network/model availability, or files outside the archive. The Linux live
  path explicitly declares its external OpenCode, model credential,
  bubblewrap/Python runtime, and host-kernel/cgroup capabilities.
- Package contains source or release binaries, exact license text, dependency
  lockfiles, config, scripts, signed stories, evaluation/performance evidence,
  and reviewer documentation.
- `.env`, credentials, private held-out corpus, private transcripts, state DB/
  WAL, signing private key, reviewer nonce, caches, and user paths are excluded.
- Every packaged artifact is allowlisted, checksummed, and represented in a
  signed top-level manifest.
- Live failure never invalidates the presentation: preflight verifies the
  recorded hero replay before attempting live startup.
- License changes require an explicit owner decision; documentation must match
  the chosen legal state.
- The replay archive content is path-portable and contains the static console
  plus signed evidence, but its clean-room security verification is certified
  only with the included Linux x86_64 verifier. This deliberately avoids a
  WASM or multi-platform verifier expansion for the contest.

---

## File Responsibility Map

- Create `packaging/targets.toml` and `packaging/README.md`.
- Create CLI preflight and expanded demo subcommands.
- Create three presentation scripts and clean-room test.
- Rewrite `scripts/contest_bundle.sh` as a thin caller of Rust package logic.
- Update CI/nightly/release workflows with pinned Node/pnpm actions.
- Align all judge-facing documentation, paths, versions, images, and claims.

## Task 1: Pin Release Metadata And Resolve Legal Naming

**Files:**

- Modify: `VERSION`
- Modify: `Cargo.toml`
- Modify: `crates/runwarden-anomaly/Cargo.toml`
- Modify: `crates/runwarden-assurance/Cargo.toml`
- Modify: `crates/runwarden-cli/Cargo.toml`
- Modify: `crates/runwarden-kernel/Cargo.toml`
- Modify: `crates/runwarden-llm-proxy/Cargo.toml`
- Modify: `crates/runwarden-mcp/Cargo.toml`
- Modify: `crates/runwarden-providers/Cargo.toml`
- Modify: `crates/runwarden-runtime/Cargo.toml`
- Modify: `crates/runwarden-sandbox-worker/Cargo.toml`
- Modify: `crates/runwarden-state/Cargo.toml`
- Create: `packaging/targets.toml`
- Create: `packaging/README.md`
- Modify: `LICENSE` only after explicit owner authorization
- Modify: `README.md`
- Modify: `SUBMISSION.md`
- Test: `crates/runwarden-cli/tests/release_manifest.rs`

**Interfaces:**

- Produces one canonical product version and supported-target declaration.

- [ ] **Step 1: Write a version-consistency test**

Assert `VERSION`, workspace package version, binary `--version`, story/bundle
producer version, and contest manifest version agree. Reject dirty source for a
final package.

- [ ] **Step 2: Define supported targets**

```toml
schema_version = "1.0.0"
primary = "x86_64-unknown-linux-gnu"

[[target]]
triple = "x86_64-unknown-linux-gnu"
live_demo = true
code_sandbox = true
offline_replay = true

```

- [ ] **Step 3: Preserve legal state unless the owner separately changes it**

Present two explicit choices:

1. dual Apache-2.0/MIT for Runwarden source and bundle;
2. retain `LicenseRef-Runwarden-Proprietary` and describe only OpenCode as the
   open-source intelligent application.

In unattended execution, retain the repository's current license and
`LicenseRef` metadata and describe OpenCode, AgentDojo, and InjecAgent only
according to their bundled third-party licenses. Do not edit `LICENSE`, Cargo
license metadata, or broaden “open source” claims without a separate recorded
owner choice. This does not block the contest build.

- [ ] **Step 4: Align metadata and run the test**

```bash
cargo test -p runwarden-cli --test release_manifest
git add VERSION Cargo.toml crates/*/Cargo.toml packaging README.md SUBMISSION.md LICENSE
git commit -m "chore(release): align contest release metadata"
```

Omit `LICENSE` from `git add` when the owner retains the current license.

## Task 2: Add Live/Replay Preflight And Demo Commands

**Files:**

- Create: `crates/runwarden-cli/src/commands/preflight.rs`
- Refactor: `crates/runwarden-cli/src/commands/demo.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Test: `crates/runwarden-cli/tests/preflight.rs`
- Test: `crates/runwarden-cli/tests/demo_commands.rs`
- Modify: `docs/reference/cli.md`

**Interfaces:**

- Produces:

```text
runwarden preflight --mode live --fallback <bundle> --json
runwarden preflight --mode replay --bundle <bundle> --json
runwarden demo prepare --scenario <id> --state-dir <relative> --json
runwarden demo live --scenario <id> --state-dir <relative> --port 8088 --proxy-port 8787 --json
runwarden demo replay --bundle <bundle> --port 8088 --json
```

- [ ] **Step 1: Write fake-environment preflight tests**

Cover supported OS/arch, exact binary/tool versions, owner-only state, ports,
Runwarden-only OpenCode config, model credential presence without value output,
MCP/proxy health, bubblewrap/worker/cgroup capability for code scenario, and
fallback bundle verification. Test every failure result includes a safe reason
and replay command.

- [ ] **Step 2: Implement replay-first preflight order**

Live preflight verifies the fallback bundle/key id and offline console first.
Only then check live dependencies. Output contains `fallback_verified=true`,
live readiness, warnings, blocking errors, and exact next command.

- [ ] **Step 3: Implement demo preparation**

Create isolated state/sandbox/XDG directories, native story/session/instance,
safe OpenCode config, and a preparation manifest. Reject non-empty existing
state unless `--recover` validates no live process and performs Plan 2 recovery.

- [ ] **Step 4: Implement live and replay commands**

Live starts proxy/reviewer server and launches or prints the exact pinned
OpenCode command. Replay verifies the bundle in Rust, serves the same WebUI in
read-only replay mode, and never requires model credentials/OpenCode.

- [ ] **Step 5: Preserve temporary compatibility aliases**

Keep current `runwarden demo --all` behavior as a deprecated alias through the
first release, but route it through native scenario/bundle APIs and emit a
migration warning. Remove fixture-driven execution.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-cli --test preflight
cargo test -p runwarden-cli --test demo_commands
git add crates/runwarden-cli docs/reference/cli.md
git commit -m "feat(cli): preflight live and replay demos"
```

## Task 3: Create The Release Binary And Source Whitelist

**Files:**

- Create: `crates/runwarden-cli/src/commands/package.rs`
- Create: `packaging/source-allowlist.txt`
- Create: `packaging/runtime-allowlist.txt`
- Create: `packaging/third-party-licenses.toml`
- Create: `THIRD_PARTY_NOTICES.md`
- Test: `crates/runwarden-cli/tests/package_whitelist.rs`

**Interfaces:**

- Produces `runwarden package contest --staging <relative> --target <triple>`.

- [ ] **Step 1: Define exact binary set**

```text
bin/runwarden
bin/runwarden-mcp
bin/runwarden-llm-proxy
bin/runwarden-sandbox-worker
```

The sandbox worker is included only for the supported Linux target. Record
binary SHA-256, target, build profile, Rust version, and linked-library summary.

- [ ] **Step 2: Define source/runtime allowlists**

Include Cargo manifests/lock/toolchain, Rust crates, WebUI source/lock/dist,
schemas, official scenarios without private raw transcripts, red-team source/
public corpora/manifests, examples/config, scripts, docs, license/security files,
exact third-party license texts/notices, and signed generated evidence selected
later. A test verifies every shipped dependency/tool/dataset named in SBOM or
source manifests has a corresponding notice and license payload.

Runtime verification inputs are mandatory allowlist entries at exact paths:
`benchmarks/workloads/` including its `SHA256SUMS`,
`benchmarks/targets.toml`,
`benchmarks/baselines/x86_64-unknown-linux-gnu.json`, and
`benchmarks/runner-enrollment.toml`. Package tests reject their absence or a
digest mismatch with the performance artifact receipts.

Explicitly exclude `.git`, `.env*`, `target`, `node_modules`, non-whitelisted
artifacts, private data, caches, state, signing keys, logs, worktrees, and
supplemental stale fixtures.

- [ ] **Step 3: Implement safe whitelist copying**

Resolve every source and destination, reject absolute/traversal/symlink escape,
refuse duplicate normalized paths, and copy into a new mode-0700 staging root.
Fail on an unexpected required file or a dirty tracked generated contract.

- [ ] **Step 4: Build release binaries and assets first**

```bash
pnpm --dir webui install --frozen-lockfile
pnpm --dir webui contracts:check
pnpm --dir webui build
cargo build --workspace --release --locked --target "$TARGET"
```

Require dist/schema drift clean before copying. Copy native binaries only from
`target/$TARGET/release/`; reject fallback to host `target/release` or
`target/debug`. The static viewer may be copied elsewhere, but the release
manifest must not claim native replay verification on an unverified target.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-cli --test package_whitelist
git add crates/runwarden-cli packaging
git commit -m "feat(package): whitelist contest release inputs"
```

## Task 4: Build And Sign The Self-Contained Contest Bundle

**Files:**

- Modify: `crates/runwarden-kernel/src/evidence_artifact.rs`
- Modify: `crates/runwarden-cli/src/commands/package.rs`
- Create: `schemas/contest-submission.schema.json`
- Modify: `schemas/index.json`
- Rewrite: `scripts/contest_bundle.sh`
- Create: `scripts/test_contest_bundle_clean.sh`
- Test: `crates/runwarden-cli/tests/clean_room_bundle.rs`
- Test: `crates/runwarden-cli/tests/contest_manifest.rs`

**Interfaces:**

- Produces `artifacts/contest-bundle/` and a deterministic archive.
- Produces `runwarden-contest-linux-x86_64.tar.zst` and
  `runwarden-contest-replay.tar.zst`; the latter is the clean-room portable
  fallback.

- [ ] **Step 1: Define final bundle layout**

```text
README.md
SUBMISSION.md
LICENSE
THIRD_PARTY_NOTICES.md
VERSION
bin/
source/
config/opencode/runwarden-only.json
scripts/{preflight,live,replay}.sh
stories/{scenario}/{deterministic,opencode}/
evaluation/
performance/
benchmarks/
schemas/
docs/
manifest.json
manifest.sig
public-key.pem
SHA256SUMS
```

- [ ] **Step 2: Accept only current signed evidence**

Require six deterministic story bundles at exactly
`stories/<scenario>/deterministic/story-bundle/`, six recorded OpenCode story
bundles at exactly `stories/<scenario>/opencode/story-bundle/`, the public
held-out A/B artifact, performance artifact, and generated reports.

Only recorded OpenCode story bundles may use their documented recording source
SHA. Deterministic stories, evaluation, performance, reports, schemas, and
submission manifest must match the current clean SHA, current input digests,
schema major, and workspace signing key id. Never admit stale evaluation or
performance evidence merely because its signature is internally valid.

- [ ] **Step 3: Create a top-level signed manifest**

Use Plan 6's generic envelope with
`artifact_kind=EvidenceArtifactKind::ContestSubmission`. The canonical
kind-specific `submission.json` includes product/version, git/dirty, archive
kind, target, Rust/Node/pnpm/OpenCode/bubblewrap versions, binary/source/story/
evaluation/performance artifact ids and digests, generation command/time,
required paths, external live prerequisites, replay guarantees, and
limitations. Its typed Rust schema is the only accepted producer input.

Freeze the payload boundary:

```rust
pub struct ContestSubmission {
    pub schema_version: SchemaVersion,
    pub submission_id: String,
    pub product_version: String,
    pub git_sha: GitCommitId,
    pub source_dirty: bool,
    pub archive_kind: ContestArchiveKind,
    pub target_triple: String,
    pub tool_versions: ContestToolVersions,
    pub binaries: Vec<ContestPayloadRef>,
    pub sources: Vec<ContestPayloadRef>,
    pub stories: Vec<ContestStoryRef>,
    pub evaluation: ContestPayloadRef,
    pub performance: ContestPayloadRef,
    pub reports: Vec<ContestPayloadRef>,
    pub required_paths: Vec<WorkspaceRelativePath>,
    pub live_prerequisites: Vec<String>,
    pub replay_guarantees: Vec<String>,
    pub limitations: Vec<String>,
}
```

All payload reference paths are validated workspace-relative paths and carry
artifact id, kind, SHA-256, key id, and source git SHA. Lists use a documented
UTF-8 sort key before canonical serialization; unknown fields are rejected by
Rust and JSON Schema. `GitCommitId` is a private newtype that accepts exactly
the full lowercase hexadecimal commit id returned by `git rev-parse HEAD` and
rejects abbreviated or symbolic refs.

`required_paths` and `sources` include the top-level `benchmarks/` tree at the
exact paths required by the performance verifier; it is both allowlisted and
covered by the submission manifest/checksums, never hidden under `source/`.

Sign exact canonical bytes with the Plan 6 workspace key. The strict verifier
rejects unknown/duplicate paths, symlinks/special files, non-canonical manifest
bytes, wrong kind, stale SHA/input digest, nested verifier failure, or an
unallowlisted file. `SHA256SUMS` follows Plan 6's non-self-referential rule.

- [ ] **Step 4: Make the shell script a thin deterministic wrapper**

`contest_bundle.sh` runs the release gate, invokes `runwarden package contest`,
invokes Rust verification, and prints artifact paths. It does not maintain a
second copy whitelist or hand-write manifest JSON.

Archive creation uses a committed `SOURCE_DATE_EPOCH` derived from the release
commit, UTF-8 byte-sorted paths, normalized uid/gid `0`, empty owner/group
names, normalized modes, fixed mtimes, and pinned compression settings. A test
builds each archive twice from identical inputs and requires byte-identical
SHA-256 digests.

- [ ] **Step 5: Add clean-room archive verification**

Copy/archive the bundle to a fresh temp directory outside the repository,
clear Runwarden/model/XDG environment, disable network where supported, and
run top-level verification, all 12 story bundle verifiers,
`eval verify --public-only --require-signed-scoring-receipt --require-pass`,
and `benchmark verify --workload-set benchmarks/workloads --targets
benchmarks/targets.toml --baseline
benchmarks/baselines/x86_64-unknown-linux-gnu.json --runner-enrollment
benchmarks/runner-enrollment.toml --require-release-eligible --require-pass`,
plus generated-report rerender checks and offline replay smoke. Assert no path in output
refers to the source checkout or `target/debug`. The replay archive must pass
without OpenCode, model credentials, Python, or bubblewrap installed.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-cli --test contest_manifest --test clean_room_bundle
bash scripts/test_contest_bundle_clean.sh
git add crates/runwarden-cli scripts
git commit -m "feat(package): sign a self-contained contest bundle"
```

## Task 5: Add Pinned CI, Nightly Evidence, And Release Workflows

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/contest-evidence.yml`
- Create: `.github/workflows/nightly.yml`
- Create: `.github/workflows/release.yml`
- Modify: `docs/reference/ci.md`

**Interfaces:**

- Runs current WebUI/evidence/package gates in automation.

- [ ] **Step 1: Add pinned Node and pnpm setup**

Use immutable actions:

```yaml
- uses: pnpm/action-setup@008330803749db0355799c700092d9a85fd074e9
  with:
    version: 11.9.0
    run_install: false
- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
  with:
    node-version: 22.22.2
    cache: pnpm
    cache-dependency-path: webui/pnpm-lock.yaml
- run: pnpm --dir webui install --frozen-lockfile
- run: pnpm --dir webui exec playwright install --with-deps chromium
```

Keep existing immutable checkout/toolchain/upload SHAs. Add a repository test
that resolves every pinned action SHA against an allowed upstream/tag and fails
on an unresolvable, mutable, or 40-hex-but-nonexistent reference.

- [ ] **Step 2: Define workflow layers**

- PR/push: `scripts/pr_fast_gate.sh`.
- Manual full: `scripts/release_gate_local.sh` plus WebUI e2e.
- Nightly fixed Linux: held-out A/B, the exact named ignored tests below,
  performance, and signed evidence upload. Never run every ignored workspace
  test and never refresh OpenCode recordings implicitly:

  ```bash
  cargo test -p runwarden-providers --test linux_sandbox \
    certified_linux_sandbox_matrix -- --ignored --exact
  ```

  Any other crash/capability ignored test must be individually named in this
  plan and workflow before it can join the gate. Model-backed recording uses a
  separate explicit `workflow_dispatch` refresh job with credentials and
  produces reviewable candidate artifacts only.
- Contest evidence: six deterministic stories on all supported replay targets,
  Linux live/sandbox on primary target, then package/clean-room verify.
- Release tag: build/test live and replay binaries only on
  `x86_64-unknown-linux-gnu`; build and clean-room verify both archives on that
  target; upload both signed archives and checksum manifests. Any optional
  cross-platform static-viewer smoke is informational and cannot add a support
  claim until an equivalent native verifier matrix exists.

- [ ] **Step 3: Prevent stale artifact publication**

Release workflow accepts artifacts only from the current workflow run and
verifies embedded git SHA/dirty=false. It never downloads “latest” artifacts
without matching run id/SHA.

- [ ] **Step 4: Validate workflow YAML and commit**

Run the repository's workflow syntax/lint mechanism and local shell syntax:

```bash
bash -n scripts/*.sh
bash scripts/pr_fast_gate.sh
```

Expected: pass.

```bash
git add .github/workflows docs/reference/ci.md
git commit -m "ci: produce signed contest evidence"
```

## Task 6: Create The Eight-Minute Live And Replay Scripts

**Files:**

- Create: `scripts/contest_demo_preflight.sh`
- Create: `scripts/contest_demo_live.sh`
- Create: `scripts/contest_demo_replay.sh`
- Rewrite: `docs/contest/demo-script.md`
- Rewrite: `docs/guides/manual-walkthrough.md`
- Modify: `docs/contest/reproduction.md`
- Modify: `SUBMISSION.md`
- Test: `crates/runwarden-cli/tests/demo_script_contract.rs`

**Interfaces:**

- Produces one-command preflight/live/replay flows from the bundle root.

- [ ] **Step 1: Write script path/version tests**

Run scripts from a temp directory with fake binaries. Assert they resolve only
bundle-relative paths, quote all paths, reject wrong versions, preserve secret
values from logs, and print the fallback command on live failure.

- [ ] **Step 2: Implement preflight script**

Invoke included `bin/runwarden preflight --mode live --fallback
stories/prompt-injection-file-exfil/opencode --json`. Stop before the live demo
when required dependencies fail, but print verified replay readiness and exact
replay command.

- [ ] **Step 3: Implement live script**

Prepare isolated state/XDG, start live hero story and browser URL, run pinned
OpenCode task, and keep cleanup traps for proxy/MCP/OpenCode process trees. It
does not run build, full release gate, held-out eval, or package generation on
stage.

The script starts a monotonic presentation clock and automatically switches to
the already-verified replay when any live process exits unexpectedly, health is
not ready by 20 seconds, the first committed event is not visible by 45
seconds, or the approval segment has not reached a terminal operation by 4:30.
Fallback kills the live process tree, opens replay at the corresponding story
frame, prints one safe reason code, and continues without asking the presenter
to type a recovery command.

- [ ] **Step 4: Implement replay script**

Verify expected key id, serve/open the self-contained hero replay, start in
presentation mode, and expose analyst mode/report evidence. No model/API key/
OpenCode/network is required.

- [ ] **Step 5: Lock the presentation timeline**

Document:

```text
0:00-0:35  one-sentence architecture and authority boundary
0:35-1:10  OpenCode sees only Runwarden plus first-screen story
1:10-2:10  indirect injection and confidential-read review denial
2:10-2:50  hidden callback denied before side effect
2:50-4:10  exact finance email approval, execution, one-shot receipt
4:10-4:50  model input filter block plus benign control
4:50-5:30  event-chain/report citation verification
5:30-6:40  six scenarios and held-out A/B metrics with denominators
6:40-7:20  innovation statement and honest limitations
7:20-8:00  reserved fallback/question-transition margin
```

The rehearsal contract fails when wall-clock elapsed exceeds 8:00, when any
segment misses its deadline, or when an automatic live-to-replay transition
cannot complete inside the reserved margin.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-cli --test demo_script_contract
bash -n scripts/contest_demo_*.sh
git add scripts docs SUBMISSION.md
git commit -m "docs(demo): script the eight-minute security story"
```

## Task 7: Remove Stale Claims, Paths, Fixtures, And Images

**Files:**

- Modify: `docs/README.md`
- Modify: `README.md`
- Modify: `SUBMISSION.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/contest/*.md`
- Modify: `docs/reference/*.md` as indicated by behavior
- Remove or replace unreferenced/misleading `docs/assets/*`
- Remove migrated legacy fixture authority after compatibility deadline
- Test: `crates/runwarden-cli/tests/documentation_contract.rs`

**Interfaces:**

- Makes reviewer claims match generated evidence and actual package paths.

- [ ] **Step 1: Add documentation path/claim tests**

Parse Markdown links and commands. Assert referenced bundle paths exist, six
scenarios are named consistently, test/sample counts come from generated
summaries, and no command depends on source-checkout artifacts.

- [ ] **Step 2: Remove fixture-driven execution and legacy console references**

Delete or archive old expected-call execution code, file approvals, JSONL live
authority, `console.html`, stale static paths, and outdated TypeScript SDK
diagram claims after all replacement gates pass. Retain compatibility import/
export only where the release notes explicitly promise it.

- [ ] **Step 3: Rewrite the innovation statement**

Use one consistent claim: precise authority binding plus truthful side-effect
state plus durable human approval plus verified observation-backed reports,
shown in one live/replay security story. Do not market ordinary allowlists as
the sole innovation.

- [ ] **Step 4: State limitations**

Include local contest scope, self-signed workspace provenance, Linux-only code
sandbox, recorded-model variability, no production multi-tenant identity, and
monitor/evaluation boundaries.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-cli --test documentation_contract
git add README.md SUBMISSION.md CHANGELOG.md docs crates/runwarden-cli
git commit -m "docs: align the final contest narrative"
```

## Task 8: Execute The Final Release Gate And Rehearsal

**Files:**

- Verify only; fix only release-blocking issues in the owning plan.

**Interfaces:**

- Certifies the final signed package, both demo paths, and all release evidence
  at one clean git SHA.

- [ ] **Step 1: Start from a clean worktree**

```bash
git status --short
git rev-parse HEAD
```

Expected: no output from status; record the full SHA.

- [ ] **Step 2: Run all required correctness gates**

```bash
cargo test --workspace
cargo test -p runwarden-providers --test linux_sandbox \
  certified_linux_sandbox_matrix -- --ignored --exact
bash scripts/pr_fast_gate.sh
bash scripts/security_gate_local.sh
bash scripts/release_gate_local.sh
pnpm --dir webui exec playwright install --with-deps chromium
pnpm --dir webui test:e2e
```

Expected: all exit zero on the supported Linux runner.

- [ ] **Step 3: Run held-out and performance evidence gates**

```bash
bash scripts/nightly_full_gate.sh
bash scripts/performance_gate_local.sh
```

Expected: current signed results meet approved thresholds/budgets.

- [ ] **Step 4: Build and clean-room verify the bundle**

```bash
bash scripts/contest_bundle.sh
bash scripts/test_contest_bundle_clean.sh
```

Expected: top-level signature/checksums, all story bundles, release binaries,
offline replay, evaluation, performance, and docs verify from a fresh directory.
The clean-room log must show the nested semantic verifier result for each
story, the public evaluation artifact, the performance artifact, and the
`ContestSubmission` envelope; a top-level checksum-only result is insufficient.

- [ ] **Step 5: Rehearse both presentation paths**

Run preflight, live script, and replay script. Time the eight-minute narrative.
Record only timing/issues, not credentials or private transcript content. Live
and replay must show the same final hero story semantics. Rehearsal is failed
unless elapsed time is at most 8:00 and forced failures at each frozen deadline
successfully continue in replay.

- [ ] **Step 6: Record release evidence**

Create the release tag/manifest only after all prior commands pass on the same
clean SHA. Publish SHA256 and expected signing key id beside the archive.
