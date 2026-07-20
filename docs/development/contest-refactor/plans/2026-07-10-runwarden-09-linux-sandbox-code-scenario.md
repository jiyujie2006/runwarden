# Linux Sandbox And Code Scenario Implementation Plan

**Goal:** Add one bounded Python code provider whose legitimate example runs inside certified Linux isolation and whose filesystem, network, child-process, and resource escape attempts are blocked and evidenced in the sixth formal scenario.

**Architecture:** A dedicated `runwarden-sandbox-worker` accepts a narrow versioned request, installs mandatory isolation, and replaces itself with one fixed interpreter via `execveat`. It does not attempt to return after exec. The provider supervisor owns process output/exit collection and constructs the typed result. It launches pinned bubblewrap with user/mount/pid/network namespaces, a manifest-pinned read-only Python runtime closure, workspace-only write access, cleared environment, process cleanup, and seccomp/Landlock enforcement. Delegated cgroup v2 plus wall/output limits enforce resources. Unsupported or degraded isolation fails closed; no unsandboxed fallback exists.

**Tech Stack:** Linux x86_64 primary target, bubblewrap 0.11.0, `seccompiler` 0.5.0, `landlock` 0.4.5, cgroup v2, Rust 1.95.0.

## Global Constraints

- Provider id is `external.code.python`; runtime is fixed to `python3`.
- Agent input may provide source and request lower limits, but never command,
  argv, executable path, cwd, environment, mount, network, namespace, seccomp,
  cgroup, or worker path.
- Formal execution requires bubblewrap 0.11.0, worker binary identity, user/
  mount/pid/network namespaces, no-new-privileges, seccomp, Landlock, and
  delegated cgroup v2.
- Missing capability returns `sandbox_unavailable` before code runs.
- Network capability is `None` in this contest. A future broker is outside
  scope.
- The worker has no secret-bearing environment and no state/signing-key mount.
- Linux integration tests are mandatory in the supported release/nightly
  runner; non-Linux CI runs protocol and explicit-unsupported tests.

---

## File Responsibility Map

- Create crate `crates/runwarden-sandbox-worker/` with request protocol,
  limits, Landlock/seccomp, and one binary.
- Create `runwarden-providers/src/runtime/code_execution.rs` supervisor.
- Extend Plan 3 resource extractor/catalog/default executor.
- Create `scenarios/code-execution-sandbox-abuse/` using Plan 8 format.

### Frozen Protocol

```rust
pub const SANDBOX_PROTOCOL_VERSION: &str = "1.0.0";

pub struct SandboxRequest {
    pub protocol_version: String,
    pub operation_id: OperationId,
    pub source_relative_path: WorkspaceRelativePath,
    pub limits: ExecutionLimits,
}

pub struct WorkerSetupError {
    pub protocol_version: String,
    pub reason_code: String,
}

pub struct SandboxResult {
    pub protocol_version: String,
    pub status: SandboxStatus,
    pub exit_code: Option<i32>,
    pub stdout_hash: Sha256Digest,
    pub stderr_hash: Sha256Digest,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub wall_time_ms: u64,
    pub reason_code: Option<String>,
}
```

Before exec, the worker may emit one `WorkerSetupError` on its dedicated setup
pipe. On success the pipe closes-on-exec and the worker becomes Python; only
the supervisor can create `SandboxResult` after observing process exit,
signals, cgroup events, timeout, and bounded output. Raw stdout/stderr stay in
private reconciliation material and never enter story/API/bundle DTOs.

The inherited descriptor contract is exact: stdin `0` carries the one request
and is replaced with read-only `/dev/null` after validation; stdout `1` and
stderr `2` are bounded program streams. Interpreter fd `3` and setup-error fd
`4` cross the supervisor-to-bubblewrap-to-worker exec boundary temporarily
without `CLOEXEC`; the worker verifies their identity, immediately sets
`CLOEXEC` itself, and every fd `>=5` is closed before isolation/exec. The worker
rejects startup if it cannot establish and verify this layout.

## Task 1: Build The Narrow Sandbox Worker Protocol

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/runwarden-sandbox-worker/Cargo.toml`
- Create: `crates/runwarden-sandbox-worker/src/lib.rs`
- Create: `crates/runwarden-sandbox-worker/src/protocol.rs`
- Create: `crates/runwarden-sandbox-worker/src/main.rs`
- Test: `crates/runwarden-sandbox-worker/tests/protocol.rs`

**Interfaces:**

- Produces the frozen stdin/stdout JSON protocol.
- The worker accepts no arbitrary executable or environment map.

- [ ] **Step 1: Write failing protocol validation tests**

Test supported version, UUIDv7 operation id, relative `main.py`, clamped limits,
single JSON input, trailing bytes, unknown fields, absolute/traversal path,
wrong extension, and oversized request. Invalid input returns one JSON error
and never starts Python.

- [ ] **Step 2: Create the crate**

```toml
[package]
name = "runwarden-sandbox-worker"
version = "0.1.0"
edition.workspace = true
license.workspace = true
publish.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "runwarden-sandbox-worker"
path = "src/main.rs"

[dependencies]
runwarden-kernel = { path = "../runwarden-kernel" }
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
time.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4.5"
libc = "0.2"
seccompiler = "0.5.0"

[dev-dependencies]
tempfile = "3.23"
```

- [ ] **Step 3: Implement exact request validation**

Maximum request is 64 KiB. `source_relative_path` must equal `main.py` for v1.
Limits are bounded by server maxima: wall 5 seconds, CPU 2 seconds, memory
128 MiB, combined output 64 KiB, process count 1. Smaller positive limits are
accepted; zero or larger values are rejected rather than silently expanded.

- [ ] **Step 4: Return only setup failure before exec**

The supervisor moves the preopened interpreter and setup pipe to exact fds 3
and 4 with `dup3(..., 0)`, closes their source descriptors, and explicitly
allowlists those two descriptors across the bwrap exec. As its first setup
action, the worker verifies fd 3 against the pinned interpreter identity and fd
4 as the expected pipe, sets `FD_CLOEXEC` on both with `fcntl`, and verifies
the flags. It then consumes the complete stdin request, redirects fd 0 to
`/dev/null`, and uses
`close_range(5, UINT_MAX, CLOSE_RANGE_UNSHARE)` before reducing
`RLIMIT_NOFILE`; `ENOSYS` or any identity/flag/close failure is
`sandbox_unavailable`.

The worker emits only `WorkerSetupError` on the dedicated fd 4 when
validation/isolation/exec preparation fails. Diagnostic logs go to a bounded
inherited stderr captured privately by the supervisor and never contain
request source. Panic hook emits generic `worker_internal`. On success,
close-on-exec closes fds 3/4 as the worker process image becomes Python;
normal stdout/stderr are program streams consumed by the supervisor.

Keep protocol types and validation portable. Put Linux isolation modules and
dependencies behind `cfg(target_os = "linux")`; non-Linux `main` validates the
request then emits stable `sandbox_unsupported_platform`. This preserves
cross-platform `cargo test --workspace` compilation.

- [ ] **Step 5: Run and commit**

```bash
cargo test -p runwarden-sandbox-worker --test protocol
git add Cargo.toml Cargo.lock crates/runwarden-sandbox-worker
git commit -m "feat(sandbox): define bounded worker protocol"
```

## Task 2: Apply No-New-Privileges, Landlock, Seccomp, And Rlimits

**Files:**

- Create: `crates/runwarden-sandbox-worker/src/isolation.rs`
- Create: `crates/runwarden-sandbox-worker/src/seccomp.rs`
- Create: `crates/runwarden-sandbox-worker/src/limits.rs`
- Modify: `crates/runwarden-sandbox-worker/src/main.rs`
- Test: `crates/runwarden-sandbox-worker/tests/limits.rs`
- Test: `crates/runwarden-sandbox-worker/tests/isolation_contract.rs`

**Interfaces:**

- Produces: `install_worker_isolation(workspace, limits)`.
- Fails before `execve` when a required control is unavailable.

- [ ] **Step 1: Write an isolation-order test**

Inject a recorder and assert this exact order:

```text
validate_request -> normalize_fds -> clear_environment -> set_rlimits
-> no_new_privs -> landlock -> seccomp -> exec_python
```

Any failed stage must leave `exec_python` uncalled.

- [ ] **Step 2: Implement environment and rlimit controls**

Clear environment, then set only `PATH=/runtime/bin`, `LANG=C.UTF-8`,
`PYTHONHASHSEED=0`, and `PYTHONDONTWRITEBYTECODE=1`. Apply `RLIMIT_CPU`,
`RLIMIT_AS`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE=32`, `RLIMIT_NPROC=1`, and
`RLIMIT_CORE=0` as defense in depth.

- [ ] **Step 3: Install no-new-privileges and Landlock**

Call `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Build Landlock with
`set_compatibility(CompatLevel::HardRequirement)` and handle every
`AccessFs::from_all(ABI::V3)` right. Add read+execute rules only for the
manifest runtime tree; add read/write/create/remove (but not execute) rules for
`/workspace` and `/tmp`. No other path gets a rule. Require
`restrict_self()` to return exactly
`RestrictionStatus { ruleset: RulesetStatus::FullyEnforced,
no_new_privs: true }`; `PartiallyEnforced` or `NotEnforced` is
`sandbox_unavailable`. Tests inject each status and unsupported right.

- [ ] **Step 4: Install a default-deny seccomp policy**

For `TargetArch::x86_64`, use default `KillProcess` and allow only:

```text
read write readv writev close fstat newfstatat statx lseek pread64
openat access faccessat faccessat2 readlink readlinkat getdents64 getcwd
mmap mprotect munmap mremap madvise brk
rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack
futex set_tid_address set_robust_list rseq arch_prctl
clock_gettime clock_nanosleep nanosleep getrandom
getpid getppid gettid uname sched_getaffinity
fcntl dup dup2 dup3 pipe2 ioctl
prlimit64 exit exit_group execveat
```

Add seccomp conditions: `prlimit64` requires pid argument `0`; `execveat`
requires the preopened interpreter fd `3` and flags exactly `AT_EMPTY_PATH`.
The fd is opened before filtering and marked close-on-exec. No `execve`,
socket family, clone/fork, ptrace, mount, namespace, BPF, perf, keyring,
reboot/kexec/module, chmod/chown, or device syscall is allowed. Compile with
`seccompiler`, install with `apply_filter_all_threads`, and keep an
x86_64 golden BPF digest. aarch64/riscv64 return unsupported until they have
separate reviewed lists; no architecture silently reuses this one.

- [ ] **Step 5: Exec the fixed interpreter**

Open the manifest-pinned interpreter as fd 3, then use only:

```text
/runtime/bin/python3 -I -S /workspace/main.py
```

via `execveat(3, "", argv, envp, AT_EMPTY_PATH)`. No shell, `-c`, user argv,
import path, or environment override is accepted.

- [ ] **Step 6: Run worker tests and commit**

```bash
cargo test -p runwarden-sandbox-worker
git add crates/runwarden-sandbox-worker
git commit -m "feat(sandbox): enforce worker isolation"
```

## Task 3: Build The Bubblewrap And Cgroup Supervisor

**Files:**

- Create: `crates/runwarden-providers/src/runtime/mod.rs`
- Create: `crates/runwarden-providers/src/runtime/code_execution.rs`
- Create: `sandbox/python-runtime-x86_64.json`
- Test: `crates/runwarden-providers/tests/code_supervisor.rs`
- Test: `crates/runwarden-providers/tests/code_process_cleanup.rs`

**Interfaces:**

- Produces: `CodeSandboxExecutor::execute` and `preflight`.
- Consumes exact Plan 3 execution permit/request.

- [ ] **Step 1: Write a fake-bwrap launch-plan test**

Assert fixed arguments include `--die-with-parent`, `--new-session`,
`--unshare-all`, `--as-pid-1`, `--block-fd`, `--clearenv`, read-only runtime binds, proc/dev/tmpfs,
workspace bind, `/workspace` cwd, and the exact worker path. Assert no source,
agent command, auth token, state path, or host working directory appears.
The launch plan passes only fds 0 through 4 to the worker contract; bwrap's
release/block descriptor and every supervisor-internal descriptor are closed
before the worker can exec Python. A real pinned-bwrap regression test proves
fds 3/4 reach the worker across the intermediate bwrap exec and are absent
after the worker's Python `execveat`.

- [ ] **Step 2: Implement strict preflight**

Resolve `/usr/bin/bwrap`, require version `bubblewrap 0.11.0`, calculate its
digest, verify user namespaces, verify worker digest/path, verify cgroup v2
delegation, and run a no-op worker self-test. Cache only a successful preflight
for the process lifetime.

`sandbox/python-runtime-x86_64.json` pins Python real version, interpreter
digest, worker/bwrap digests, target triple, dynamic loader and every shared
library/stdlib file exposed under `/runtime`, with relative destination and
SHA-256. Preflight recomputes the full closure and rejects missing/extra/changed
files. Bubblewrap binds only those files/directories read-only; it never
binds host `/usr`, `/lib`, `/etc`, or the repository wholesale.

- [ ] **Step 3: Prepare one private operation workspace**

Create `<sandbox-root>/code/<operation-id>/` mode `0700`, write `main.py` with
`create_new`, fsync, and mount only that directory read/write as `/workspace`.
Never mount Runwarden state, repository root, home, `/etc`, or network sockets.

- [ ] **Step 4: Attach the process tree to cgroup v2**

Create a delegated child cgroup keyed by operation id. Set `memory.max`,
`memory.swap.max=0`, `pids.max=4`, and `cpu.max` from limits. The four-process
ceiling covers the host bwrap launcher/PID namespace machinery plus the single
worker process that becomes Python; the payload itself remains one process
because `RLIMIT_NPROC=1` and seccomp denies all clone/fork syscalls.

Create a pipe, pass its read end with bwrap `--block-fd`, spawn bwrap, attach
the bwrap PID to the cgroup, verify membership, then close the write end to
release launch. Do not use `--sync-fd` as a start barrier. On any failure, use
`cgroup.kill`, kill the process group, reap it, and return
`sandbox_unavailable`. A real regression test must prove the allowed Python
program starts under this topology.

- [ ] **Step 5: Enforce wall/output limits and cleanup**

Read stdout/stderr concurrently into private files with per-stream and combined caps. Kill the
entire process group/cgroup on timeout, overflow requiring termination,
disconnect, or supervisor error. Return hashes/counts/truncation plus a Plan 3
`CleanupToken`; do not remove cgroup, private output, or workspace inside
`execute`. `OperationRuntime` calls `finalize_cleanup(ResultCommitted)` only
after the journal result is durable, or
`JournalFailedRetainForReconcile` on failure. Reconciliation verifies the
private receipt/output and then performs final cleanup.

- [ ] **Step 6: Run tests and commit**

```bash
cargo test -p runwarden-providers --test code_supervisor
cargo test -p runwarden-providers --test code_process_cleanup
git add crates/runwarden-providers
git commit -m "feat(providers): supervise isolated Python execution"
```

## Task 4: Add Typed Code Claims And Executor Integration

**Files:**

- Modify: `crates/runwarden-providers/src/resource_claims/mod.rs`
- Create: `crates/runwarden-providers/src/resource_claims/code.rs`
- Modify: `crates/runwarden-providers/src/catalog/`
- Modify: `crates/runwarden-providers/src/executor/default.rs`
- Test: `crates/runwarden-providers/tests/code_execution.rs`
- Test: `crates/runwarden-kernel/tests/typed_resource_policy.rs`

**Interfaces:**

- Always adds the `external.code.python` descriptor with typed
  `ProviderAvailability::{Available,Unavailable { reason_code }}`. Availability
  never changes provider identity or claim semantics.

- [ ] **Step 1: Write claim and authority tests**

Valid args contain `source` plus optional lower limits. Assert the claim fixes
runtime `python3`, server-owned workspace, network `None`, and clamped limits.
Reject command, argv, cwd, env, network, mount, interpreter, and larger limits.

- [ ] **Step 2: Add provider contract**

The provider is external, high risk, process-spawning, file-read/write, and
always reviewer-approved. Its evidence contract requires sandbox preflight
digest, isolation feature list, limits, exit status, output truncation state,
and side-effect truth.

- [ ] **Step 3: Route through `DefaultProviderExecutor`**

After permit validation, dispatch only the exact `CodeExecution` claim and
frozen source. Map outcomes explicitly:

- clean exit: `OperationState::Completed`,
  `ProviderExecutionStatus::Completed`, `SideEffectState::Completed`;
- Python started, then nonzero/signal/CPU/wall/memory/output termination:
  `OperationState::Failed`, `ProviderExecutionStatus::ExecutedWithError`,
  `SideEffectState::ExecutedWithError`;
- preflight/setup failed before Python exec:
  `OperationState::Failed`, `ProviderExecutionStatus::FailedBeforeSideEffect`,
  `SideEffectState::BlockedBeforeExecution`;
- supervisor loses proof after exec: `OperationState::OutcomeUnknown` and
  `SideEffectState::OutcomeUnknown`.

Never map setup failure to simulated success. The provider remains visible in
catalog/status when unavailable so the UI can display the stable reason and a
call returns `sandbox_unavailable`, not `provider_unknown`.

- [ ] **Step 4: Run tests and commit**

```bash
cargo test -p runwarden-providers --test code_execution
cargo test -p runwarden-kernel --test typed_resource_policy
git add crates/runwarden-kernel crates/runwarden-providers
git commit -m "feat(providers): mediate typed Python execution"
```

## Task 5: Prove Allowed And Adversarial Linux Behavior

**Files:**

- Test: `crates/runwarden-providers/tests/linux_sandbox.rs`
- Modify: `scripts/security_gate_local.sh`
- Modify: `scripts/nightly_full_gate.sh`

**Interfaces:**

- Certifies the actual supported Linux environment.

- [ ] **Step 1: Add required cases**

Run one allowed `print("RUNWARDEN_OK")` and deny/fail these programs:

- read `/etc/passwd`;
- read/write outside `/workspace`;
- follow an escaping symlink;
- connect to `127.0.0.1` and a public IP;
- create a child process;
- allocate above memory limit;
- spin past CPU/wall limit;
- emit above output cap;
- read a synthetic parent environment secret;
- read a deliberately non-`CLOEXEC` parent fd containing
  `RUNWARDEN_SECRET_FD_MARKER` (launch it as fd 9 and also enumerate
  `/proc/self/fd`); Python must see only 0/1/2 after exec and never the marker;
- leave a background process after timeout.

- [ ] **Step 2: Assert evidence, not only exit codes**

Every result must contain operation id, sandbox control digest, applied limits,
status/reason, truncated flags, side-effect state, and obs ref. Host secret and
raw malicious source must not appear in display/export events. The FD test
also asserts fds 3/4 close on successful exec, all fds >=5 are absent, and a
failure to sanitize descriptors returns pre-execution `sandbox_unavailable`.

- [ ] **Step 3: Layer CI behavior**

Ordinary cross-platform tests validate protocol and return explicit unsupported
outside certified Linux. Mark real capability tests ignored in Cargo, then make
the supported Linux security/nightly gate run:

```bash
cargo test -p runwarden-providers --test linux_sandbox certified_linux_sandbox_matrix -- --ignored --exact
```

Expose the matrix as one ignored test named
`certified_linux_sandbox_matrix`; release gates invoke that exact name rather
than every ignored workspace test:

```bash
cargo test -p runwarden-providers --test linux_sandbox \
  certified_linux_sandbox_matrix -- --ignored --exact
```

This command is required, not optional, on the contest Linux runner.

- [ ] **Step 4: Run locally and commit**

```bash
cargo test -p runwarden-providers --test linux_sandbox certified_linux_sandbox_matrix -- --ignored --exact
bash scripts/security_gate_local.sh
git add crates/runwarden-providers scripts
git commit -m "test(sandbox): prove Linux escape resistance"
```

## Task 6: Add The Sixth Formal Code-Execution Scenario

**Prerequisite:** Plan 8 Tasks 1-3 (loader, independent assertions, runner and
reviewer actor) are merged for deterministic scenario work. The OpenCode
recording in Step 3 additionally requires Plan 8 Task 5. Sandbox Tasks 1-5 may
be developed earlier.

**Files:**

- Create: `scenarios/code-execution-sandbox-abuse/scenario.toml`
- Create: `scenarios/code-execution-sandbox-abuse/session.toml`
- Create: `scenarios/code-execution-sandbox-abuse/task.md`
- Create: `scenarios/code-execution-sandbox-abuse/attack/sandbox-escape.md`
- Create: `scenarios/code-execution-sandbox-abuse/environment/README.md`
- Create: `scenarios/code-execution-sandbox-abuse/driver/deterministic.json`
- Create: `scenarios/code-execution-sandbox-abuse/driver/opencode.toml`
- Create: `scenarios/code-execution-sandbox-abuse/reviewer/actions.json`
- Create: `scenarios/code-execution-sandbox-abuse/assertions.json`
- Test: `crates/runwarden-cli/tests/six_scenario_properties.rs`
- Modify: `docs/reference/first-scenario.md`
- Modify: `docs/reference/threat-model.md`
- Modify: `docs/security-risk-analysis-report.md`

**Interfaces:**

- Completes the six-scenario contest suite.

- [ ] **Step 1: Write the scenario acceptance test**

Assert one reviewer-approved bounded program completes, and separate escape,
network, child-process, and exhaustion attempts are blocked/failed with no
uncontrolled host side effect. Assert report claims cite each observation.

- [ ] **Step 2: Create attack and driver inputs**

The task asks for a harmless local data calculation. The untrusted input tries
to expand it into host-file reading, direct network, child process, and
resource exhaustion. The deterministic driver extracts those attempts from the
attack asset and submits them through the code provider; it does not read
assertions.

- [ ] **Step 3: Add property assertions and recording**

Require typed CodeExecution claims, reviewer binding, sandbox preflight,
allowed short execution, denied/failed attack attempts, bounded output, process
cleanup, verified chain, and supported report claims. Record a pinned OpenCode
story on the certified Linux runner.

Write the complete recording to
`scenarios/code-execution-sandbox-abuse/recordings/opencode/story-bundle/`:

```bash
target/release/runwarden scenario record \
  --scenario code-execution-sandbox-abuse --driver opencode \
  --output scenarios/code-execution-sandbox-abuse/recordings/opencode/story-bundle \
  --expected-key-id "$KEY_ID" --json
target/release/runwarden bundle verify \
  --bundle scenarios/code-execution-sandbox-abuse/recordings/opencode/story-bundle \
  --expected-key-id "$KEY_ID" --json
```

Plan 12 copies this exact sixth directory alongside the five Plan 8 sources.

- [ ] **Step 4: Run and commit**

```bash
cargo test -p runwarden-cli --test six_scenario_properties
target/debug/runwarden scenario run --scenario code-execution-sandbox-abuse --driver deterministic --output artifacts/stories/code-execution-sandbox-abuse/deterministic --json
git add scenarios/code-execution-sandbox-abuse crates/runwarden-cli docs
git commit -m "feat(scenario): add code sandbox abuse story"
```

## Task 7: Verify The Complete Sandbox Checkpoint

**Files:**

- Modify: `docs/reference/provider-integration.md`
- Modify: `docs/reference/provider-model.md`
- Create: `docs/reference/code-sandbox.md`
- Modify: `docs/README.md`

**Interfaces:**

- Certifies the supported Linux sandbox contract and sixth-scenario evidence.

- [ ] **Step 1: Document support and fail-closed behavior**

Document exact provider id/runtime, prohibited agent fields, bubblewrap/worker/
cgroup preflight, namespaces, seccomp, Landlock, resource limits, evidence,
supported target, and absence of an unsandboxed fallback.

- [ ] **Step 2: Run full gates**

```bash
cargo test --workspace
cargo test -p runwarden-providers --test linux_sandbox certified_linux_sandbox_matrix -- --ignored --exact
bash scripts/pr_fast_gate.sh
bash scripts/security_gate_local.sh
bash scripts/release_gate_local.sh
pnpm --dir webui test:e2e
```

Expected: all pass on the certified Linux runner.

- [ ] **Step 3: Commit documentation**

```bash
git add docs
git commit -m "docs(sandbox): define certified Linux execution"
```
