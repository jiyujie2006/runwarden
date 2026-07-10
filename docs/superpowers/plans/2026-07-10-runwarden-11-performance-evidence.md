# Performance Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Quantify Runwarden's kernel, journal, filter, verification, SSE, and end-to-end overhead with reproducible workloads without turning shared-runner noise into false release claims.

**Architecture:** Criterion microbenchmarks isolate pure components. A Rust end-to-end harness uses fixed payloads, a deterministic delayed upstream, temporary SQLite state, and concurrency 1/16/64. It records HDR histograms, throughput, CPU/RSS where supported, toolchain/hardware metadata, and workload digests. PRs compile and smoke benchmarks; only an approved fixed runner enforces performance budgets.

**Tech Stack:** Criterion 0.8.2, `hdrhistogram` 7.5.4, Rust 1.95.0, Linux `/proc` metrics on the primary contest target.

**Prerequisites:** Plans 2 through 6 are complete. This plan reuses Plan 6's
`EvidenceArtifactManifest`, canonical JSON, Ed25519 signing, workspace key
identity, safe export, and strict verification implementation; it does not
create a second performance-only signature format.

## Global Constraints

- Performance measurements never replace correctness/security gates.
- Model/provider network time is excluded from Runwarden overhead or reported
  separately with a fixed synthetic delay.
- Cold and warm measurements are separate.
- Every result records target triple, CPU, memory, OS/kernel, Rust version,
  git SHA/dirty state, workload digest, command, repetitions, and time.
- Shared GitHub-hosted runner values are informational only.
- Hard regression thresholds run only on an approved fixed Linux runner.
- No benchmark uses real credentials, public network, or unbounded output.
- Overhead distributions are built from per-request paired spans. A producer
  must never subtract independently aggregated p50/p95/p99 values.
- A run is release eligible only when a verifier recomputes its metrics from
  signed raw data and matches an explicitly enrolled fixed-runner fingerprint.

---

## Task 1: Add Microbenchmark Targets And Stable Workloads

**Files:**

- Modify: root/workspace dependency declarations
- Create: `crates/runwarden-kernel/benches/policy_decision.rs`
- Create: `crates/runwarden-state/benches/journal.rs`
- Create: `crates/runwarden-providers/benches/input_inspection.rs`
- Create: `crates/runwarden-assurance/benches/story_verification.rs`
- Create: `crates/runwarden-llm-proxy/benches/filter.rs`
- Create: `benchmarks/workloads/{policy,journal,filter,story}.json`
- Create: `crates/runwarden-assurance/src/performance_metrics.rs`
- Test: `crates/runwarden-assurance/tests/benchmark_metrics.rs`

**Interfaces:**

- Produces criterion targets with fixed workload ids and sizes.

- [ ] **Step 1: Add exact dev dependencies**

Add `criterion = "0.8.2"` as a workspace dependency and each benchmark crate's
dev dependency. Declare `[[bench]] harness = false` entries with names matching
the files above.

- [ ] **Step 2: Add workload digests**

Workloads cover:

- typed allow, deny, and review policy decisions;
- SQLite propose/policy, approval lease, and event append transactions;
- input inspection at 1 KiB, 64 KiB, and 1 MiB;
- story verification at 1, 10,000, and 100,000 events;
- safe and blocked proxy filter payloads at 1 KiB and 64 KiB.

Each JSON file includes schema version, deterministic seed, cases, and expected
semantic result. `benchmarks/workloads/SHA256SUMS` stores its SHA-256; a unit
test verifies the sidecar so no file contains a self-referential digest.

- [ ] **Step 3: Implement benchmark functions without setup pollution**

Move parsing/fixture creation outside `b.iter`. Use `black_box` for inputs and
assert expected result once before measurement. Journal benchmarks use a fresh
prepared database per sample batch and measure only the named transaction.

Freeze Criterion configuration for release evidence at `sample_size=100`,
`warm_up_time=3s`, `measurement_time=10s`, `confidence_level=0.95`,
`significance_level=0.05`, `noise_threshold=0.02`, and 10,000 bootstrap
resamples. Freeze HDR histograms to 3 significant digits over 1 microsecond
through 120 seconds. Preserve Criterion iteration counts/raw nanoseconds and
periodic CPU/RSS samples as signed raw payloads; JSON summaries alone are not
evidence.

- [ ] **Step 4: Add metric math tests**

Test HDR percentile extraction, throughput, per-request paired-span overhead,
zero/empty samples, overflow, failed-request accounting, and JSON serialization
using fixed duration vectors. A paired observation is valid only when the
baseline and protected spans share request id, workload case, concurrency,
cold/warm mode, and synthetic-upstream delay. Reject missing, duplicate,
reordered, or mismatched pairs. Include a regression test proving that
`p95(protected) - p95(baseline)` is not used as a substitute for
`p95(protected - baseline)`.

- [ ] **Step 5: Compile and smoke-run**

```bash
cargo bench --workspace --no-run
cargo bench -p runwarden-kernel --bench policy_decision -- --sample-size 10
cargo test -p runwarden-assurance --test benchmark_metrics
```

Expected: compilation and smoke run pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates benchmarks/workloads
git commit -m "perf: add reproducible component benchmarks"
```

## Task 2: Build The End-To-End Overhead Harness

**Files:**

- Create: `crates/runwarden-cli/src/commands/performance.rs`
- Modify: `crates/runwarden-cli/src/main.rs`
- Create: `crates/runwarden-kernel/src/performance.rs`
- Create: `benchmarks/workloads/end-to-end.json`
- Test: `crates/runwarden-cli/tests/benchmark_workflow.rs`

**Interfaces:**

- Produces `runwarden benchmark run --workload --output --json`.

- [ ] **Step 1: Write a deterministic workflow test**

Run a 20-request smoke workload with fake clock/upstream. Assert result schema,
workload digest, count, p50/p95/p99 ordering, throughput, error count, and no
external network connection.

- [ ] **Step 2: Define benchmark result contracts**

```rust
pub struct LatencyDistribution {
    pub samples: u64,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

pub struct PerformanceRun {
    pub run_id: String,
    pub purpose: PerformanceRunPurpose,
    pub workload_set_id: String,
    pub workload_set_sha256: Sha256Digest,
    pub concurrency: u32,
    pub cold: bool,
    pub latency: LatencyDistribution,
    pub throughput_per_second: f64,
    pub errors: u64,
    pub cpu_seconds: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
    pub environment: PerformanceEnvironment,
}

pub enum PerformanceRunPurpose {
    Informational,
    BaselineCandidate,
    ReleaseEvidence,
}

pub struct PerformanceEnvironment {
    pub runner_id: String,
    pub runner_class: RunnerClass,
    pub target_triple: String,
    pub cpu_vendor: String,
    pub cpu_model: String,
    pub logical_cpu_count: u32,
    pub memory_bytes: u64,
    pub os_release: String,
    pub kernel_release: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub allocator: String,
    pub power_governor: Option<String>,
    pub virtualization: Option<String>,
    pub fingerprint_sha256: Sha256Digest,
}

pub enum RunnerClass {
    SharedInformational,
    EnrolledFixed,
}

pub struct PairedRequestSpan {
    pub request_id: String,
    pub case_id: String,
    pub concurrency: u32,
    pub cold: bool,
    pub baseline_us: u64,
    pub protected_us: u64,
    pub synthetic_upstream_us: u64,
    pub protected_error: bool,
    pub baseline_error: bool,
}

pub struct SignedOverheadDistribution {
    pub samples: u64,
    pub min_us: i64,
    pub p50_us: i64,
    pub p95_us: i64,
    pub p99_us: i64,
    pub max_us: i64,
}
```

`PerformanceEnvironment::fingerprint_sha256` is computed from canonical JSON of
all preceding environment fields. The runner id is an enrolled stable label,
not a hostname supplied by the benchmark process.

For every valid pair compute `overhead_us = i128(protected_us) -
i128(baseline_us)`, range-check it into `i64`, retain negative noise samples,
sort signed values ascending, and use nearest-rank quantiles with rank
`ceil(p * n)` (one-based, clamped to `1..=n`). Component latencies use HDR;
signed overhead never uses HDR, never underflows, and is never clamped or
dropped. The 50 ms gate applies to this recomputed signed p95.

- [ ] **Step 3: Implement isolated measurements**

Measure separately and retain one `PairedRequestSpan` for every attempted
request:

1. passthrough HTTP/proxy with a fixed 20 ms upstream delay, reported as a
   separate control and never folded into Runwarden overhead;
2. proxy input/output inspection overhead;
3. MCP parse plus typed extraction;
4. policy plus journal transaction;
5. approval lease/execute with simulated no-op executor;
6. committed-event-to-SSE visibility;
7. full local request excluding model/provider delay.

Run warm concurrency 1, 16, and 64; run cold startup at concurrency 1.

- [ ] **Step 4: Emit raw and summary artifacts**

Write the following workspace-relative staging layout. Do not discard error
samples or subtract failed requests from denominators:

```text
artifacts/performance/<run-id>/
  run.json
  environment.json
  raw/microbenchmarks.json
  raw/end-to-end-histograms.json
  raw/resource-samples.jsonl
  raw/paired-request-spans.jsonl
  summary.json
  baseline-comparison.json       # release_evidence only
  inputs/workload-set-receipt.json
  inputs/target-receipt.json
  inputs/baseline-receipt.json   # release_evidence only
  inputs/runner-enrollment-receipt.json
  manifest.json
  manifest.sig
  public-key.pem
  SHA256SUMS
```

Raw paired spans are the source of truth. Histograms and summaries are derived
views that the verifier recomputes. The kind-specific schema has a conditional
file rule: `baseline_candidate` and `informational` runs must omit the baseline
receipt, baseline input digest, and `baseline-comparison.json`, and are always
`release_eligible=false`; `release_evidence` runs must include all three and a
verified baseline receipt. No placeholder receipt/comparison is allowed, and
non-release summaries do not report a baseline delta.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-cli --test benchmark_workflow
git add crates/runwarden-cli benchmarks/workloads/end-to-end.json
git commit -m "perf: measure end-to-end Runwarden overhead"
```

## Task 3: Add Fixed-Runner Baselines And Layered Gates

**Files:**

- Create: `benchmarks/baselines/x86_64-unknown-linux-gnu.json`
- Create: `benchmarks/targets.toml`
- Create: `benchmarks/runner-enrollment.toml`
- Create: `scripts/performance_gate_local.sh`
- Modify: `scripts/pr_fast_gate.sh`
- Modify: `scripts/nightly_full_gate.sh`
- Test: `crates/runwarden-cli/tests/performance_thresholds.rs`

**Interfaces:**

- Enforces the plan-index budgets only when environment fingerprint matches.

- [ ] **Step 1: Define target and tolerance rules**

`targets.toml` names the approved CPU model/runner id and requires:

- kernel decision p95 under 2 ms;
- journal propose/evaluate p95 under 10 ms;
- total policy/journal overhead p95 under 50 ms;
- committed-event SSE visibility p95 under 500 ms;
- no more than 15% regression from approved baseline for the same workload.

`runner-enrollment.toml` binds the stable runner id to the exact canonical
environment fingerprint and is committed only after an operator records three
consistent enrollment probes. No hostname wildcard, missing-hardware
placeholder, or self-declared runner id can satisfy the release gate.

- [ ] **Step 2: Reject invalid comparisons**

Threshold evaluation refuses to compare a mismatched target, workload digest,
toolchain, cold/warm mode, or concurrency. Shared-runner output is marked
`informational` and cannot fail/pass the fixed-runner budget.

- [ ] **Step 3: Layer gates**

- PR: `cargo bench --workspace --no-run` and 20-request smoke.
- Nightly fixed runner: all microbenchmarks and end-to-end matrix, then compare.
- Release: use the most recent matching signed performance run; fail if absent
  or stale for the current git/workload digest.

- [ ] **Step 4: Generate and review the initial baseline**

Run three complete fixed-runner sessions, compare variance, and store the
per-cell median of the three session values only after reviewer approval.
Cells are keyed by the canonical tuple `(workload_id, case_id, metric,
concurrency, cold)`; missing or duplicate cells invalidate all three sessions.
Record all three run ids and raw artifact digests in baseline provenance. If no
fixed runner is enrolled in the development
environment, keep the gate explicitly `not_release_eligible`; never generate
placeholder hardware or a passing baseline.

The three sessions are immutable signed `BaselineCandidate` artifacts and omit
baseline receipts by construction. The approved baseline file is a separate
reviewed input whose provenance references all three candidate artifact ids,
manifest digests, and per-cell selection math. It cannot retroactively make a
candidate release eligible. Only a subsequent fresh `ReleaseEvidence` run may
bind that approved baseline receipt and satisfy the release gate.

- [ ] **Step 5: Run tests and commit**

```bash
cargo test -p runwarden-cli --test performance_thresholds
bash scripts/performance_gate_local.sh --smoke
git add benchmarks scripts
git commit -m "perf: gate approved fixed-runner budgets"
```

## Task 4: Publish Honest Performance Evidence

**Files:**

- Create: `docs/contest/performance.md`
- Modify: `docs/03-evaluation-results.md`
- Modify: `docs/contest/scorecard.md`
- Modify: `docs/README.md`
- Create: `crates/runwarden-assurance/src/performance_report.rs`
- Create: `crates/runwarden-assurance/src/performance_artifact.rs`
- Modify: `crates/runwarden-assurance/src/evidence_artifact.rs`
- Modify: `crates/runwarden-cli/src/commands/performance.rs`
- Modify: `crates/runwarden-assurance/src/lib.rs`
- Test: `crates/runwarden-assurance/tests/performance_artifact.rs`
- Test: `crates/runwarden-cli/tests/performance_tamper.rs`

**Interfaces:**

- Produces a Plan 6 `EvidenceArtifactKind::PerformanceRun` plus judge-facing
  component and end-to-end tables with provenance.

- [ ] **Step 1: Write strict artifact and tamper tests**

Export a small fixed run, then verify it independently. Mutate each of raw
paired spans, histogram bins, resource samples, summary percentiles, runner id,
environment fingerprint, workload-set/target/baseline/runner-enrollment
receipt, manifest bytes,
signature, key, extra file, and symlink. Require a stable typed error and a
non-zero CLI exit for every mutation. Directly editing a summary while leaving
raw data unchanged must fail recomputation.

- [ ] **Step 2: Export and verify the signed performance artifact**

Use Plan 6's generic artifact exporter with
`EvidenceArtifactKind::PerformanceRun`. Manifest inputs bind the complete
workload set (`policy.json`, `journal.json`, `filter.json`, `story.json`,
`end-to-end.json`, and its non-self-referential `SHA256SUMS`),
targets, runner enrollment, toolchain fingerprint, and current git SHA.
`ReleaseEvidence` additionally binds the approved baseline; other purposes
must not carry one. The verifier must recompute samples/errors, p50/p95/p99/max, throughput,
paired overhead, resource summaries, baseline delta, fixed-runner match, and
threshold status from raw files. `release_eligible` is verifier output; the
producer cannot assert it.

Expose:

```text
runwarden benchmark verify \
  --artifact artifacts/performance/<run-id> \
  --expected-key-id <key-id> \
  --expected-git-sha <sha> \
  --workload-set benchmarks/workloads \
  --targets benchmarks/targets.toml \
  --baseline benchmarks/baselines/x86_64-unknown-linux-gnu.json \
  --runner-enrollment benchmarks/runner-enrollment.toml \
  --require-release-eligible \
  --require-pass \
  --json
```

Without `--require-pass`, a structurally valid signed artifact may verify while
returning `threshold_status=fail`. `--require-release-eligible` fails for
shared or fingerprint-mismatched runners.

- [ ] **Step 3: Render performance tables from verified evidence**

Show cold/warm, concurrency, p50/p95/p99/max, throughput, errors, CPU/RSS,
baseline delta, hardware, workload digest, and measurement boundary. Separate
model/provider time from Runwarden overhead. Render only the verifier's typed
result; do not parse or trust producer-authored summary fields directly.

- [ ] **Step 4: State limitations**

Explain that local contest simulation is not production load, shared runner
results are not comparable, and the synchronous proxy architecture may limit
throughput even when security correctness passes.

- [ ] **Step 5: Run complete gates**

```bash
cargo bench --workspace --no-run
bash scripts/performance_gate_local.sh --smoke
cargo test -p runwarden-assurance --test performance_artifact
cargo test -p runwarden-cli --test performance_tamper
cargo test --workspace
bash scripts/pr_fast_gate.sh
```

Expected: all pass.

- [ ] **Step 6: Commit the checkpoint**

```bash
git add docs crates/runwarden-assurance crates/runwarden-cli benchmarks scripts
git commit -m "docs(perf): publish reproducible overhead evidence"
```
