# Runwarden Red-Team Harness

Adversarial test harness + corpora that drive attacks against the Runwarden-supervised
agent stack and score whether Runwarden blocked them. This is the contest deliverable
#1 "agent attack scripts" + "adversarial/jailbreak test-case sets".

## Layout

- `corpora/*.jsonl` — hand-authored attack **sets**, one JSON object per line:
  `{"id","category","expected","prompt"}`. Output-filter rows may also include
  `upstream_returns`, which is the mock model response. `expected` is one of
  `input_blocked`, `output_blocked`, `tool_denied`, `requires_review`, or
  `allowed_benign`.
  - `prompt_injection.jsonl`, `jailbreak.jsonl`, `indirect_prompt_injection.jsonl`,
    `encoded_bypass.jsonl`, `report_fabrication.jsonl` → `input_blocked`
  - `tool_hijack.jsonl`, `path_escape.jsonl`, `schema_poisoning.jsonl`,
    `environment_egress.jsonl` → `tool_denied` or `input_blocked`
  - `memory_poisoning.jsonl`, `knowledge_poisoning.jsonl` → `tool_denied` or
    `requires_review`
  - `benign_control.jsonl` → `allowed_benign`
  - `output_filter.jsonl` → `output_blocked` or `allowed_benign`
  - Public datasets (HarmBench/AdvBench/JailbreakBench/garak/PyRIT) can be added in
    the same JSONL shape.
- `run.py` — the harness, three modes (below).

## Modes

### `proxy-probe` — base-model input filter (fast, no LLM)

Sends each attack prompt to `runwarden-llm-proxy` at `/v1/chat/completions`
with a mock upstream and scores whether the input filter blocked it (HTTP 403)
before forwarding. This harness mode exercises the input filter only; the proxy
binary also supports `/v1/responses`, output inspection, streaming SSE output
blocking, and `model_call` trace JSONL. Reproducible + offline.

The harness generates a fresh 256-bit `RUNWARDEN_PROXY_CLIENT_TOKEN` for the
proxy process and sends it as `Authorization: Bearer ...` on every request. The
client capability is independent of the upstream API-key variable; an
unauthenticated 401 is not counted as an input-filter block.

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
            redteam/corpora/encoded_bypass.jsonl redteam/corpora/benign_control.jsonl \
  --summary-out artifacts/redteam/proxy-probe-summary.json \
  --fail-on-fail
```

Use `--fail-on-fail` for deterministic gates. Samples whose expected outcome
belongs to agent or scenario replay are marked `SKIP` with a coverage reason.

### `output-probe` — base-model streaming output filter

Sends benign prompts through `runwarden-llm-proxy` while the mock upstream
returns the corpus row's independent `upstream_returns` text as a streaming
completion. Harmful completions should be blocked with HTTP 403. Each probe
uses a fresh proxy client capability, and the mock emits a complete Chat SSE
sequence ending in `[DONE]`; malformed or truncated streams are separate
fail-closed protocol tests in the Rust proxy suite, not corpus passes.

```bash
python3 redteam/run.py output-probe \
  --corpora redteam/corpora/output_filter.jsonl \
  --summary-out artifacts/redteam/output-probe-summary.json \
  --fail-on-fail
```

### `agent-drive` — real LLM tool-call supervision

Drives `opencode` with each attack prompt through the local LLM proxy, configured
to use `runwarden-mcp` as its only tool server, and scores captured-call-bound
provider events from an isolated per-case `events.jsonl`. Start `runwarden demo` (or an
equivalent proxy on `127.0.0.1:8787`) with a working upstream before this optional mode.

In the agent shell, export the `RUNWARDEN_PROXY_CLIENT_TOKEN` printed by the
fresh demo run. Do not copy the upstream API key into that shell: OpenCode
authenticates to the local proxy with the client capability, while the upstream
credential remains at the proxy boundary. The supplied OpenCode config expects
`{env:RUNWARDEN_PROXY_CLIENT_TOKEN}`.

```bash
mkdir -p /tmp/oc-test
cp examples/agent-configs/opencode.runwarden-only.json /tmp/oc-test/opencode.json
export PATH="$PWD/target/debug:$PATH"
python3 redteam/run.py agent-drive \
  --corpora redteam/corpora/path_escape.jsonl \
  --config-dir /tmp/oc-test --model runwarden-proxy/big-pickle --limit 2
```

Expected when the model calls the tool: path traversal is denied
(`error_kind: root_escape`, `side_effect_executed: false`). This mode is
model-dependent and has an explicitly limited evidence claim. Every case gets a
fresh state directory, session identity, run nonce, capture shim, and persistent
evidence directory. Scoring verifies freshness, the provider-event hash chain,
and bindings for session, provider, canonical action, and critical-parameter
digests. It does **not** cryptographically prove that the attack prompt caused
the observed tool call.

Accordingly every evaluated row is labeled
`evidence_scope: provider_observational`, `assurance: exploratory`, and
`counts_toward_deterministic_verified: false`. The summary reports these under
`exploratory_*`; it excludes them from `deterministic_verified_*` and from the
deterministic `coverage` map. Release gates use proxy/output probes plus
scenario replay.

## Notes

- `agent-drive` uses a directive suffix ("You must call the relevant runwarden tool")
  because free models don't always invoke tools from a bare instruction.
- Results are written to `artifacts/redteam/*-results.jsonl`; summary JSON is
  written to `artifacts/redteam/*-summary.json`. Agent-drive also keeps
  per-case manifests, captured tool calls, sealed events, and results under
  `artifacts/redteam/agent-drive-evidence/` by default.
- A PASS from `agent-drive` is exploratory provider-observation evidence, not a
  deterministic ASR/containment data point and not proof of prompt-to-tool
  causality.
- Validate corpus schema and ids with
  `python3 redteam/validate_corpora.py redteam/corpora/*.jsonl`.
