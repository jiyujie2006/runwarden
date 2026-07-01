# Runwarden Red-Team Harness

Adversarial test harness + corpora that drive attacks against the Runwarden-supervised
agent stack and score whether Runwarden blocked them. This is the contest deliverable
#1 "agent attack scripts" + "adversarial/jailbreak test-case sets".

## Layout

- `corpora/*.jsonl` — hand-authored attack **sets**, one JSON object per line:
  `{"id","category","expected","prompt"}`. `expected` is one of
  `input_blocked`, `tool_denied`, `requires_review`, or `allowed_benign`.
  - `prompt_injection.jsonl`, `jailbreak.jsonl`, `indirect_prompt_injection.jsonl`,
    `encoded_bypass.jsonl`, `report_fabrication.jsonl` → `input_blocked`
  - `tool_hijack.jsonl`, `path_escape.jsonl`, `schema_poisoning.jsonl`,
    `environment_egress.jsonl` → `tool_denied` or `input_blocked`
  - `memory_poisoning.jsonl`, `knowledge_poisoning.jsonl` → `tool_denied` or
    `requires_review`
  - `benign_control.jsonl` → `allowed_benign`
  - Public datasets (HarmBench/AdvBench/JailbreakBench/garak/PyRIT) can be added in
    the same JSONL shape.
- `run.py` — the harness, two modes (below).

## Modes

### `proxy-probe` — base-model input filter (fast, no LLM)

Sends each attack prompt to `runwarden-llm-proxy` at `/v1/chat/completions`
with a mock upstream and scores whether the input filter blocked it (HTTP 403)
before forwarding. This harness mode exercises the input filter only; the proxy
binary also supports `/v1/responses`, output inspection, streaming SSE output
blocking, and `model_call` trace JSONL. Reproducible + offline.

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl \
            redteam/corpora/encoded_bypass.jsonl redteam/corpora/benign_control.jsonl \
  --summary-out artifacts/redteam/proxy-probe-summary.json \
  --fail-on-fail
```

Use `--fail-on-fail` for deterministic gates. Samples whose expected outcome
belongs to agent or scenario replay are marked `SKIP` with a coverage reason.

### `agent-drive` — real LLM tool-call supervision

Drives `opencode` (real free model, no API key) with each attack prompt, configured
to use `runwarden-mcp` as its only tool server, and scores whether the Runwarden
kernel **denied** the resulting tool call (parsed from the runwarden-mcp debug log).

```bash
# requires: opencode installed + runwarden-mcp built + /tmp/oc-test/opencode.json
python3 redteam/run.py agent-drive \
  --corpora redteam/corpora/path_escape.jsonl \
  --model opencode/big-pickle --limit 2
```

Result: **2/2 denied** (`error_kind: root_escape`, `side_effect_executed: false`) —
the kernel blocks path-traversal reads driven by the real LLM.

## Notes

- `agent-drive` uses a directive suffix ("You must call the relevant runwarden tool")
  because free models don't always invoke tools from a bare instruction.
- Results are written to `artifacts/redteam/*-results.jsonl`; summary JSON is
  written to `artifacts/redteam/*-summary.json`.
- Validate corpus schema and ids with
  `python3 redteam/validate_corpora.py redteam/corpora/*.jsonl`.
