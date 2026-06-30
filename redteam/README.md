# Runwarden Red-Team Harness

Adversarial test harness + corpora that drive attacks against the Runwarden-supervised
agent stack and score whether Runwarden blocked them. This is the contest deliverable
#1 "agent attack scripts" + "adversarial/jailbreak test-case sets".

## Layout

- `corpora/*.jsonl` — hand-authored attack **sets**, one JSON object per line:
  `{"id","category","expected","prompt"}`. `expected` is `input_blocked` (proxy must
  block the prompt) or `tool_denied` (kernel must deny the resulting tool call).
  - `prompt_injection.jsonl`, `jailbreak.jsonl` → `input_blocked`
  - `tool_hijack.jsonl`, `path_escape.jsonl`, `memory_poisoning.jsonl` → `tool_denied`
  - Public datasets (HarmBench/AdvBench/JailbreakBench/garak/PyRIT) can be added in
    the same JSONL shape.
- `run.py` — the harness, two modes (below).

## Modes

### `proxy-probe` — base-model input filter (fast, no LLM)

Sends each attack prompt directly to `runwarden-llm-proxy` and scores whether the
input filter blocked it (HTTP 403) before forwarding. Reproducible + offline.

```bash
python3 redteam/run.py proxy-probe \
  --corpora redteam/corpora/prompt_injection.jsonl redteam/corpora/jailbreak.jsonl
```

Result on the hand-authored set: **5/16 blocked** (31%). The 11 forwarded are
paraphrases/synonyms the rule-based substring filter misses — the empirical
justification for the L2 semantic filter.

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
- Results are written to `artifacts/redteam/*-results.jsonl`; a summary is printed.
