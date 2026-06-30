# Runwarden Contest Red-Team Range

Runwarden is a Rust-owned security kernel for demonstrating how agent tool use can be mediated, traced, and reported under adversarial prompts. The contest edition focuses on four reproducible attack chains and a trace-backed reviewer workflow.

Agents see only `runwarden-mcp`. Filesystem, browser, email, API, memory, knowledge, and downstream MCP capabilities are represented as Runwarden providers and evaluated by Rust policy before any trusted side effect.

## Attack Surface

- Prompt injection that tries to read local secrets and exfiltrate them.
- Tool description or argument hijacking that adds hidden email/API actions.
- Memory and knowledge poisoning that asks the agent to skip approval or fabricate citations.
- Local web and environment attacks that target localhost, private networks, or metadata services.

## Core Components

| Component | Role |
| --- | --- |
| `crates/runwarden-kernel` | Rust source of truth for sessions, provider policy, approvals, trace, and contracts. |
| `crates/runwarden-providers` | First-party providers plus mediated demo/external provider catalog. |
| `crates/runwarden-mcp` | Only MCP server exposed to agents. |
| `crates/runwarden-cli` | Contest workflow: sessions, providers, trace, reports, scenarios, demo runner, and static UI. |
| `crates/runwarden-assurance` | Report lint/render and trace-backed scenario metrics. |
| `crates/runwarden-llm-proxy` | Local proxy for model-call filtering and red-team probes. |
| `crates/runwarden-anomaly` | Lightweight behavior anomaly scoring used by MCP/provider evidence. |
| `packages/webui` | Static demo reviewer console. |

## Demo

```bash
cargo build --workspace

target/debug/runwarden eval scenarios --json

target/debug/runwarden demo run \
  --scenario prompt-injection-file-exfil \
  --output artifacts/demo/prompt-injection-file-exfil \
  --json

target/debug/runwarden report render \
  --scenario-suite scenarios \
  --format markdown \
  --output artifacts/reports/contest-report.md \
  --json

target/debug/runwarden ui build \
  --input artifacts/demo \
  --output artifacts/reviewer-console.html \
  --json
```

## Scenario Set

- `prompt-injection-file-exfil`
- `tool-hijack-email-api`
- `memory-knowledge-poisoning`
- `environment-local-web-risk`

Each scenario contains a benign request, attack prompt, deterministic demo-agent script, expected provider calls, expected denials, obs refs, report claims, and metric baselines.

## Verification

```bash
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
cargo test --workspace
pnpm test
pnpm build
```

Reference documentation starts at [docs/README.md](docs/README.md).
