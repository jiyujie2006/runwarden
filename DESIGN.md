# Design System - Runwarden

## Product Context

- **What this is:** Runwarden Enterprise is an agent-native security kernel with a Reviewer Console for approving, auditing, and verifying AI agent tool use.
- **Who it is for:** Security reviewers, platform engineers, enterprise AI teams, and operators responsible for safe agent execution.
- **Space/industry:** AI agent security, runtime guardrails, security operations, LLM observability, compliance evidence.
- **Project type:** Data-dense web app / security control plane, supported by CLI and MCP entrypoints.
- **Memorable thing:** Serious software for serious agent security work.

## Aesthetic Direction

- **Direction:** Industrial / Utilitarian Security Workbench.
- **Decoration level:** Minimal with intentional evidence-line accents.
- **Mood:** Calm, exact, operational, evidence-first.

## Typography

- **Display / Page titles:** IBM Plex Sans, 600-700 weight.
- **Body / UI:** IBM Plex Sans, 400-500 weight.
- **Labels:** IBM Plex Sans, 500-600 weight.
- **Data / Tables:** JetBrains Mono for obs IDs, hashes, provider IDs, argument hashes, code, and schema-like values.
- **Code:** JetBrains Mono.
- **Loading:** Prefer self-hosting for enterprise/offline packaging.
- **Scale:** 12px metadata, 14px compact table/body, 16px default body, 18px section lead, 22px section heading, 34px page heading, 44px major title.

## Color

- **Approach:** Restrained balanced palette with semantic colors doing real work.
- **Primary:** Oxide Green `#2F6F4E`.
- **Primary ink:** `#F3FAF5`.
- **Background / Paper:** `#F7F8F4`.
- **Surface:** `#FFFFFF`.
- **Surface 2:** `#EEF1EA`.
- **Line:** `#CDD5C8`.
- **Ink:** Graphite `#20241F`.
- **Muted text:** `#687064`.
- **Semantic success / verified:** `#1F7A4D`.
- **Semantic warning / review:** `#A76716`.
- **Semantic error / denied:** `#B42318`.
- **Semantic info / trace:** `#2866A8`.
- **Dark mode:** Redesign surfaces around `#151813`, `#1E231C`, `#262D24`; reduce saturation and keep semantic colors text-readable.

## Spacing

- **Base unit:** 4px.
- **Density:** Compact but not cramped.
- **Scale:** 2xs 2px, xs 4px, sm 8px, md 12px, lg 16px, xl 24px, 2xl 32px, 3xl 48px.
- **Table rows:** 36px minimum for read-only rows, 44px minimum when actions are present.
- **Touch targets:** 44px minimum.

## Layout

- **Approach:** Grid-disciplined app shell.
- **Desktop grid:** 220-240px left nav, fluid main workspace, 320-380px details drawer.
- **Top status strip:** Current assessment/session, risk status, trace integrity, pending approvals, fast/full gate status.
- **Main workspace:** Tables, timelines, queues, reports, and artifact lists.
- **Details drawer:** Shared detail pattern for approvals, providers, obs events, report claims, and artifacts.
- **Border radius:** sm 4px, md 8px, lg 12px, full 9999px for status pills only.
- **Cards:** Only when the card is the interaction; no decorative card grids.

## Components

- **Status strip:** Text + color + icon/dot; never color alone.
- **Risk badge:** `allow`, `deny`, `requires_review`, `failed`, `tampered`, `verified`, `incomplete`.
- **Data table:** Dense rows, sticky header for long lists, monospace IDs, row click opens details drawer.
- **Details drawer:** Title, state, side effects, obs refs, hashes, actions, recovery path.
- **Approval confirmation:** High-risk approval only inside details drawer after context is visible.
- **Trace timeline:** Paginated, filterable, keyboard traversable, with obs jump search.
- **Report claim map:** Claim-to-obs mapping must be visible and keyboard reachable.
- **Artifact verifier:** Hash status, redaction sidecar status, provenance/SBOM evidence.

## Motion

- **Approach:** Minimal-functional.
- **Durations:** micro 50-100ms, short 120-180ms, medium 220-300ms.
- **Easing:** enter ease-out, exit ease-in, move ease-in-out.
- **Use motion for:** drawer open/close, row expansion, filter application, status changes.
- **Do not use motion for:** decorative atmosphere, background movement, celebratory effects.

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-27 | Industrial / Utilitarian Security Workbench | Matches serious agent-security posture and avoids generic SaaS dashboard patterns. |
| 2026-05-27 | IBM Plex Sans + JetBrains Mono | Gives readable UI text and precise evidence/code/data rendering without default font stacks. |
| 2026-05-27 | Warm neutral surfaces + oxide green primary | Keeps long review sessions readable and gives Runwarden a distinct verification-centered accent. |
| 2026-05-27 | Minimal-functional motion | Supports comprehension without making safety-critical actions feel theatrical. |
| 2026-05-27 | Details drawer approval confirmation | High-risk approvals require context, reason, and final summary before consuming ApprovalRecord. |

