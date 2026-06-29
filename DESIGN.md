# Design System - Runwarden

## Product Context

- **What this is:** Runwarden is a contest red-team range for demonstrating
  Rust-mediated AI agent tool safety under adversarial prompts.
- **Who it is for:** Security reviewers, competition judges, platform
  engineers, and operators evaluating agent tool mediation.
- **Space/industry:** AI agent security, red-team evaluation, runtime
  guardrails, trace evidence, and report verification.
- **Project type:** Data-dense static reviewer console backed by CLI, MCP,
  scenario, trace, and report workflows.
- **Memorable thing:** Reproducible attacks with evidence-backed denials.

## Aesthetic Direction

- **Direction:** Industrial / Utilitarian Security Workbench.
- **Decoration level:** Minimal with intentional evidence-line accents.
- **Mood:** Calm, exact, operational, evidence-first.

## Typography

- **Display / Page titles:** IBM Plex Sans, 600-700 weight.
- **Body / UI:** IBM Plex Sans, 400-500 weight.
- **Labels:** IBM Plex Sans, 500-600 weight.
- **Data / Tables:** JetBrains Mono for obs IDs, hashes, provider IDs,
  argument hashes, code, and schema-like values.
- **Code:** JetBrains Mono.
- **Scale:** 12px metadata, 14px compact table/body, 16px default body, 18px
  section lead, 22px section heading, 34px page heading, 44px major title.

## Color

- **Approach:** Restrained balanced palette with semantic colors doing real
  work.
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

## Spacing

- **Base unit:** 4px.
- **Density:** Compact but not cramped.
- **Scale:** 2xs 2px, xs 4px, sm 8px, md 12px, lg 16px, xl 24px, 2xl 32px,
  3xl 48px.
- **Table rows:** 36px minimum for read-only rows, 44px minimum when actions are
  present.
- **Touch targets:** 44px minimum.

## Layout

- **Approach:** Grid-disciplined static workbench.
- **Desktop grid:** Scenario navigation, fluid evidence workspace, and compact
  summary/details area.
- **Top status strip:** Scenario count, trace state, denial count, review
  count, blocked side-effect count, and report link status.
- **Main workspace:** Scenario summaries, attack timelines, provider outcomes,
  trace references, metrics, and report claim links.
- **Border radius:** sm 4px, md 8px, full 9999px for status pills only.
- **Cards:** Only when the card is the interaction; no decorative card grids.

## Components

- **Status strip:** Text + color + icon/dot; never color alone.
- **Risk badge:** `allow`, `deny`, `requires_review`, `failed`, `verified`,
  `incomplete`.
- **Scenario table:** Dense rows, provider counts, denial counts, review counts,
  and report claim counts.
- **Trace timeline:** Verified obs IDs with provider, decision, execution
  status, and side-effect state.
- **Report claim map:** Claim-to-obs mapping must be visible and keyboard
  reachable.
- **Metrics table:** Trace completeness and report citation accuracy per
  scenario.

## Motion

- **Approach:** Minimal-functional.
- **Durations:** micro 50-100ms, short 120-180ms, medium 220-300ms.
- **Easing:** enter ease-out, exit ease-in, move ease-in-out.
- **Use motion for:** row expansion, filter application, status changes.
- **Do not use motion for:** decorative atmosphere, background movement, or
  celebratory effects.

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-05-27 | Industrial / Utilitarian Security Workbench | Matches serious agent-security posture and avoids generic SaaS dashboard patterns. |
| 2026-05-27 | IBM Plex Sans + JetBrains Mono | Gives readable UI text and precise evidence/code/data rendering without default font stacks. |
| 2026-05-27 | Warm neutral surfaces + oxide green primary | Keeps long review sessions readable and gives Runwarden a distinct verification-centered accent. |
| 2026-05-27 | Minimal-functional motion | Supports comprehension without making safety-critical events feel theatrical. |
| 2026-06-29 | Static contest reviewer console | Keeps policy in Rust and makes reviewer evidence reproducible from demo JSON. |
