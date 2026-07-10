# Reviewer WebUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-file console with a Chinese-first security-story workbench that makes attack, authority, policy, approval, execution, and evidence understandable in ten seconds and uses the same React components for live and verified replay.

**Architecture:** A Vite-built React app consumes only generated Rust story contracts. `useSyncExternalStore` subscribes to interchangeable embedded, replay, and live story sources. Rust serves assets, computes all security states, verifies replay bundles, protects approval APIs, and generates CSP-hashed self-contained offline HTML. The frontend owns layout, selection, playback, and form delivery only.

**Tech Stack:** Node 22.22.2, pnpm 11.9.0, React/React DOM 19.2.7, TypeScript 7.0.2, Vite 8.1.4, Vitest 4.1.10, Testing Library 16.3.2, Playwright 1.61.1, Axe 4.12.1, `json-schema-to-typescript` 15.0.4.

## Global Constraints

- No TypeScript implementation of allow/deny, approval validity, resource
  authorization, evidence validity, report support, or overall story outcome.
- No CDN, remote font, runtime package fetch, service worker, or executable
  story content.
- No `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, or dynamic
  code evaluation.
- Attack text, tool parameters, reasons, and report content render as React
  text nodes.
- Offline mode has no write controls and makes no network request.
- Live POST uses Rust-issued nonce, accepted loopback origin, and expected
  entity versions.
- Chinese is primary copy; technical ids and raw event fields remain English.
- 1920x1080 is the presentation target; 1366x768 is the minimum fully usable
  target.
- WCAG 2.2 AA intent: keyboard operation, visible focus, non-color state, and
  no serious/critical Axe issue.
- Vite assets are deterministic, tracked, drift-tested, and embedded by Rust.

---

## File Responsibility Map

- Create `webui/package.json`, `pnpm-lock.yaml`, TypeScript/Vite/Vitest/
  Playwright configs, and `index.html`.
- Create `webui/scripts/generate-contracts.mjs` and contract drift checker.
- Create `webui/src/contracts/generated.ts` from Rust JSON Schema.
- Create `webui/src/api/{types,embedded,replay,live,reviewer}.ts`.
- Create `webui/src/app/{App,useStorySource,labels}.tsx`.
- Create feature directories for story, authority, approval, evidence, replay,
  and events.
- Create focused shared components and CSS tokens/layout.
- Create `runwarden-cli/src/web_server/assets.rs` and
  `runwarden-cli/src/export/offline_html.rs`.

### Source Contract

```ts
import type {
  SecurityStory,
  StoryEvent,
  StoryReplayFrame,
} from '../contracts/generated'

export interface StorySource {
  readonly kind: 'embedded' | 'replay' | 'live'
  subscribe(listener: () => void): () => void
  getSnapshot(): StorySourceSnapshot
  start(): void
  stop(): void
}

export interface StorySourceSnapshot {
  story: SecurityStory
  events: StoryEvent[]
  replayFrames: StoryReplayFrame[]
  connection: 'offline' | 'connecting' | 'live' | 'disconnected'
  replay: ReplayState | null
  lastSequence: number
}
```

## Checkpoint 1: Static Story Foundation

## Task 1: Bootstrap A Pinned React/Vite Package

**Files:**

- Create: `webui/package.json`
- Create: `webui/pnpm-lock.yaml`
- Create: `webui/tsconfig.json`
- Create: `webui/tsconfig.app.json`
- Create: `webui/vite.config.ts`
- Create: `webui/vitest.config.ts`
- Create: `webui/playwright.config.ts`
- Create: `webui/index.html`
- Create: `webui/src/main.tsx`
- Create: `webui/src/test/setup.ts`
- Modify: `.gitignore`
- Modify: `crates/runwarden-kernel/tests/contract_schemas.rs`

**Interfaces:**

- Produces deterministic `dist/reviewer-console.js` and
  `dist/reviewer-console.css` plus Vite manifest.
- Replaces the current test asserting that an active TypeScript WebUI must not
  exist.

- [ ] **Step 1: Create the exact package manifest**

```json
{
  "name": "@runwarden/reviewer-console",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "packageManager": "pnpm@11.9.0",
  "engines": {"node": ">=22.12.0"},
  "scripts": {
    "contracts:generate": "node scripts/generate-contracts.mjs",
    "contracts:check": "node scripts/check-contracts.mjs",
    "lint": "tsc -p tsconfig.app.json --noEmit",
    "typecheck": "tsc -p tsconfig.app.json --noEmit",
    "test": "vitest run",
    "test:coverage": "vitest run --coverage",
    "build": "vite build",
    "test:e2e": "playwright test"
  },
  "dependencies": {
    "react": "19.2.7",
    "react-dom": "19.2.7"
  },
  "devDependencies": {
    "@axe-core/playwright": "4.12.1",
    "@playwright/test": "1.61.1",
    "@testing-library/jest-dom": "6.9.1",
    "@testing-library/react": "16.3.2",
    "@testing-library/user-event": "14.6.1",
    "@types/node": "26.1.1",
    "@types/react": "19.2.17",
    "@types/react-dom": "19.2.3",
    "@vitejs/plugin-react": "6.0.3",
    "@vitest/coverage-v8": "4.1.10",
    "jsdom": "29.1.1",
    "json-schema-to-typescript": "15.0.4",
    "typescript": "7.0.2",
    "vite": "8.1.4",
    "vitest": "4.1.10"
  }
}
```

- [ ] **Step 2: Configure deterministic Vite output**

`vite.config.ts`:

```ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: './',
  plugins: [react()],
  build: {
    target: 'baseline-widely-available',
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    manifest: true,
    assetsInlineLimit: 100_000,
    rolldownOptions: {
      input: 'src/main.tsx',
      output: {
        entryFileNames: 'reviewer-console.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: asset =>
          asset.names.some(name => name.endsWith('.css'))
            ? 'reviewer-console.css'
            : 'assets/[name]-[hash][extname]',
      },
    },
  },
})
```

The app must not use dynamic imports; a build test later rejects manifest
imports/chunks.

- [ ] **Step 3: Configure Vitest and Playwright**

Use jsdom, `src/test/setup.ts`, restored mocks, and V8 coverage with 80% line/
branch/function/statement thresholds for `src/api`, `src/app`, and `src/features`.
Configure Playwright projects for Chromium at 1366x768 and 1920x1080 with one
retry in CI and zero locally.

- [ ] **Step 4: Install and generate the lockfile**

```bash
pnpm --dir webui install --frozen-lockfile=false
pnpm --dir webui exec playwright install --with-deps chromium
pnpm --dir webui lint
pnpm --dir webui build
```

Expected: the first command creates `pnpm-lock.yaml`; lint/build exit zero.

- [ ] **Step 5: Track deterministic build artifacts**

Add precise `.gitignore` exceptions for:

```text
!webui/dist/
!webui/dist/reviewer-console.js
!webui/dist/reviewer-console.css
!webui/dist/.vite/
!webui/dist/.vite/manifest.json
```

Replace `active_typescript_webui_surface_is_removed` with a test asserting the
package, lockfile, generated contract, and fixed dist files exist.

- [ ] **Step 6: Commit the package shell**

```bash
git add webui .gitignore crates/runwarden-kernel/tests/contract_schemas.rs
git commit -m "feat(webui): bootstrap reviewer console"
```

## Task 2: Generate TypeScript From The Rust Story Schema

**Files:**

- Create: `webui/scripts/generate-contracts.mjs`
- Create: `webui/scripts/check-contracts.mjs`
- Create: `webui/src/contracts/generated.ts`
- Create: `webui/src/contracts/bootstrap.ts`
- Test: `webui/src/contracts/contracts.test.ts`

**Interfaces:**

- Produces the only TypeScript definitions for `StoryEvidenceView`,
  `SecurityStory`, `StoryEvent`, `StoryReplayFrame`, and every nested security
  contract.

- [ ] **Step 1: Implement the generator**

```js
import { compileFromFile } from 'json-schema-to-typescript'
import { writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '../..')
const source = resolve(root, 'schemas/story-evidence-view.schema.json')
const output = resolve(root, 'webui/src/contracts/generated.ts')
const body = await compileFromFile(source, {
  bannerComment: '/* Generated from Rust SecurityStory schema. Do not edit. */',
  style: {singleQuote: true, semi: false, tabWidth: 2},
  unknownAny: false,
})
await writeFile(output, body, 'utf8')
```

- [ ] **Step 2: Implement drift checking without mutating the worktree**

The check script compiles to a temporary file, compares bytes with
`generated.ts`, deletes the temporary file, and exits nonzero with the command
`pnpm --dir webui contracts:generate` when different.

- [ ] **Step 3: Add the non-security bootstrap envelope**

```ts
import type { StoryEvidenceView } from './generated'

export interface ReviewerBootstrapWire {
  schema_version: string
  mode: 'offline' | 'live'
  active_story_id: string
  reviewer_nonce: string | null
  accepted_origin: string | null
  evidence: StoryEvidenceView
}

export interface ReviewerBootstrap {
  mode: 'offline' | 'live'
  schemaVersion: string
  evidence: StoryEvidenceView
  reviewerNonce: string | null
  acceptedOrigin: string | null
  apiBase: string | null
  eventsUrl: string | null
}
```

`mapReviewerBootstrap` is the only snake_case-to-camelCase boundary. It rejects
unsupported schema majors using the same accepted-major list as Rust but does
not recalculate any policy/evidence state. Do not narrow a supported `1.x`
version to the literal `1.0.0`.
Components read `evidence.story.evidence_status` directly; the bootstrap mapper
does not create a second “bundle verification” status.

- [ ] **Step 4: Run generation/tests and commit**

```bash
pnpm --dir webui contracts:generate
pnpm --dir webui contracts:check
pnpm --dir webui test
git add webui/src/contracts webui/scripts
git commit -m "feat(webui): generate Rust story contracts"
```

## Task 3: Implement Embedded And Replay Story Sources

**Files:**

- Create: `webui/src/api/types.ts`
- Create: `webui/src/api/embedded.ts`
- Create: `webui/src/api/replay.ts`
- Create: `webui/src/app/useStorySource.ts`
- Test: `webui/src/api/replay.test.ts`
- Test: `webui/src/app/useStorySource.test.tsx`

**Interfaces:**

- Produces the exact `StorySource` contract in this plan's header.
- Uses React `useSyncExternalStore` with stable subscribe/getSnapshot functions.

- [ ] **Step 1: Write replay clock tests**

Use fake timers and four Rust-produced replay frames. Assert play, pause, step,
speed, restart,
and listener cleanup. `getSnapshot()` must return the identical object until
state changes.

- [ ] **Step 2: Implement the source base class**

```ts
export abstract class MutableStorySource implements StorySource {
  abstract readonly kind: StorySource['kind']
  protected listeners = new Set<() => void>()
  protected snapshot: StorySourceSnapshot

  constructor(snapshot: StorySourceSnapshot) {
    this.snapshot = snapshot
  }

  subscribe = (listener: () => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  getSnapshot = () => this.snapshot
  start() {}
  stop() {}

  protected publish(next: StorySourceSnapshot) {
    this.snapshot = next
    for (const listener of this.listeners) listener()
  }
}
```

- [ ] **Step 3: Implement embedded and replay sources**

`EmbeddedStorySource` never mutates and has connection `offline`.
`ReplayStorySource` selects the Rust-produced frame at its cursor; it does not
reduce events, infer policy, or synthesize stage/operation state. Playback
state is UI metadata only.

- [ ] **Step 4: Implement the React hook**

```ts
import { useEffect, useSyncExternalStore } from 'react'
import type { StorySource } from '../api/types'

export function useStorySource(source: StorySource) {
  const snapshot = useSyncExternalStore(
    source.subscribe,
    source.getSnapshot,
    source.getSnapshot,
  )
  useEffect(() => {
    source.start()
    return () => source.stop()
  }, [source])
  return snapshot
}
```

- [ ] **Step 5: Run tests and commit**

```bash
pnpm --dir webui test
git add webui/src/api webui/src/app
git commit -m "feat(webui): share embedded and replay story sources"
```

## Task 4: Build The First-Screen Security Story Layout

**Files:**

- Create: `webui/src/app/App.tsx`
- Create: `webui/src/app/labels.ts`
- Create: `webui/src/components/{StatusBadge,Panel,CopyId}.tsx`
- Create: `webui/src/features/story/{OutcomeHeader,ScenarioNav,SecurityStoryRail}.tsx`
- Create: `webui/src/features/authority/AuthorityPanel.tsx`
- Create: `webui/src/features/events/EventTimeline.tsx`
- Create: `webui/src/styles/{tokens,layout,components}.css`
- Test: `webui/src/app/App.test.tsx`

**Interfaces:**

- Produces the ten-second first screen at both required resolutions.

- [ ] **Step 1: Write a first-screen semantic test**

Render the hero fixture and assert visible text for scenario/attack, requested
provider/resource, policy result, approval/execution state, and evidence state.
Assert each status has an icon/shape plus text, not color alone.

- [ ] **Step 2: Define Chinese labels as display mappings only**

```ts
export const storyStatusLabels = {
  running: '运行中',
  awaiting_approval: '等待人工审批',
  blocked_before_side_effect: '副作用前已阻断',
  completed_with_controlled_side_effect: '受控执行已完成',
  failed: '执行失败',
  outcome_unknown: '执行结果未知',
  evidence_invalid: '证据无效',
} as const
```

Mappings only translate exact Rust enum values; they do not group or infer.

- [ ] **Step 3: Implement the app grid**

Use semantic regions and this layout contract:

```css
.workbench {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 210px minmax(0, 1fr) 320px;
  grid-template-rows: auto minmax(330px, 1fr) minmax(190px, 32vh);
  grid-template-areas:
    "header header header"
    "scenarios story authority"
    "timeline timeline timeline";
  gap: 12px;
  padding: 12px;
  background: var(--rw-canvas);
  color: var(--rw-text);
}

@media (max-width: 1500px) {
  .workbench {
    grid-template-columns: 184px minmax(0, 1fr) 280px;
    gap: 8px;
    padding: 8px;
  }
}
```

Use a dark neutral canvas, high-contrast text, blue authority accents, amber
review, red deny, green controlled completion, and purple evidence. Fonts use
the local system stack only.

- [ ] **Step 4: Implement the eight-stage story rail**

Render identity, attack, model, proposed tool, policy, approval, execution, and
evidence in fixed order from `story.stage_statuses`. Each stage is a keyboard
button with `aria-current` when selected and displays Rust-provided status,
summary, and observation count.

- [ ] **Step 5: Implement authority and event overview**

Authority shows actor/authz/expiry, providers, roots, recipient/origin/store
constraints, budgets, and policy hash. Event timeline shows committed sequence,
event type, provider, safe summary, operation id, and obs refs. Never render
raw JSON by default.

- [ ] **Step 6: Run tests and commit**

```bash
pnpm --dir webui lint
pnpm --dir webui test
git add webui/src
git commit -m "feat(webui): tell the security story on one screen"
```

## Task 5: Add Analyst Details, Evidence, And Read-Only Approval Views

**Files:**

- Create: `webui/src/features/story/StageDetails.tsx`
- Create: `webui/src/features/approval/ApprovalDrawer.tsx`
- Create: `webui/src/features/evidence/EvidencePanel.tsx`
- Create: `webui/src/features/replay/ReplayControls.tsx`
- Create: `webui/src/app/ModeToolbar.tsx`
- Test: `webui/src/features/approval/ApprovalDrawer.test.tsx`
- Test: `webui/src/features/evidence/EvidencePanel.test.tsx`

**Interfaces:**

- Produces presentation and analyst modes from the same story.
- Approval is read-only in embedded/replay mode.

- [ ] **Step 1: Write safe-rendering tests**

Pass strings containing `<img onerror>`, `</script>`, Unicode bidi controls,
and `secret-raw-marker`. Assert malicious markup is visible as text, no element
is created, bidi controls are escaped/annotated by the Rust-provided preview,
and the secret marker is absent from the fixture.

- [ ] **Step 2: Implement exact approval binding display**

Show requester, provider/action, resource claim, classification, argument hash,
policy hash, expiry, one-shot state, reviewer/reason, lease/consumption, and obs
refs. Include the fixed copy: `本次审批仅绑定此操作，不扩大智能体的常驻权限。`

- [ ] **Step 3: Implement evidence status and report links**

Display chain head, evidence status, verification errors, claims, cited obs
refs, and support state exactly as Rust supplied. Missing evidence remains
visible and never receives a favorable icon.

- [ ] **Step 4: Implement presentation/analyst and replay controls**

Presentation mode enlarges story/outcome and auto-follows. Analyst mode exposes
checks, redacted argument views, hashes, causal links, assertion results, and
claim refs. Replay controls call only `ReplayStorySource` playback methods.

- [ ] **Step 5: Run tests and commit checkpoint 1**

```bash
pnpm --dir webui lint
pnpm --dir webui typecheck
pnpm --dir webui test
pnpm --dir webui build
git add webui
git commit -m "feat(webui): add analyst evidence and replay views"
```

## Task 6: Embed Deterministic Assets And Generate Offline HTML In Rust

**Files:**

- Create: `crates/runwarden-cli/src/web_server/assets.rs`
- Create: `crates/runwarden-cli/src/export/offline_html.rs`
- Modify: `crates/runwarden-cli/src/server.rs`
- Modify: `crates/runwarden-cli/src/export/story_bundle.rs`
- Modify: `crates/runwarden-cli/Cargo.toml`
- Test: `crates/runwarden-cli/tests/offline_story_html.rs`
- Test: `crates/runwarden-cli/tests/webui_asset_drift.rs`

**Interfaces:**

- Produces a self-contained `reviewer-console.html` inside a verified bundle.
- Consumes only a Rust-verified story bundle model.

- [ ] **Step 1: Write offline security tests**

Generate HTML and assert:

- it contains one escaped `application/json` bootstrap;
- it contains no raw secret marker;
- it contains no `file://`, CDN URL, nonce, or private argument;
- CSP has `default-src 'none'` and `connect-src 'none'`;
- offline bootstrap mode is `offline` and reviewer nonce is null;
- script/style hashes match the exact final inline bytes.

- [ ] **Step 2: Embed fixed Vite output**

```rust
pub const REVIEWER_JS: &str =
    include_str!("../../../../webui/dist/reviewer-console.js");
pub const REVIEWER_CSS: &str =
    include_str!("../../../../webui/dist/reviewer-console.css");
```

Add a Rust test that parses Vite manifest and rejects imports, dynamic imports,
remote assets, source maps, or unexpected dist files.

- [ ] **Step 3: Escape final inline bytes and compute CSP hashes**

Replace literal `</script` in JavaScript with `<\\/script` and literal
`</style` in CSS with `<\\/style` before hashing/embedding. Serialize bootstrap
JSON and replace `<`, `>`, `&`, U+2028, and U+2029 with JSON Unicode escapes.
Compute CSP SHA-256 base64 from the transformed inline bytes.

- [ ] **Step 4: Add offline HTML to signed bundle payloads**

Run Rust bundle verification before rendering. Add
`reviewer-console.html` to manifest payload files, then rebuild/sign/checksum
the bundle. Static header displays `VERIFIED AT EXPORT` plus key id and export
time; it does not claim live re-verification.

- [ ] **Step 5: Run tests and commit**

```bash
pnpm --dir webui build
cargo test -p runwarden-cli --test webui_asset_drift
cargo test -p runwarden-cli --test offline_story_html
cargo test -p runwarden-cli --test bundle_tamper
git add webui/dist crates/runwarden-cli
git commit -m "feat(webui): embed verified offline reviewer console"
```

## Checkpoint 2: Live, Approval, And Presentation Quality

## Task 7: Implement The Live SSE Source And Reviewer Client

**Files:**

- Create: `webui/src/api/live.ts`
- Create: `webui/src/api/reviewer.ts`
- Modify: `webui/src/main.tsx`
- Modify: `webui/src/features/approval/ApprovalDrawer.tsx`
- Test: `webui/src/api/live.test.ts`
- Test: `webui/src/api/reviewer.test.ts`
- Test: `crates/runwarden-cli/tests/reviewer_webui_e2e.rs`

**Interfaces:**

- Produces: `LiveStorySource` and `ReviewerClient`.
- Uses the same app/components as replay.

- [ ] **Step 1: Write SSE lifecycle/reconnect tests**

Mock EventSource. Assert one connection starts, cleanup closes it, committed
event ids advance last sequence, disconnect changes connection state, and
reconnect URL includes `after_seq` equal to the last committed sequence.

- [ ] **Step 2: Implement live source**

On start, fetch the active story snapshot once, open EventSource, and on each
event fetch incremental committed state by sequence. It displays server states
only; it does not apply event-to-policy reducers. On 409 schema/version error,
reload the whole story snapshot.

The live snapshot carries separate Rust events and replay frames. Replay picks
the authoritative frame and shows only events with `sequence <= frame.sequence`;
it never folds events into story state. Offline bundle verification supplies
the same `StoryEvidenceView` shape.

- [ ] **Step 3: Implement reviewer client**

```ts
export interface ApprovalDecisionRequest {
  approvalId: string
  decision: 'approve' | 'deny'
  reviewer: string
  reason: string
  expectedApprovalVersion: number
  expectedOperationVersion: number
}
```

The client removes `approvalId` from the body, places it only in
`/api/approvals/{approvalId}/decision`, and explicitly maps the remaining
camelCase fields to Rust's exact snake_case keys
`expected_approval_version`/`expected_operation_version`. POST with the exact
nonce header and same-origin credentials.
On 409, refresh and show the Rust reason. Never optimistically change approval
state.

Add a real integration test that launches the Rust reviewer server with a temp
SQLite state, loads bootstrap in Chromium, submits approval, observes the
journal decision and committed SSE sequence, and verifies the UI changes only
after that event. This complements unit mocks and catches wire drift.

- [ ] **Step 4: Enable live approval controls only**

In live mode, show reason textarea and exact `批准本次执行` / `拒绝并记录原因`
buttons. In replay/offline mode, render the decision record without buttons or
form controls. Disable submission while in flight and restore focus to the
decision summary after committed state arrives.

- [ ] **Step 5: Run tests and commit**

```bash
pnpm --dir webui test
pnpm --dir webui build
cargo test -p runwarden-cli --test reviewer_webui_e2e
git add webui
git commit -m "feat(webui): stream live stories and deliver approvals"
```

## Task 8: Add Visual, Accessibility, And Live/Replay E2E Gates

**Files:**

- Create: `webui/e2e/static-story.spec.ts`
- Create: `webui/e2e/layout.spec.ts`
- Create: `webui/e2e/live-approval.spec.ts`
- Create: `webui/e2e/live-replay-equivalence.spec.ts`
- Create: `webui/e2e/offline-readonly.spec.ts`
- Create: `webui/e2e/secret-redaction.spec.ts`
- Create: `webui/e2e/__screenshots__/`
- Create: `webui/fixtures/hero-story.json`
- Modify: `scripts/pr_fast_gate.sh`
- Modify: `scripts/release_gate_local.sh`

**Interfaces:**

- Enforces the ten-second rubric and both presentation resolutions.

- [ ] **Step 1: Write viewport and screenshot tests**

At 1366x768 and 1920x1080, assert header, attack, selected tool/resource,
policy state, approval/execution state, and evidence status boxes are fully
inside the viewport. Capture stable screenshots with animations disabled.

- [ ] **Step 2: Write keyboard and Axe tests**

Tab from scenario navigation through story stages to approval. Enter a reason,
deny one fixture, then approve another using keyboard only. Run Axe and fail on
serious or critical issues. Assert visible focus and text/icon state markers.

- [ ] **Step 3: Prove live/replay component equivalence**

Feed the same final Rust story through a fake live source and replay source.
Compare the set of `data-stage`, `data-status`, operation ids, claim refs, and
visible final outcome. Only mode labels and playback controls may differ.

- [ ] **Step 4: Prove offline makes no network request**

Open generated offline HTML with Playwright request interception. Fail on any
HTTP(S), WebSocket, EventSource, or local-file request. Assert no approval POST
control exists and CSP is active.

- [ ] **Step 5: Add WebUI gates**

After a package-existence guard during migration, make `pr_fast_gate.sh` run:

```bash
pnpm --dir webui install --frozen-lockfile
pnpm --dir webui contracts:check
pnpm --dir webui lint
pnpm --dir webui typecheck
pnpm --dir webui test
pnpm --dir webui build
git diff --exit-code -- webui/dist webui/src/contracts/generated.ts
```

Make the release gate additionally run `pnpm --dir webui test:e2e`.

- [ ] **Step 6: Run and commit**

```bash
pnpm --dir webui test
pnpm --dir webui build
pnpm --dir webui test:e2e
bash scripts/pr_fast_gate.sh
git add webui scripts
git commit -m "test(webui): gate presentation and accessibility"
```

## Task 9: Remove The Legacy Console And Update Reviewer Documentation

**Files:**

- Delete: `crates/runwarden-cli/src/console.html`
- Modify: `crates/runwarden-cli/src/server.rs`
- Modify: `crates/runwarden-cli/src/web_server/mod.rs`
- Modify: `docs/reference/webui-review-console.md`
- Modify: `docs/reference/rust-kernel-ts-interaction.md`
- Modify: `docs/guides/reviewer-console.md`
- Modify: `docs/reference/contest-review-outputs.md`
- Modify: `docs/README.md`

**Interfaces:**

- Makes the React console the sole reviewer surface after all fallback tests
  pass.

- [ ] **Step 1: Switch live root/assets to embedded Vite files**

Serve a small Rust HTML shell at `/`, JS/CSS at fixed same-origin asset paths,
and strict CSP. Bootstrap includes safe story snapshot, nonce, API base, and
events URL. Cache HTML as no-store and hashed immutable assets as long-lived.

- [ ] **Step 2: Delete the old console after regression parity**

Remove `include_str!("console.html")` only after static, live approval, trace
verification, and offline e2e tests pass. Update Rust tests that previously
searched for `STATIC_EVENTS` to inspect the new bootstrap/story contract.

- [ ] **Step 3: Rewrite references**

Document React as presentation-only, source modes, CSP, approval delivery,
first-screen layout, analyst/presentation modes, accessibility, offline
verification wording, and asset drift gates.

- [ ] **Step 4: Run the complete merge gate**

```bash
pnpm --dir webui contracts:check
pnpm --dir webui lint
pnpm --dir webui typecheck
pnpm --dir webui test
pnpm --dir webui build
pnpm --dir webui test:e2e
cargo test --workspace
bash scripts/pr_fast_gate.sh
bash scripts/release_gate_local.sh
```

Expected: all pass.

- [ ] **Step 5: Commit checkpoint 2**

```bash
git add webui crates/runwarden-cli docs scripts
git commit -m "refactor(webui): replace the legacy reviewer console"
```
