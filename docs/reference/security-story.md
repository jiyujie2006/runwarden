# Security Story

`SecurityStory` is the Rust-owned reviewer projection for one security run.
The current writer schema is `1.0.0`; readers accept canonical three-component
versions whose major component is `1`. The generated contract is
`schemas/security-story.schema.json`, and Rust remains the source of truth.

## Authoritative State

Rust emits the authoritative `RunMode`, `EnforcementMode`, `StoryProvenance`,
`StoryStatus`, `EvidenceStatus`, `OperationState`, `SideEffectState`, and stage
enums. Presentation code may display these values but must not infer or
reclassify policy, approval, execution, or evidence state from strings.

A story contains exactly one status for each ordered stage: identity, attack,
model, proposed tool, policy, approval, execution, and evidence. Native
observation references are typed `ObservationId` values. An aggregate contains
an event count and final event hash, not copied historical events.

## Native Event Journal

`StateStore::append_event` appends standalone observations only while a native
story's evidence state is `Pending`, through one SQLite immediate transaction.
Legacy-derived, incomplete, invalid, and verified stories are immutable through
this entry point. Its public payload allowlist is `ModelCall`,
`ToolProposal`, `CausalLink`, `InputConsumed`, `SandboxDecision`, and
`MonitorObservation`. Operation proposal, policy decision, approval lifecycle,
provider execution, and evidence-verification events are domain-owned and are
rejected by the public append API; their Rust state transitions append them
through the crate-private transactional helper instead.

Before a public append, Runwarden verifies the complete current story evidence.
The shared helper then allocates the next story-local sequence, seals the event,
CAS-advances the story version, builds the display-safe aggregate, and seals
one replay frame before commit. Event and observation ids are globally unique;
a duplicate returns a structured conflict and is never retried with a newly
invented id. `recorded_at` must not precede the stored story update time, so an
event cannot move the authoritative journal clock backwards.

`events_after` and `replay_frames` use an exclusive `sequence > after_sequence`
cursor and accept limits from 1 through 10,000. Each read uses one SQLite read
transaction and verifies the full story, event chain, replay-frame chain, and
current snapshot before returning a page. This deliberately prevents a cursor
from hiding corruption before the requested page. Replay-frame story snapshots
contain event count and final hash scalars, never a copied `events` array.

## Private Inputs And Safe Views

Raw provider arguments, outputs, trace payloads, reasons, and arbitrary JSON
remain private legacy material. The adapter hashes complete Canonical JSON v1
arguments and outputs, including nested object keys and values, and exposes
only typed SHA-256 commitments and fixed redacted views. Provider/action text
is retained only for a small hardcoded set of known demo pairs; every unknown
pair becomes fixed redacted labels. No raw legacy value is copied into a
`SecurityOperation` or native `StoryEvent`.

Legacy resources use `ResourceClaim::OpaqueLegacy`, which is display-only and
is not an executable claim. The adapter does not create approvals, policy
checks with evidence references, report claims, `StoryEvent` records, or
`ObservationId` values from fixture JSON.

## Native And Legacy Provenance

`StoryProvenance::Native` is reserved for stories backed by the native journal
and sealed event chain. `StoryProvenance::LegacyDerived` identifies a
conservative projection of the existing demo `webui.json` shape.

Every legacy story has `EvidenceStatus::Incomplete`, `event_count = 0`, no
final event hash, empty report claims, and no observation references. It never
becomes `Verified` merely because the legacy trace or report passed its older
verification path. Native assurance must resolve native observations and
recompute support separately.

Legacy operation state mapping is deliberately conservative:

| Legacy tuple | Operation state | Side-effect state |
| --- | --- | --- |
| `denied`, `not_executed`, `false` | `denied` | `blocked_before_execution` |
| `requires_review`, `not_executed`, `false` | `awaiting_approval` | `not_attempted` |
| `allowed`, `completed`, `false` | `observed_only` | `not_attempted` |
| `allowed`, `simulated`, `false` | `observed_only` | `simulated` |
| Exact known-safe pair plus `allowed`, `completed`, `true` | `completed` | `completed` |
| `allowed`, `failed`, `false` | `failed` | `failed_before_side_effect` |
| Exact known-safe pair plus `allowed`, `executed_with_error`, `true` | `failed` | `executed_with_error` |
| Any unknown or contradictory tuple | `outcome_unknown` | `outcome_unknown` |

Only an exact hardcoded provider/action pair with a compatible tuple and
`side_effect_executed = true` may affirm execution of a side effect. Unknown or
redacted pairs that claim `completed` or `executed_with_error` become
`OutcomeUnknown`. A legacy `completed` label without a side effect is not
promoted to `OperationState::Completed`.

## Legacy Authority And Identity

The CLI generates one typed UUIDv7 session id before creating the kernel
session and reuses it in the story authority and every operation. Authority is
projected only from the trusted assessment/session. Provider-call JSON cannot
supply authority, identities, roots, budgets, or approvals, and absolute root
paths are never copied into the story.

The current demo assessments contain a trusted actor but no authz id or
expiry. Their legacy snapshot therefore uses the explicit sentinels
`legacy-not-configured`, `not_configured`, and the Unix epoch. Missing agent
and model identities use `legacy-unavailable`; these labels state absence and
do not claim an identity. Unknown budgets and authority classes remain zero or
empty, and the story remains `Incomplete`.

## Demo Output

`runwarden demo --scenario ... --output <dir>` writes `story.json` beside the
legacy `webui.json` and other retained contest artifacts. `runwarden demo
--all` produces one story for each of the five official scenarios. The output
directory and the `story.json` leaf are each checked through the same
workspace-relative containment boundary, so a pre-existing leaf symlink cannot
redirect the story outside the workspace.

Before an `--all` run, the CLI removes only a direct `story.json` regular file
or symlink leaf from each immediate, ordinary nonofficial child directory. A
symlink leaf is unlinked without following its target. The CLI does not delete
child directories, arbitrary sibling files, nested story files, or anything
under a child that is itself a symlink directory.
