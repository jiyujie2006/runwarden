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
| `allowed`, `completed`, `true` | `completed` | `completed` |
| `allowed`, `failed`, `false` | `failed` | `failed_before_side_effect` |
| `allowed`, `executed_with_error`, `true` | `failed` | `executed_with_error` |
| Any unknown or contradictory tuple | `outcome_unknown` | `outcome_unknown` |

Only the tuple with `side_effect_executed = true` becomes a completed
side-effect operation. A legacy `completed` label without a side effect is not
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
directory uses the same workspace-relative containment and symlink checks as
the other demo artifacts.
