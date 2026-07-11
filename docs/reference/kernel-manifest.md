# Kernel Manifest

Kernel manifests are represented by assessment and session manifests. Together
they define the policy envelope used by `KernelEnforcer`.

## Policy Fields

Important runtime fields:

- provider allowlist
- scoped roots
- targets
- budgets
- actor
- authorization
- active assessment

## Assessment to Session

The assessment manifest is the human-authored TOML input. The session manifest
is the runtime policy input derived from that assessment.

```bash
runwarden demo --scenario <id> --output artifacts/demo/<id> --json
runwarden check --strict --json
```

Demo and check flows derive the session policy internally. Provider calls use
the session's allowlist, roots, authz, actor, and active-assessment state before
side effects.

## Native Typed Policy

The native typed-policy API is designed for orchestration that uses
`SessionContext::from_authority` and `evaluate_proposal` rather than inspecting
argument-key names. The context is bound to the canonical provider contracts
registered by the server. Evaluation requires a typed `ResourceClaim` and an
authenticated extraction binding that commits the exact provider, action,
complete private argument object, claim, provider contract, and Rust-derived
proposed charge. It returns a `PolicyEvaluation` value snapshot containing the
ordered check ledger, typed claim and policy digests, usage version, charge,
and one of `Allowed`, `Denied`, or `RequiresReview`.

The value additionally exposes a verified-binding flag and a domain-separated
proposal commitment. They bind monitor-only attribution to the exact full
proposal without turning the serializable evaluation into an approval,
execution permit, or side-effect capability.

This API is deliberately state-free. An `Allowed` result does not execute
a tool or reserve budget, and a `RequiresReview` result does not accept a
caller-provided approval id. Native execution still requires the SQLite lease,
durable execution-start transition, authenticated permit, and the single
provider executor boundary.
