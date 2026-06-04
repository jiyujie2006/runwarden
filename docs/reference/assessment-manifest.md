# Assessment Manifest

Assessment manifests are TOML files that define an evaluation or security
assessment scope. They are the input for persisted session manifests.

## Core Fields

- `version`
- `name`
- `mode`
- `provider_allowlist`
- `roots`
- `targets`
- `budgets`
- `authorization`
- `actor`
- `active_assessment`

## Runtime Role

`runwarden session create` derives a session from an assessment manifest:

```bash
runwarden session create --manifest scenarios/enterprise-agent-security/manifests/assessment.toml --session enterprise_ops --json
```

The resulting session carries the provider allowlist, scoped roots, actor,
authz state, budgets, and active-assessment flag used by `KernelEnforcer`.

## Scenario Contract

Checked-in scenarios store manifests at:

```text
scenarios/<scenario>/manifests/assessment.toml
```

Run:

```bash
runwarden eval scenarios --json
```

to validate the scenario golden corpora that reference these manifests.
