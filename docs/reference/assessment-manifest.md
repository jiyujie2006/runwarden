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

Demo/check flows derive sessions from assessment manifests internally:

```bash
runwarden demo --scenario prompt-injection-file-exfil --output artifacts/demo/prompt-injection-file-exfil --json
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
runwarden check --strict --json
```

to validate the scenario golden corpora that reference these manifests.
