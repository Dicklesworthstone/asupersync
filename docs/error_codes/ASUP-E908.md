# ASUP-E908 - Semantic Lint Core Tokio Boundary

## Symptom

`[ASUP-E908]` means the semantic lint runner found malformed or leaking Tokio
feature-boundary evidence.

## Probable Causes

- A production dependency graph is not classified tokio-free.
- A scoped Tokio carve-out lacks quarantine rationale or a valid RCH proof
  command.

## Fix

- Fix the feature graph or move the Tokio edge behind a documented
  non-production carve-out.
- Update proof-lane commands so production and scoped-audit claims are distinct.

## Example

Keep production `asupersync` normal graphs tokio-free and quarantine fuzz or
compat edges in the boundary contract.

```text
[ASUP-E908] production profile declares a tokio dependency path
```

## Related

- `ASUP-E901`
- `ASUP-E403`
