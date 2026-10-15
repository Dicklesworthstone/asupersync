# ASUP-E905 - Semantic Lint Outcome Severity

## Symptom

`[ASUP-E905]` means an `Outcome` value is ignored or a cancellation severity is
collapsed into success.

## Probable Causes

- `Outcome::Cancelled` or `Outcome::Panicked` was mapped to a successful value.
- A task or combinator discarded an `Outcome` without preserving severity.

## Fix

- Propagate, match, or record the full `Outcome` lattice explicitly.
- Document fixture-only discards with an owner bead allow marker.

## Example

Return or record cancellation severity instead of assigning an `Outcome` to
`let _`.

```text
[ASUP-E905] Outcome severity value is ignored; preserve or explicitly handle the Outcome lattice
```

## Related

- `ASUP-E301`
- `ASUP-E401`
