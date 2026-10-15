# ASUP-E907 - Semantic Lint Cleanup Budget

## Symptom

`[ASUP-E907]` means cleanup, drain, or finalizer code has no visible bounded
budget.

## Probable Causes

- Cleanup used `Budget::INFINITE` or ad hoc wall-duration constants.
- A drain or finalizer call has no obvious `Budget` argument or owner boundary.

## Fix

- Derive cleanup duration from an explicit `Budget` or deadline capability.
- Keep finalizers bounded so region close can reach quiescence.

## Example

Replace an unbounded cleanup call with a budget derived from the enclosing
operation.

```text
[ASUP-E907] cleanup or drain path uses Budget::INFINITE without a bounded owner
```

## Related

- `ASUP-E105`
- `ASUP-E303`
