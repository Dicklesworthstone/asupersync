# ASUP-E902 - Semantic Lint Ambient Determinism

## Symptom

`[ASUP-E902]` means the semantic lint runner found ambient time or entropy in a
lab-sensitive path.

## Probable Causes

- Code called host wall-clock, monotonic time, or process entropy directly.
- A test fixture bypassed virtual time or deterministic seed capabilities.

## Fix

- Route time and entropy through `Cx` or lab-runtime capabilities.
- Use an allow marker only for deliberate diagnostics with an owner bead.

## Example

Replace direct `SystemTime::now()` use in replay-visible code with the runtime
or lab time source supplied by the caller.

```text
[ASUP-E902] ambient wall-clock call in lab-sensitive path risks deterministic replay
```

## Related

- `ASUP-E401`
- `ASUP-E403`
