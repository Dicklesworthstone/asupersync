# ASUP-E403 - Lab Seed Nondeterminism

## Symptom

`[ASUP-E403]` means two lab runs with the same seed produced different
outcomes.

## Probable Causes

- A data structure iteration order is nondeterministic.
- The test used wall-clock time, random entropy, or global process state.

## Fix

- Replace unordered iteration with stable ordering in trace-visible paths.
- Route time and entropy through `Cx` capabilities.

## Example

Use `BTreeMap` or explicit sorting for trace-visible maps instead of relying on
hash-map iteration order.

## Related

- `ASUP-E401`
- `ASUP-E901`
