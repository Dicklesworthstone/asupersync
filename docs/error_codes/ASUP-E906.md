# ASUP-E906 - Semantic Lint Race Loser Drain

## Symptom

`[ASUP-E906]` means a race loser appears to be dropped or drop-abort-defused
without local loser-drain proof.

## Probable Causes

- A loser-named handle was dropped without abort, join, drain, or cancel evidence.
- A `defuse_drop_abort` path lacks nearby proof that the loser is drained.

## Fix

- Cancel and join losing branches before returning the race winner.
- Add local loser-drain proof comments only when another path actually drains the
  loser.

## Example

Abort a losing handle with `CancelReason::race_loser()` and join it before the
winner result escapes.

```text
[ASUP-E906] race loser is dropped without explicit abort/join loser-drain invariant evidence
```

## Related

- `ASUP-E302`
- `ASUP-E303`
