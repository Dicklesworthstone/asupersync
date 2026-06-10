# ASUP-E401 - Replay Divergence

## Symptom

`[ASUP-E401]` means a replay run diverged from its recorded deterministic trace.

## Probable Causes

- Code introduced nondeterministic ordering or ambient time.
- A trace schema changed without migration or golden update.

## Fix

- Compare the first-divergence event, not just the final failure.
- Normalize ordering, timestamps, and ids before accepting new goldens.

## Example

If two same-seed runs produce different task order, inspect the first trace
event where task ids or wake order differ.

## Related

- `ASUP-E403`
- `ASUP-E402`
