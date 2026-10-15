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

Replay divergence display text starts with:

```text
[ASUP-E401] replay divergence at event <index>: expected <event>, got <event>. <context>
```

The root `asupersync lab replay` structured error title and the Frankenlab
replay adapter message also start with `[ASUP-E401]`. Their focused adapter
tests are authored, but were not executed in the static A4 source lane that
added the token.

If two same-seed runs produce different task order, inspect the first trace
event where task ids or wake order differ.

## Related

- `ASUP-E403`
- `ASUP-E402`
