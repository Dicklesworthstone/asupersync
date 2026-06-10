# ASUP-E003 - Region Closed

## Symptom

`[ASUP-E003]` appears when the target region is closing or already closed and
therefore admits no new tasks.

## Probable Causes

- Spawn raced with region close.
- The caller kept using a scope after the owning region began draining.

## Fix

- Treat spawn-vs-shutdown as a normal cancellation race.
- Move the spawn earlier or route work through a still-live parent region.

## Example

If a worker sees this during graceful shutdown, stop producing new child work
and let the region drain.

The central `Error` display for `ErrorKind::RegionClosed` starts with:

```text
[ASUP-E003] RegionClosed
```

## Related

- `ASUP-E002`
- `ASUP-E301`
