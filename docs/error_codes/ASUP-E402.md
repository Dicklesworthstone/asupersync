# ASUP-E402 - Futurelock Detected

## Symptom

`[ASUP-E402]` means the lab runtime detected a task that stopped being polled
while it still held one or more obligations.

## Probable Causes

- Tasks are mutually waiting on each other.
- A wake registration was lost or cancelled incorrectly.
- A task passed its last checkpoint while holding an obligation and then stopped
  making poll progress.

## Fix

- Inspect wait-for edges and the last wake event for each parked task.
- Use the `last_checkpoint` field in the diagnostic to jump to the most recent
  task phase that was still making progress.
- Add a deterministic regression that reproduces the minimal parked set.

## Example

The panic/display text starts with:

```text
[ASUP-E402] futurelock detected: <task> in <region> idle=<steps> held=<obligations> last_checkpoint="<checkpoint message>"
```

If task A waits for task B while task B waits on a permit held by task A, reduce
the trace to those two wait edges and fix ownership.

## Related

- `ASUP-E205`
- `ASUP-E301`
