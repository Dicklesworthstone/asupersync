# ASUP-E402 - Futurelock Detected

## Symptom

`[ASUP-E402]` means the lab runtime detected no possible progress for a set of
futures.

## Probable Causes

- Tasks are mutually waiting on each other.
- A wake registration was lost or cancelled incorrectly.

## Fix

- Inspect wait-for edges and the last wake event for each parked task.
- Add a deterministic regression that reproduces the minimal parked set.

## Example

If task A waits for task B while task B waits on a permit held by task A, reduce
the trace to those two wait edges and fix ownership.

## Related

- `ASUP-E205`
- `ASUP-E301`
