# ASUP-E006 - Region At Capacity

## Symptom

`[ASUP-E006]` means region admission rejected a spawn because the live-task
limit was reached.

## Probable Causes

- The region has too many live child tasks.
- Admission limits are lower than the workload envelope requires.

## Fix

- Await existing task completions before spawning more.
- Raise the region admission limit only after proving the capacity envelope.

## Example

For a fan-out loop, add a bounded concurrency limit and await completions before
starting more work.

The central `Error` display for `ErrorKind::AdmissionDenied` starts with:

```text
[ASUP-E006] AdmissionDenied
```

## Related

- `ASUP-E003`
- `ASUP-E204`
