# ASUP-E301 - Cancel Drain Timeout

## Symptom

`[ASUP-E301]` means cancellation was requested but drain did not complete within
budget.

## Probable Causes

- A child task ignored cancellation.
- A finalizer or obligation holder blocked drain progress.

## Fix

- Inspect pending children, finalizers, and obligations for the region.
- Make cancellation checkpoints visible in long-running loops.

## Example

CPU-heavy loops should check the `Cx` cancellation state periodically and return
through normal cleanup instead of spinning past drain budget.

The central `Error` display for `ErrorKind::CancelTimeout` starts with:

```text
[ASUP-E301] CancelTimeout
```

## Related

- `ASUP-E003`
- `ASUP-E105`
