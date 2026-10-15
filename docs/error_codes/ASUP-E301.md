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

Region-close diagnostics use the same code when live work is still blocking
drain. The rendered explanation includes the responsible region, child/task
facts, waiter edges, the task's last checkpoint message when available, and any
held obligations:

```text
[ASUP-E301] region close drain still blocked for RegionId(...).
  doc: docs/error_codes/ASUP-E301.md
  - task TaskId(...) still running (state=Running, polls=7, wait_edges=[TaskId(...)], last_checkpoint="connecting to db")
  - obligation ObligationId(...) held by task TaskId(...) (type=SendPermit, holder_waiters=[TaskId(...)], holder_last_checkpoint="connecting to db")
```

## Related

- `ASUP-E003`
- `ASUP-E105`
