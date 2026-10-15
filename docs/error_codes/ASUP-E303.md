# ASUP-E303 - Finalizer Timeout

## Symptom

`[ASUP-E303]` means a region finalizer exceeded its configured completion
budget.

## Probable Causes

- Cleanup performed unbounded I/O or blocking work.
- A finalizer waited on a task in the same closing region.

## Fix

- Move blocking cleanup behind an explicit bounded capability.
- Avoid waiting on same-region tasks from finalizer code.

## Example

```text
[ASUP-E303] finalizer 42 exceeded 5000000000ns completion budget (escalation=BoundedPanic); move blocking cleanup behind a bounded capability or avoid waiting on same-region tasks from finalizer code
```

Finalizers should enqueue bounded cleanup or close resources directly; they
should not wait for new work inside the region they are closing. The source
diagnostic is emitted from `src/record/finalizer.rs`.

## Related

- `ASUP-E105`
- `ASUP-E301`
