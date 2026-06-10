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

Finalizers should enqueue bounded cleanup or close resources directly; they
should not wait for new work inside the region they are closing.

## Related

- `ASUP-E105`
- `ASUP-E301`
