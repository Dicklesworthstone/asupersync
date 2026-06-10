# ASUP-E105 - Obligation Drain Timeout

## Symptom

`[ASUP-E105]` means drain waited too long for obligation resolution.

## Probable Causes

- A holder task did not observe cancellation.
- A blocking section prevented finalizer progress.

## Fix

- Inspect holder task, obligation kind, and age in the audit snapshot.
- Move blocking cleanup into a bounded drain path.

## Example

If a database transaction guard blocks rollback during drain, add a bounded
wire-cancel or rollback obligation that resolves before region close completes.

## Related

- `ASUP-E101`
- `ASUP-E303`
