# ASUP-E104 - Obligation Abort Missing

## Symptom

`[ASUP-E104]` means cancellation dropped work without aborting the obligation
that represented the reserved operation.

## Probable Causes

- A two-phase reserve/send path lost the reserved permit.
- A cancellation branch returned before abort cleanup.

## Fix

- Add abort cleanup to every early return after reservation.
- Test cancellation between reserve and commit.

## Example

For channel send, reserve the permit, then ensure a cancelled send aborts the
permit before returning the cancellation outcome.

## Related

- `ASUP-E101`
- `ASUP-E202`
