# ASUP-E104 - Obligation Abort Missing

## Symptom

`[ASUP-E104]` means cancellation dropped work without aborting the obligation
that represented the reserved operation.

## Probable Causes

- A two-phase reserve/send path lost the reserved permit.
- A cancellation branch returned before abort cleanup.
- An `IoOp` was dropped while still pending, without calling `complete()`,
  `cancel()`, `abort()`, or handing the obligation off with `into_raw()`.

## Fix

- Add abort cleanup to every early return after reservation.
- Test cancellation between reserve and commit.
- Resolve every `IoOp` via `complete`/`cancel`/`abort`, or transfer ownership of
  the pending obligation with `into_raw()` before the guard drops.

## Example

For channel send, reserve the permit, then ensure a cancelled send aborts the
permit before returning the cancellation outcome.

For runtime I/O, the `IoOp` drop guard in `src/runtime/io_op.rs` panics when an
unresolved operation is dropped:

```text
[ASUP-E104] I/O obligation <id> was dropped without completion, cancellation, abort, or explicit into_raw() handoff; see docs/error_codes/ASUP-E104.md
```

## Related

- `ASUP-E101`
- `ASUP-E202`
