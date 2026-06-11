# ASUP-E903 - Semantic Lint Await Holding Resource

## Symptom

`[ASUP-E903]` means an await point appears while a lock, permit, lease, or
capability token remains live.

## Probable Causes

- A guard or permit binding stayed in scope across `.await`.
- Cancellation cleanup can wait while still holding the resource it must release.

## Fix

- Drop, commit, abort, release, or close the resource before awaiting.
- Split the critical section so awaited work happens after resource resolution.

## Example

Move the awaited call after the permit has been sent, aborted, or explicitly
dropped.

```text
[ASUP-E903] permit, lease, or capability token is live across .await
```

## Related

- `ASUP-E101`
- `ASUP-E202`
