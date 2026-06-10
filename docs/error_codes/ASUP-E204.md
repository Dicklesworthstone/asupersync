# ASUP-E204 - Semaphore Permit Exhausted

## Symptom

`[ASUP-E204]` means a semaphore acquire could not obtain the requested permits.

## Probable Causes

- All permits are held or queued ahead under FIFO policy.
- The request asked for more permits than the semaphore can issue.

## Fix

- Respect FIFO no-queue-jump behavior when diagnosing availability.
- Reduce permit count or split the work into smaller admitted units.

## Example

If a waiter for two permits is queued first, a later one-permit `try_acquire`
must not jump ahead even when one permit is currently free.

## Related

- `ASUP-E006`
- `ASUP-E205`
