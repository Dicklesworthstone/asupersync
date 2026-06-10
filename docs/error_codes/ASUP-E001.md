# ASUP-E001 - Runtime Unavailable

## Symptom

`[ASUP-E001]` appears when a spawn handle points at a runtime that is no
longer available.

## Probable Causes

- The runtime was dropped before the spawn call.
- Shutdown began before the caller enqueued the task.

## Fix

- Hold a strong runtime handle for the spawner lifetime.
- Stop spawning after shutdown starts and treat this error as terminal.

## Example

If shutdown owns the last runtime reference, move task creation before shutdown
or return a cancelled outcome instead of retrying spawn forever.

## Related

- `ASUP-E003`
- `ASUP-E006`
