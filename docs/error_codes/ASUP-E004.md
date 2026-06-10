# ASUP-E004 - Local Scheduler Unavailable

## Symptom

`[ASUP-E004]` means `spawn_local` was attempted without an active worker-local
scheduler.

## Probable Causes

- `spawn_local` was called outside a worker thread.
- A fixture constructed runtime state without local scheduler context.

## Fix

- Use `spawn` for `Send` tasks.
- Call `spawn_local` only from runtime worker context.

## Example

Library code that may run outside the runtime should accept a `Cx` and spawn
through the owning scope instead of assuming worker-local state exists.

## Related

- `ASUP-E001`
- `ASUP-E007`
