# ASUP-E007 - Authorization Denied

## Symptom

`[ASUP-E007]` means the current capability context cannot create tasks in the
target region.

## Probable Causes

- The `Cx` was narrowed without spawn rights.
- Code attempted to spawn through a region it does not own.

## Fix

- Pass a `Cx` with spawn capability for the target region.
- Spawn through the owning scope instead of bypassing capability flow.

## Example

If middleware narrows a request context, keep spawn authority in the request
owner and pass only the specific child capability needed downstream.

## Related

- `ASUP-E004`
- `ASUP-E901`
