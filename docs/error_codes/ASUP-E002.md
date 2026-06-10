# ASUP-E002 - Region Not Found

## Symptom

`[ASUP-E002]` means a spawn target referenced a region id that is not present in
runtime state.

## Probable Causes

- The region id was cached past region close.
- A test fixture reused a stale `RegionId`.

## Fix

- Spawn into a live ancestor region.
- Refresh the handle that produced the region id before retrying.

## Example

When a region closes, discard child handles derived from that region and
request a fresh scope from the live owner.

## Related

- `ASUP-E003`
- `ASUP-E101`
