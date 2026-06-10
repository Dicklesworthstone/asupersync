# ASUP-E103 - Root-Region Obligation

## Symptom

`[ASUP-E103]` means code attempted to create an obligation in the root region.

## Probable Causes

- A test fixture used the root `RegionId` for obligation-bearing code.
- Runtime setup skipped child-region allocation before creating a permit.

## Fix

- Move the fixture or runtime path into a non-root region.
- Preserve the guard because root-region obligations hide leaks and break quiescence.

## Example

In tests, use a non-root synthetic region instead of `ArenaIndex::new(0, 0)`
when creating permits or guards.

The typed token reserve guard starts with:

```text
[ASUP-E103] Cannot create obligation token in root region
```

## Related

- `ASUP-E101`
- `ASUP-E301`
