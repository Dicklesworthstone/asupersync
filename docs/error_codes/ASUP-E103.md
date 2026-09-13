# ASUP-E103 - Root-Region Obligation

## Symptom

`[ASUP-E103]` means code attempted to create an obligation in the root region.

`GenServerHandle::call` and `GenServerRef::call` return `CallError::Cancelled`
whose reason message starts with this token when the caller task runs in the
root region; the call is refused before any mailbox slot is taken, so the
server is unaffected (asupersync-0ex6x0).

## Probable Causes

- A test fixture used the root `RegionId` for obligation-bearing code.
- Runtime setup skipped child-region allocation before creating a permit.
- A GenServer call was issued from a root-region task (`block_on`,
  `RuntimeHandle::spawn`, or a `LabRuntime` task created directly under the
  root region).

## Fix

- Move the fixture or runtime path into a non-root region.
- Issue GenServer calls from a child region (a `Scope` region or a task
  spawned inside one); casts carry no reply obligation and are unaffected.
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
