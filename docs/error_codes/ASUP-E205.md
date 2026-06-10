# ASUP-E205 - Lock-Order Violation

## Symptom

`[ASUP-E205]` means a path acquired runtime locks outside the required order.

## Probable Causes

- Nested runtime or obligation locks were introduced in the wrong order.
- A diagnostic query held one shard lock while entering another domain.

## Fix

- Acquire locks in this order: E(Config), D(Instrumentation), B(Regions), A(Tasks), C(Obligations).
- Snapshot data under one lock and release it before querying another domain.

## Example

An inspector should copy obligation ids while holding the obligation shard, then
drop that lock before querying region state.

## Related

- `ASUP-E101`
- `ASUP-E402`
