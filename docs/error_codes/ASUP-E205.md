# ASUP-E205 - Lock-Order Violation

## Symptom

`[ASUP-E205]` means a path acquired runtime locks outside the required order.
The debug and `lock-metrics` lock-ordering guards emit this token at the start
of rank-order and cross-module violation panics.

## Probable Causes

- Nested runtime or obligation locks were introduced in the wrong order.
- A diagnostic query held one shard lock while entering another domain.

## Fix

- Acquire locks in this order: E(Config), D(Instrumentation), B(Regions), A(Tasks), C(Obligations).
- Snapshot data under one lock and release it before querying another domain.

## Example

An inspector should copy obligation ids while holding the obligation shard, then
drop that lock before querying region state. Acquiring a lower-ranked config
lock while a task-rank lock is still held panics with `[ASUP-E205]`.

## Related

- `ASUP-E101`
- `ASUP-E402`
