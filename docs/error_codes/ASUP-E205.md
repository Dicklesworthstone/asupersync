# ASUP-E205 - Lock-Order Violation

## Symptom

`[ASUP-E205]` means a path violated the runtime lock-order policy. The debug and
`lock-metrics` guards emit this token at the start of rank-order,
cross-module, and lock-name policy panics.

## Probable Causes

- Nested runtime or obligation locks were introduced in the wrong order.
- A diagnostic query held one shard lock while entering another domain.
- `lock-metrics` was enabled and a named lock used an undocumented unranked
  name. These fail closed with `reason=denied-unknown-lock-rank`.

## Fix

- Acquire locks in this order: E(Config), D(Instrumentation), B(Regions), A(Tasks), C(Obligations).
- Snapshot data under one lock and release it before querying another domain.
- For named locks, use a ranked prefix (`config`, `metrics`, `instrumentation`,
  `trace`, `region`, `task`, `scheduler`, or `obligation`) unless the lock is
  explicitly documented in `src/sync/lock_ordering.rs` with a stable
  `LOCK_ORDER_REASON_*` allowance.

## Example

An inspector should copy obligation ids while holding the obligation shard, then
drop that lock before querying region state. Acquiring a lower-ranked config
lock while a task-rank lock is still held panics with `[ASUP-E205]`.

With `lock-metrics` enabled, constructing
`ContendedMutex::new("another_unknown", value)` also panics with
`[ASUP-E205] ... reason=denied-unknown-lock-rank` because the name has no rank
and no documented allowance.

## Related

- `ASUP-E101`
- `ASUP-E402`
