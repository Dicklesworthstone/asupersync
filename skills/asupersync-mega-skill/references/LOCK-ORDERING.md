# Lock Ordering and Concurrency Discipline

## Canonical Lock Order

When acquiring multiple locks, the strict order is:

```
E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations)
```

Violating this order causes deadlocks. This is enforced by:

- Named `ShardGuard` constructors that always acquire in canonical order
- `lock_order::before_lock` / `after_lock` debug assertions on every shard
  acquisition (`LockShard` labels)
- Dedicated contract/audit tests, e.g. `tests/lock_order_inventory_contract.rs`
  and `tests/runtime_no_await_while_holding_lock_audit.rs`, plus a loom lane
  (`tests/scheduler_loom.rs`, feature `loom-tests`)

Mnemonic: "Every Day Brings Another Challenge."

Source: `src/runtime/sharded_state.rs`

## ShardedState

Runtime state split into independently locked shards:

| Shard | Label | Contents |
|-------|-------|----------|
| E | Config | Immutable runtime configuration |
| D | Instrumentation | Trace surfaces, metrics |
| B | Regions | Region ownership tree, state transitions |
| A | Tasks | Task table, stored futures, intrusive queue links |
| C | Obligations | Permit/ack/lease lifecycle, leak tracking |

### Why Independent Shards?

Hot-path polling proceeds without serializing every region or obligation mutation. Each shard can be locked independently when only one table is needed.

Lock nature per shard: A/B/C are Arc-shared `ContendedMutex` tables (aliased
to scheduler/lifecycle seams via `task_shard_handle` / `region_shard_handle` /
`obligation_shard_handle`); D is internally synchronized (short-held trace
mutex, acquired after shard locks by convention — it is not a `LockShard`);
E is read-only config with no lock.

The sharded shape is a public opt-in: `RuntimeBuilder::with_sharded_state(true)`
(default `RuntimeStateShape::Unified`). On sharded builds, obligation
resolution targets shard C via wrapper-side resolution in
`src/runtime/state.rs` (shard A then shard C, buffered effect sinks,
post-release drain).

### Multi-Shard Operations

Use `ShardGuard` to acquire multiple shards in canonical order at runtime
(debug assertions verify the order). Named constructors: `tasks_only` (A),
`regions_only` (B), `obligations_only` (C), `for_spawn` (B->A),
`for_obligation` (B->C), `for_obligation_resolve` / `for_cancel` /
`for_task_completed` / `all` (B->A->C).

## ContendedMutex

Source: `src/sync/contended_mutex.rs`

Wrapper around `parking_lot::Mutex` with optional contention metrics (feature: `lock-metrics`):
- Wait time tracking (cumulative, max, and retained percentile samples)
- Hold time tracking (cumulative and max)
- Contention event counting

Use for all shard locks in `ShardedState`.

## Channel Waker Dedup

Waiter registration paths deduplicate wakeups; the canonical surviving example
is watch's `WatchWaiter` with a shared `queued: Arc<AtomicBool>` flag
(`src/channel/watch.rs`). The mpsc/broadcast waiter internals have been
reworked since (waiter-ID wraparound and stale-waiter fixes in v0.4.0), so
verify the current per-primitive mechanism in `src/channel/` before citing it.

Prevents duplicate wakeups and reduces contention on the wake path.

## Worker Wake Coordination

- `Idle -> Polling -> Notified` state machine for centralized wake dedup
- Scheduling paths route through `wake_state.notify()`
- Wakes during poll are coalesced (no double-enqueueing)
- `Waker::will_wake` guards skip redundant clones on waiter registration

## Lost-Wakeup Prevention

Multiple strategies used:
- Permit-style `Parker` with queue rechecks after wakeup
- Capacity re-checks after waiter registration (closes capacity-check/registration race)
- Both send and receive waiters woken on channel close

## Intrusive Queue Links

Source: `src/runtime/scheduler/intrusive.rs`

- Links stored directly in `TaskRecord`
- Queue-tag membership checks (O(1) pop without allocation)
- Owner pop and thief steal stay O(1)

## Atomic Counter Discipline

Source: `src/runtime/scheduler/global_injector.rs`

- Timed counters incremented before heap insert
- Saturating decrements on pop
- Cached earliest-deadline fast path
- Workers skip timed-lane mutex when no deadline work exists

## Steal-Path Locality

Source: `src/runtime/scheduler/local_queue.rs`

- Local queues track pinned local tasks
- When none present, stealers take no-branch non-local path
- When locals exist, skipped/restored with `SmallVec` (allocation-free common path)

## Migration to parking_lot

Runtime, scheduler, I/O, lab, networking, and transport internals all use `parking_lot` primitives where it improves lock-path cost. This was a deliberate, measured migration.

## Rules

1. Always acquire in canonical order: E -> D -> B -> A -> C
2. Never hold a shard lock across an await point
3. Use `ContendedMutex` for shard locks (enables metrics)
4. Use `ShardGuard` for multi-shard operations
5. Prefer atomic operations over locks on hot paths
6. Use `Waker::will_wake` to skip redundant clone operations
