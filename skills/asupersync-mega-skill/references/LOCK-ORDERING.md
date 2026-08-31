# Lock Ordering and Concurrency Discipline

## Table of Contents

- [Canonical Rank Vocabulary](#canonical-rank-vocabulary)
- [ShardedState](#shardedstate)
- [ContendedMutex](#contendedmutex)
- [Channel Waker Dedup](#channel-waker-dedup)
- [Worker Wake Coordination](#worker-wake-coordination)
- [Lost-Wakeup Prevention](#lost-wakeup-prevention)
- [Intrusive Queue Links](#intrusive-queue-links)
- [Atomic Counter Discipline](#atomic-counter-discipline)
- [Steal-Path Locality](#steal-path-locality)
- [Migration to parking_lot](#migration-to-parking_lot)
- [Out-Of-Lock Effect Delivery](#out-of-lock-effect-delivery)
- [Rules](#rules)

## Canonical Rank Vocabulary

The repository's canonical rank vocabulary is:

```
E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations)
```

Acquiring a lower-ranked lock while a higher-ranked lock is held can deadlock.
The enforcement boundary is narrower than the five-symbol vocabulary:

- `ShardGuard` constructors acquire the mechanically represented table locks in
  `B -> A -> C` order.
- `lock_order::before_lock` / `after_lock` debug assertions cover the
  `LockShard::{Regions, Tasks, Obligations}` acquisitions.
- Ranked `ContendedMutex`, async `Mutex`, and `RwLock` paths also use the
  general checks in `src/sync/lock_ordering.rs`.
- E is immutable and requires no lock. D uses its own synchronization and is
  convention/audit checked, not represented by `LockShard`; trace may currently
  be emitted while a table lock is held, so the inventory records D as an
  enforcement gap rather than a proven global order.
- Dedicated contract/audit tests, e.g. `tests/lock_order_inventory_contract.rs`
  and `tests/runtime_no_await_while_holding_lock_audit.rs`, plus a loom lane
  (`tests/scheduler_loom.rs`, feature `loom-tests`)

Mnemonic: "Every Day Brings Another Challenge."

Source: `src/runtime/sharded_state.rs`

## ShardedState

`ShardedState` defines independently locked tables:

| Shard | Label | Contents |
|-------|-------|----------|
| E | Config | Immutable runtime configuration |
| D | Instrumentation | Trace surfaces, metrics |
| B | Regions | Region ownership tree, state transitions |
| A | Tasks | Task table, stored futures, intrusive queue links |
| C | Obligations | Permit/ack/lease lifecycle, leak tracking |

### Why Independent Shards?

Hot-path polling proceeds without serializing every region or obligation mutation. Each shard can be locked independently when only one table is needed.

Lock nature per shard: A/B/C are Arc-shared `ContendedMutex` tables with exact
handle accessors. D is internally synchronized and is not a `LockShard`; E is
read-only config with no lock.

The sharded shape is a public opt-in: `RuntimeBuilder::with_sharded_state(true)`
(default `RuntimeStateShape::Unified`). The current public runtime route is
hybrid: scheduler dispatch uses shard A, obligation mint/settlement uses shard C
through wrapper-side A-then-C resolution, and region records remain embedded in
the unified `RuntimeState`. Shard B therefore remains dormant as a lifecycle
owner. Do not teach this opt-in as a completed A/B/C cutover. The unified shape
preserves the v0.4.3-compatible default and observable contracts.

### Multi-Shard Operations

Use `ShardGuard` when operating directly on multiple `ShardedState` tables
(debug assertions verify B-before-A-before-C). Named constructors: `tasks_only` (A),
`regions_only` (B), `obligations_only` (C), `for_spawn` (B->A),
`for_obligation` (B->C), `for_obligation_resolve` / `for_cancel` /
`for_task_completed` / `all` (B->A->C).

## ContendedMutex

Source: `src/sync/contended_mutex.rs`

Wrapper around `std::sync::Mutex` (synchronous `lock()`, no `Cx`) with optional contention metrics (feature: `lock-metrics`):
- Wait and hold time tracking (cumulative, max, and retained p95/p999 samples)
- Contention event counting
- Acquisition counting

Use for the A/B/C table locks in `ShardedState`.

## Channel Waker Dedup

Waiter registration paths deduplicate wakeups; the canonical surviving example
is watch's `WatchWaiter` with a shared `queued: Arc<AtomicBool>` flag
(`src/channel/watch.rs`). The mpsc/broadcast waiter internals have been
reworked since (waiter-ID wraparound and stale-waiter fixes in v0.4.0), so
verify the current per-primitive mechanism in `src/channel/` before citing it.

Prevents duplicate wakeups and reduces contention on the wake path.

## Worker Wake Coordination

- Three-state `TaskWakeState` (`Idle`, `Polling`, `Notified`) for centralized
  wake dedup
- Ready/timed scheduling is deduplicated through `wake_state.notify()`; cancel
  promotion still calls it for bookkeeping but deliberately injects even when
  the task was already notified in another lane
- Ordinary wakes during one poll coalesce into one pending-notified bit;
  cancel-lane promotion follows the separate rule above
- `Waker::will_wake` guards skip redundant clones on waiter registration

## Lost-Wakeup Prevention

Multiple strategies used:
- Permit-style `Parker` with queue rechecks after wakeup
- Capacity re-checks after waiter registration (closes capacity-check/registration race)
- Channel close paths wake their relevant registered send/receive waiters

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

## Out-Of-Lock Effect Delivery

Treat this as a rule: never invoke a waker, metrics/tracing hook, or user/observer
callback while a `RuntimeState` or shard lock is held. Such code can re-enter the
runtime, acquire another lock, or panic. Complete authoritative mutation,
cleanup/unlink, quiescence advancement, and guard state under the lock; capture
owned effects; release every lock; then deliver each effect once, with panic
containment where the effect can call foreign code.

This is not yet a completed repository-wide property. The direct completion
observer in `RuntimeState::task_completed` has been split into
`TaskCompletionEffects` / `TaskCompletionObserver` for post-lock dispatch, but
active P0 `asupersync-909482` still tracks the broader boundary: transitive
obligation/region/finalizer callbacks, foreign-waker destruction, bounded panic
payload handling, suppression/gauge accounting, and `panic = "abort"` behavior.
Teach out-of-lock delivery as the required design and review rule, not as a
guarantee already proved for every callback or destructor.

## Rules

1. Follow the E -> D -> B -> A -> C rank vocabulary; for mechanically tracked
   shard locks, acquire B -> A -> C
2. Never hold a shard lock across an await point
3. Use `ContendedMutex` for shard locks (enables metrics)
4. Use `ShardGuard` for multi-table operations over `ShardedState`; wrapper-side
   hybrid operations must preserve their explicit A-then-C order
5. Prefer atomic operations over locks on hot paths
6. Use `Waker::will_wake` to skip redundant clone operations
7. Deliver wakers, instrumentation, and callbacks only after releasing runtime locks
