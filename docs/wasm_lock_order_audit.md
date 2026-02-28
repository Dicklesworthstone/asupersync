# Post-Refactor Lock-Order and Contention Safety Audit (asupersync-umelq.4.5)

This document audits lock acquisition order and sharded-state boundaries after
the RuntimeState split (bd-3xvow) to ensure deadlock freedom guarantees are
preserved in the WASM browser target.

## Methodology

1. Traced all lock acquisition paths through 10 critical modules
2. Verified ShardGuard enforcement covers all multi-shard operations
3. Checked sync primitives for consistent lock → wake ordering
4. Ran existing lock-ordering violation tests (35 pass, 3 should_panic)
5. Ran pool dual-lock tests (51 pass)
6. Verified clippy clean (0 warnings/errors)

## Lock Ordering Invariant (Preserved)

The canonical lock ordering from bd-3gyn2 remains intact:

```
E(Config) → D(Instrumentation) → B(Regions) → A(Tasks) → C(Obligations)
```

Mnemonic: **"Every Day Brings Another Challenge"**

### Post-Refactor Shard Layout

| Shard | Type | Lock | Refactor Status |
|-------|------|------|-----------------|
| E (Config) | `Arc<ShardedConfig>` | Lock-free (read-only) | Unchanged |
| D (Instrumentation) | `TraceBufferHandle`, atomics | Lock-free | Unchanged |
| B (Regions) | `ContendedMutex<RegionTable>` | Independent mutex | Split from RuntimeState |
| A (Tasks) | `ContendedMutex<TaskTable>` | Independent mutex | Split from RuntimeState |
| C (Obligations) | `ContendedMutex<ObligationTable>` | Independent mutex | Split from RuntimeState |

The bd-3xvow refactor split the monolithic `RuntimeState` into three
independent `ContendedMutex` shards. The `ShardGuard` API enforces
correct multi-shard acquisition order.

## ShardGuard Verification

All ShardGuard constructors maintain B → A → C ordering:

| Constructor | Locks | Order | Purpose |
|-------------|-------|-------|---------|
| `tasks_only()` | A | - | Hot-path task poll/push/pop |
| `regions_only()` | B | - | Region queries |
| `obligations_only()` | C | - | Obligation queries |
| `for_spawn()` | B, A | B→A | Task creation |
| `for_obligation()` | B, C | B→C | Obligation creation |
| `for_task_completed()` | B, A, C | B→A→C | Task completion + region advance |
| `for_cancel()` | B, A, C | B→A→C | Cancel propagation |
| `for_obligation_resolve()` | B, A, C | B→A→C | Obligation commit/abort |
| `all()` | B, A, C | B→A→C | Full snapshot/quiescence |

`ShardGuard::drop()` releases in reverse order (C, A, B). CORRECT.

Debug-only thread-local enforcement (`lock_order` module) catches violations
at runtime. Three `#[should_panic]` tests verify:
- A → B (Tasks before Regions): PANICS ✓
- C → A (Obligations before Tasks): PANICS ✓
- C → B (Obligations before Regions): PANICS ✓

## Sync Primitive Lock Safety

### Notify (`src/sync/notify.rs`)

- Single `parking_lot::Mutex<WaiterSlab>` + `AtomicU64 generation` + `AtomicUsize stored_notifications`
- `notify_one()`: Lock held while incrementing `stored_notifications` — CORRECT (prevents lost wakeup race)
- `notify_waiters()`: Wakers collected in `SmallVec<[Waker; 8]>`, lock dropped before `.wake()` — CORRECT
- `pass_baton()`: Lock held while scanning, dropped before `.wake()` — CORRECT
- `Notified::poll()`: Separate lock sections for init vs waiting — no nested acquisition

**Verdict: SAFE. Consistent lock → collect → drop → wake pattern.**

### Semaphore (`src/sync/semaphore.rs`)

- Single `parking_lot::Mutex` guarding permits + waiter queue
- Cascading wakeup: lock acquired, next waker extracted, lock dropped, then `.wake()` — CORRECT
- No nested lock acquisitions

**Verdict: SAFE.**

### RwLock (`src/sync/rwlock.rs`)

- Single `parking_lot::Mutex<RwLockState>` guarding reader count + writer queue
- `release_reader()`: Lock, extract writer waker, drop lock, wake — CORRECT
- `release_writer()`: Lock, collect all reader wakers in Vec, drop lock, wake — CORRECT
- `ReadWaiter::poll()` / `WriteWaiter::poll()`: Single lock per critical section

**Verdict: SAFE.**

### Pool (`src/sync/pool.rs`)

- Dual lock: `return_rx: parking_lot::Mutex<Receiver>` + `state: parking_lot::Mutex<PoolState>`
- `process_returns()`: Acquires `return_rx` first, then `state` within loop body, drops `state` before next iteration
- Order is always `return_rx → state`, never reversed
- Wakers collected in `SmallVec<[Waker; 4]>`, all `.wake()` calls after both locks released

**Verdict: SAFE. Consistent ordering, no inversion possible.**

### MPSC Channel (`src/channel/mpsc.rs`)

- Single `parking_lot::Mutex<Inner>` guarding queue + wakers
- `try_recv()`: Lock, pop, extract next sender waker, drop lock, wake — CORRECT
- `Reserve::poll()`: Lock, register/check capacity, drop lock, wake — CORRECT
- `SendPermit::send()`: Lock, push, extract recv waker, drop lock, wake — CORRECT
- `Recv::drop()`: Clears recv_waker under lock — no deadlock risk

**Verdict: SAFE.**

### Broadcast Channel (`src/channel/broadcast.rs`)

- Single `parking_lot::Mutex` guarding Arena + subscribers
- `send()`: Lock, broadcast to all, collect wakers, drop lock, wake — CORRECT
- Single-lock pattern throughout — no ordering concern

**Verdict: SAFE.**

## Cx Lock Interaction

`Cx` wraps `Arc<parking_lot::RwLock<CxInner>>` plus `Arc<parking_lot::RwLock<ObservabilityState>>`.

- `is_cancel_requested()`: Read lock on `inner` only — no interaction with other locks
- `checkpoint()`: Write lock on `inner` only — no interaction with other locks
- Worker sets cancel state via write lock — outside scheduler lock scope (ShardGuard dropped first)
- **No cross-lock interaction between Cx and ShardGuard** — the Cx lock is per-task and
  acquired after the task has been extracted from the scheduler

**Verdict: SAFE. Cx locks operate in a separate domain from the shard locks.**

## WASM Browser Implications

### Single-Threaded Context

In wasm32-unknown-unknown with a single-threaded executor:
- All lock contention disappears
- Lock ordering violations are impossible (single thread)
- The `ContendedMutex` metrics (`lock-metrics` feature) are unnecessary
- `parking_lot` → `RefCell`/`Cell` replacement is sufficient

### SharedArrayBuffer Context (Future)

If multi-threaded WASM becomes a target:
- The existing lock ordering system transfers directly
- `ShardGuard` + debug enforcement would work with `web_sys::Atomics`
- The thread-local lock ordering check would need a WASM-compatible TLS mechanism

## Stress Test Coverage

The existing test suite provides:

| Module | Tests | Lock Patterns Exercised |
|--------|-------|------------------------|
| `sharded_state` | 35 | All ShardGuard variants, 3 violation tests |
| `pool` | 51 | Dual-lock process_returns, exhaustion/unblock |
| `notify` | ~25 | Lost wakeup, baton passing, generation broadcast |
| `semaphore` | ~20 | Cascading wakeup, concurrent acquire |
| `rwlock` | ~20 | Reader/writer fairness, concurrent access |
| `mpsc` | ~30 | Full/empty, cancel, sender drop |
| `broadcast` | ~27 | Arena dedup, subscriber lifecycle |

No additional stress tests are needed — the existing coverage exercises all
lock interaction patterns including the critical ShardGuard ordering.

## Summary

| Component | Lock Pattern | Status | Action |
|-----------|-------------|--------|--------|
| ShardGuard B→A→C | Ordered multi-shard | SAFE | None |
| Debug enforcement | Thread-local guard | WORKING | Tests pass |
| Notify | Mutex + atomics | SAFE | None |
| Semaphore | Mutex cascade | SAFE | None |
| RwLock | Single mutex | SAFE | None |
| Pool | Dual-lock ordered | SAFE | None |
| MPSC | Single mutex | SAFE | None |
| Broadcast | Single mutex | SAFE | None |
| Cx | Per-task RwLock | SAFE | None (see F1 in hotpath audit) |

**Overall verdict: Deadlock freedom guarantees are fully preserved after
the RuntimeState split. No lock ordering violations detected. All sync
primitives follow the consistent lock → collect → drop → wake pattern.**

**No remediation required.** The lock ordering system from bd-3gyn2 is
robust and the post-refactor shard boundaries maintain the invariant.
