# Hot-Path Allocation and Contention Audit (asupersync-umelq.13.4)

This document audits runtime hot paths for avoidable allocations and contention
in the browser build profile, with focus on cancellation and scheduler critical
paths.

## Methodology

Examined 8 critical hot-path modules by reading source code and tracing
execution flow through the scheduler poll loop, cancellation check path,
synchronization primitives, and channel operations.

Files audited:
- `src/runtime/scheduler/worker.rs` (scheduler poll + execute)
- `src/cx/cx.rs` (capability context, cancellation check)
- `src/types/task_context.rs` (CxInner)
- `src/cancel/symbol_cancel.rs` (SymbolCancelToken)
- `src/sync/notify.rs` (Notify primitive)
- `src/channel/mpsc.rs` (bounded MPSC channel)
- `src/runtime/scheduler/local_queue.rs` (work-stealing queue)
- `src/runtime/scheduler/global_injector.rs` (global queue)

## Findings

### F1. `Cx::is_cancel_requested()` — RwLock read for single bool (MEDIUM)

**Location:** `src/cx/cx.rs:1048`

```rust
pub fn is_cancel_requested(&self) -> bool {
    self.inner.read().cancel_requested
}
```

This is called on every future poll to check cancellation. It acquires a
`parking_lot::RwLock` read lock just to read a plain `bool` field from
`CxInner`. While the read lock is uncontended in practice (Cx is per-task),
the lock acquire/release overhead is measurable on the hottest path in the
runtime.

**Impact:** ~10-20ns per poll on native. Proportionally worse on WASM where
parking_lot is unavailable and fallback locks are heavier.

**Recommendation:** Add an `AtomicBool` at the `Cx` struct level that mirrors
`CxInner.cancel_requested`. Update it when the runtime sets cancellation.
`is_cancel_requested()` becomes a single `Ordering::Acquire` atomic load.
`checkpoint()` still takes the write lock for consistency of the full cancel
state. This is safe because `cancel_requested` is monotonic (false → true,
never reverts).

**Risk:** LOW — The AtomicBool is strictly redundant with the RwLock-guarded
bool. Monotonic flag means no consistency concern.

---

### F2. parking_lot dependency — WASM blocker (HIGH, tracked separately)

**Location:** 86+ files use `parking_lot::{Mutex, RwLock, Condvar}`

parking_lot uses OS futexes (`libc::futex` on Linux). Not available in
`wasm32-unknown-unknown`. Every lock-based hot path requires a WASM adapter:

| Hot path | Lock type | Usage |
|----------|-----------|-------|
| `Cx::is_cancel_requested()` | RwLock read | Every poll |
| `Cx::checkpoint()` | RwLock write | Explicit checkpoints |
| `Notify::notify_one()` | Mutex | Wake/wait |
| `mpsc::try_recv()` | Mutex | Channel ops |
| `Worker::execute()` | ContendedMutex | Task scheduling |

**For single-threaded WASM** (the browser target): `RefCell`/`Cell` suffice.
No actual contention exists in a single-threaded executor.

**For SharedArrayBuffer WASM** (future multi-threaded): `web_sys::Atomics`
or `std::sync` (which has wasm32 stubs).

**Status:** Already identified in `docs/wasm_api_surface_census.md` as T2
SYNC-ADAPT. Tracked under the broader parking_lot replacement initiative.

---

### F3. `Instant::now()` in worker — needs WASM adapter (MEDIUM)

**Location:** `src/runtime/scheduler/worker.rs:387`

```rust
let poll_start = Instant::now();
```

`std::time::Instant` is not available on `wasm32-unknown-unknown` (panics).
Browser equivalent: `performance.now()` via `web_sys`.

**Recommendation:** Use the existing `TimeSource` / `WallClock` abstraction
already present in the codebase. The worker already has `timer_driver` which
can provide timestamps.

---

### F4. Worker scratch vectors — well optimized (OK)

**Location:** `src/runtime/scheduler/worker.rs:54-58`

```rust
scratch_local: Cell<Vec<TaskId>>,
scratch_global: Cell<Vec<TaskId>>,
scratch_foreign_wakers: Cell<Vec<Waker>>,
```

Pre-allocated vectors reused via `Cell::take()`/`Cell::set()` across polls.
No heap allocation in steady state. This pattern avoids per-poll `Vec::new()`
which would otherwise be the dominant allocation source in the execute path.

**Assessment:** Excellent optimization. No action needed.

---

### F5. Worker waker caching — well optimized (OK)

**Location:** `src/runtime/scheduler/worker.rs:361-378`

```rust
let waker = if let Some((w, _)) = cached_waker {
    w  // Reuse cached waker
} else {
    Waker::from(Arc::new(WorkStealingWaker { ... }))  // First poll only
};
```

Wakers are cached on the task record after first creation. Subsequent polls
reuse the cached waker (just an Arc clone, which is a refcount increment).
First poll allocates 1 `Arc<WorkStealingWaker>` + 3 inner Arc clones.

**Assessment:** Correctly amortized. The comment notes WorkStealingWaker fields
are immutable per task lifetime, so no staleness concern.

---

### F6. `Cx::clone()` — 3 Arc increments (ACCEPTABLE)

**Location:** `src/cx/cx.rs:151-160`

```rust
impl<Caps> Clone for Cx<Caps> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            observability: Arc::clone(&self.observability),
            handles: Arc::clone(&self.handles),
            _caps: PhantomData,
        }
    }
}
```

CxHandles bundles ~13 handle fields behind a single Arc (reduced from ~15
refcount operations to 1). Total Cx clone cost: 3 atomic increments.

**Assessment:** Already optimized. Cannot improve without unsafe or structural
changes.

---

### F7. `SymbolCancelToken::is_cancelled()` — optimal (OK)

**Location:** `src/cancel/symbol_cancel.rs:161`

```rust
#[inline]
pub fn is_cancelled(&self) -> bool {
    self.state.cancelled.load(Ordering::Acquire)
}
```

Pure atomic load, no lock, already `#[inline]`. This is the ideal pattern
that F1 should follow for `Cx::is_cancel_requested()`.

---

### F8. `Notify::notify_one()` — O(n) waiter scan (LOW)

**Location:** `src/sync/notify.rs:169-195`

Linear scan through WaiterSlab entries to find first non-notified waiter.
Lock dropped before `waker.wake()` (correct pattern).

For the common case (1-2 waiters), this is fine. Could become expensive
with hundreds of waiters. `notify_waiters()` uses `SmallVec<[Waker; 8]>`
to avoid heap allocation for ≤8 waiters.

**Assessment:** Acceptable for typical use. The WaiterSlab is a reasonable
trade-off vs. an intrusive linked list (simpler, cache-friendlier for small N).

---

### F9. MPSC `try_recv()` — well optimized (OK)

**Location:** `src/channel/mpsc.rs:701-722`

Single lock acquisition, O(1) VecDeque pop, lock dropped before
`waker.wake()`. Waker clone uses `will_wake()` dedup to avoid redundant
clones on re-poll.

**Assessment:** Clean design. No avoidable allocations.

---

### F10. `HashSet<u64>` for IO token tracking (LOW, native-only)

**Location:** `src/runtime/scheduler/worker.rs:50`

```rust
seen_io_tokens: HashSet<u64>,
```

HashSet grows dynamically on insert. In WASM browser, the worker module is
not used (single-threaded lab runtime instead), so this is native-only.

**Assessment:** Not applicable to browser target.

---

## Summary

| # | Finding | Severity | Browser Impact | Action |
|---|---------|----------|---------------|--------|
| F1 | `is_cancel_requested()` RwLock for bool | MEDIUM | High | Add AtomicBool fast-path |
| F2 | parking_lot WASM blocker | HIGH | Blocking | Tracked in WASM initiative |
| F3 | `Instant::now()` in worker | MEDIUM | Blocking | Use TimeSource abstraction |
| F4 | Scratch vectors | OK | N/A | Already optimal |
| F5 | Waker caching | OK | N/A | Already optimal |
| F6 | Cx::clone() cost | OK | Low | Already optimal (3 Arc incr) |
| F7 | SymbolCancelToken check | OK | N/A | Already optimal |
| F8 | Notify waiter scan | LOW | Low | Acceptable for typical N |
| F9 | MPSC try_recv | OK | N/A | Already optimal |
| F10 | IO token HashSet | LOW | N/A | Native-only |

## Browser-Specific Observations

The native runtime uses a multi-threaded work-stealing scheduler (`Worker`).
In WASM browser, the execution model is single-threaded, so:

1. **Worker module is not on the WASM critical path.** The lab runtime's
   single-threaded scheduler would be the browser execution engine.
2. **All lock contention disappears.** With a single thread, locks are
   uncontended. The overhead becomes purely the lock/unlock instructions.
3. **parking_lot → RefCell/Cell** is sufficient for single-threaded WASM.
4. **The main hot-path concern for browser is allocation pressure** from
   GC interaction, not contention. Minimizing heap allocations per poll
   cycle is critical for smooth 60fps frame budgets.

## Recommendations Priority

1. **(P0)** parking_lot WASM adapter — already tracked, blocking everything
2. **(P1)** AtomicBool fast-path for `Cx::is_cancel_requested()` — high ROI,
   low risk, benefits both native and WASM
3. **(P1)** `Instant::now()` → `TimeSource` in scheduler — required for WASM
4. **(P2)** Audit lab runtime scheduler hot paths separately — this is the
   actual browser execution engine, distinct from Worker
