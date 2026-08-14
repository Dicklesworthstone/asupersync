# Channel and Sync Primitive Internals

## Two-Phase Channel Pattern

The core cancel-safety mechanism on capacity/deferred-send surfaces. Use
reserve/commit where the channel exposes a permit path; do not invent one for
latest-value or immediate-send channels:

```rust
// Phase 1: Reserve (cancel-safe, nothing committed)
let permit = tx.reserve(&cx).await?;
// Phase 2: Commit (linear, must happen or abort)
permit.send(message);
```

Dropping a permit aborts cleanly. Message never partially sent.

## MPSC Channel

Source: `src/channel/mpsc.rs`

Multi-producer, single-consumer with two-phase send.

```rust
let (tx, mut rx) = mpsc::channel::<T>(capacity);

// Send side (cancel-safe)
let permit = tx.reserve(&cx).await?;  // wait for capacity
let sent = permit.send(value);         // Outcome<(), SendError<T>>

// Receive side
match rx.recv(&cx).await {
    Ok(value) => { /* got value */ }
    Err(RecvError::Disconnected) => { /* all senders dropped */ }
    Err(RecvError::Cancelled) => { /* receive was cancelled */ }
    Err(RecvError::Empty) => { /* try_recv only */ }
}
```

- Send-side waiters live in a `TokenSlab` of registered wakers with
  `Waker::will_wake` dedup
- Bounded capacity with backpressure
- One-call sugar exists: `tx.send(&cx, value).await` (reserve + commit),
  `try_send()` for non-blocking attempts, `send_evict_oldest()` for
  latest-wins overwrite
- `rx.recv_many(&cx, &mut buf, limit).await` batches drain loops
- `unbounded_channel()` / `unbounded()` give a synchronous, never-waiting
  send path (caller owns memory-pressure policy)
- `SendError` variants are `Disconnected(T)`, `Cancelled(T)`, and `Full(T)`

## Oneshot Channel

Source: `src/channel/oneshot.rs`

Single send, single receive with two-phase send.

```rust
let (tx, mut rx) = oneshot::channel::<T>();
let permit = tx.reserve(&cx)?;   // synchronous; consumes the sender
permit.send(value);
let result = rx.recv(&cx).await?;
```

One-call sugar: `tx.send(&cx, value)` (consumes sender, reserves, commits).

## Broadcast Channel

Source: `src/channel/broadcast.rs`

Fan-out to multiple subscribers with waiter cleanup on drop. Its reserve path is
synchronous because it reserves a slot in the ring without awaiting capacity.

```rust
let (tx, _) = broadcast::channel::<T>(capacity);
let mut rx1 = tx.subscribe();
let mut rx2 = tx.subscribe();

let permit = tx.reserve(&cx)?;
permit.send(value);              // returns receiver count (usize)

// One-call sugar: tx.send(&cx, msg) -> Result<usize, SendError<T>>
// Lagging receivers get RecvError::Lagged(n)
```

## Watch Channel

Source: `src/channel/watch.rs`

Last-value multicast. Always-current read. `watch::Sender::send(...)` is
immediate; it does not take `Cx` and does not use reserve/commit.

```rust
let (tx, mut rx) = watch::channel(initial_value);
tx.send(new_value)?;             // Result; errs only if sender marked closed
tx.send_modify(|v| { /* read-modify-write under the send lock */ })?;

rx.changed(&cx).await?;          // wait for change
let snapshot = rx.borrow_and_clone(); // does not mark seen
let current = rx.borrow_and_update_clone(); // clones and marks seen
```

`WatchWaiter` uses `Arc<AtomicBool>` for waker dedup.

## Session Channel

Source: `src/channel/session.rs`

Typed RPC with reply obligation. Reply is a linear resource.

Tracked wrappers (`tracked_channel()`, `tracked_oneshot()`) thread the
capability context and return proofs: `TrackedSender::try_reserve(&cx)` yields
a `TrackedPermit`, and `TrackedPermit::send(value)` /
`TrackedPermit::try_send(value)` return `CommittedProof<SendPermit>`. This
capability-threaded, proof-returning API first shipped in v0.3.10 and was
re-anchored as the public contract in v0.4.0.

## Sync Primitives

All primitives are cancel-safe and deterministic under lab runtime.

### Mutex

Source: `src/sync/mutex.rs`

```rust
let mutex = Mutex::new(42);
let mut guard = mutex.lock(&cx).await?;  // takes &Cx, returns Result
*guard += 1;
// guard drop releases lock
```

- Fair, cancel-safe, tracks contention
- Two-phase: Phase 1 (wait for availability) is cancel-safe, Phase 2 (acquire) cannot fail
- Each guard tracked as an obligation
- Uses `parking_lot::Mutex` internally for waiter queue
- Poison on panic

### RwLock

Source: `src/sync/rwlock.rs`

```rust
let rw = RwLock::new(data);
let read = rw.read(&cx).await?;   // shared access
let write = rw.write(&cx).await?; // exclusive access
```

Writer-preference with reader batching.

### Semaphore

Source: `src/sync/semaphore.rs`

```rust
let sem = Semaphore::new(permits);
let permit = sem.acquire(&cx, count).await?;
// permit is an obligation released on drop
```

Counting semaphore with permit-as-obligation model.

### Barrier

Source: `src/sync/barrier.rs`

```rust
let barrier = Barrier::new(n);
let result = barrier.wait(&cx).await?;
if result.is_leader() { /* elected leader */ }
```

N-way synchronization with leader election.

### Notify

Source: `src/sync/notify.rs`

```rust
let notify = Notify::new();
notify.notified().await;       // wait for notification
notify.notify_one();           // wake one waiter
notify.notify_waiters();       // wake all waiters
```

### OnceLock (OnceCell)

Source: `src/sync/once_cell.rs`

```rust
let cell = OnceCell::new();
let val = cell.get_or_init(|| async { compute().await }).await;
```

Takes an `FnOnce() -> Future` closure (not a bare future); `get_or_try_init`
and `get_or_init_blocking` also exist. Cancel-safe: cancelled init leaves the
cell uninitialized and lets the next caller retry.

### Pool

Source: `src/sync/pool.rs`

Cancel-safe resource pooling with obligation-based return semantics: a
`PooledResource` returns to the pool on drop or explicit
`return_to_pool()`. `GenericPool::new(factory, PoolConfig::default())` is the
easy entry point; no manual `unsafe impl Send` is needed.

### ContendedMutex

Source: `src/sync/contended_mutex.rs`

`std::sync::Mutex` wrapper with synchronous `lock()` (no `Cx`). With the
`lock-metrics` feature it tracks wait/hold time, contention count, and
acquisitions; without it, a zero-cost wrapper.

## Cancel Safety Summary

| Primitive | Cancel-Safe Phase | Linear Phase |
|-----------|------------------|--------------|
| MPSC send | `reserve()` | `permit.send()` |
| Oneshot send | `reserve()` | `permit.send()` |
| Broadcast send | synchronous `reserve()` | `permit.send()` |
| Mutex lock | waiting for lock | guard held |
| Semaphore acquire | waiting for permits | permit held |
| Barrier wait | waiting for peers | post-barrier |

v0.4.0 hardened this layer: waiter-ID wraparound prevented, completed MPSC
reserve repolls rejected, interrupted semaphore acquisitions restored, RwLock
queue order preserved, OnceCell waiter state linearized, and mutex rank
released before wakeup (see CHANGELOG v0.4.0).

## Waker Dedup Pattern

Used across channels and sync primitives:
- `Waker::will_wake()` checks skip redundant clones
- Refresh only when executor context actually changes
- Reduces allocation and contention on wake paths

## Waiter Registration Race Prevention

Sink and transport channels re-check capacity after waiter registration. This closes the lost-wakeup race between capacity check and registration.
