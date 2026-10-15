# Channel and Sync Primitive Internals

## Table of Contents

- [Two-Phase Channel Pattern](#two-phase-channel-pattern)
- [MPSC Channel](#mpsc-channel)
- [Oneshot Channel](#oneshot-channel)
- [Broadcast Channel](#broadcast-channel)
- [Watch Channel](#watch-channel)
- [Session Channel](#session-channel)
- [Sync Primitives](#sync-primitives)
- [Cancel Safety Summary](#cancel-safety-summary)
- [Waker Dedup Pattern](#waker-dedup-pattern)
- [Telemetry Snapshots](#telemetry-snapshots)
- [Waiter Registration Race Prevention](#waiter-registration-race-prevention)

## Two-Phase Channel Pattern

The core cancel-safety mechanism on capacity/deferred-send surfaces. Use
reserve/commit where the channel exposes a permit path; do not invent one for
latest-value or immediate-send channels. The waiting shape is primitive-specific:

| Channel | Reservation shape | One-call send |
|---------|-------------------|---------------|
| bounded MPSC | `tx.reserve(&cx).await` (async capacity wait) | `tx.send(&cx, value).await` |
| oneshot | `tx.reserve(&cx)?` (synchronous; consumes sender) | `tx.send(&cx, value)` |
| broadcast | `tx.reserve(&cx)?` (synchronous ring-slot reservation) | `tx.send(&cx, value)` |

The common asynchronous example below is specifically bounded MPSC:

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
For a synchronous boundary that has no `Cx`, `tx.send_blocking(value)` commits
immediately and can return only `Disconnected`, never `Cancelled`; it does not
drive the runtime or wait for a receiver poll.

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
tx.send_modify(|v| { /* serialized read-modify-write */ })?;

rx.changed(&cx).await?;          // wait for change
let snapshot = rx.borrow_and_clone(); // does not mark seen
let current = rx.borrow_and_update_clone(); // clones and marks seen
```

`WatchWaiter` uses `Arc<AtomicBool>` for waker dedup. `send_modify` invokes the
caller closure outside the value `RwLock`, so readers are not blocked by the
closure, but it retains the private writer-serialization lock across
clone/closure/writeback. Do not recursively call `send` or `send_modify` on the
same channel from that closure.

## Session Channel

Source: `src/channel/session.rs`

Typed RPC with reply obligation. Reply is a linear resource.

Tracked wrappers (`tracked_channel()`, `tracked_oneshot()`) thread the
capability context and return proofs: `TrackedSender::try_reserve(&cx)` yields
a `TrackedPermit`, and `TrackedPermit::send(value)` /
`TrackedPermit::try_send(value)` return
`Result<CommittedProof<SendPermit>, SendError<T>>`. This capability-threaded,
proof-returning API first shipped in v0.3.10 and was re-anchored as the public
contract in v0.4.0.

## Sync Primitives

Waiter teardown is cancel-safe and deterministic under the lab runtime. Only
operations whose signatures accept `&Cx` are intrinsically context-cancel-aware;
drop-cancel-safe futures such as `Notify::notified()` do not themselves observe
`Cx` cancellation.

### Mutex

Source: `src/sync/mutex.rs`

```rust
let mutex = Mutex::new(42);
let mut guard = mutex.lock(&cx).await?;  // takes &Cx, returns Result
*guard += 1;
// guard drop releases lock
```

- FIFO-fair and cancel-safe
- Two-phase: Phase 1 (wait for availability) is cancel-safe, Phase 2 (acquire) cannot fail
- Slab-backed waiter chain gives O(1) FIFO registration cleanup and waker update
- Uses `parking_lot::Mutex` internally for waiter state
- Poison on panic

`MutexGuard<'_, T>` borrows the mutex and is intentionally `!Send`. Choose the
guard shape from the task-placement contract:

- movable worker task: put the mutex in `Arc` and use
  `OwnedMutexGuard::lock(arc, &cx).await`, which is `Send`/`Sync` when `T` is;
- genuinely thread-local state: acquire the borrowed guard inside a future
  spawned through `Cx::spawn_local` on an active owning scheduler worker.

An owned guard solves the migration bound; it does not by itself prove abort
delivery. Cancellation tests must still prove the task parked, then assert the
exact nested result and waiter cleanup.

### RwLock

Source: `src/sync/rwlock.rs`

```rust
let rw = RwLock::new(data);
let read = rw.read(&cx).await?;   // shared access
let write = rw.write(&cx).await?; // exclusive access
```

Writer-preference with reader batching.

Unlike borrowed `MutexGuard`, the borrowed RwLock guards have explicit `Send`
implementations when `T` satisfies their bounds (`Send + Sync` for read,
`Send` for write). Put the lock in an `Arc` and use
`OwnedRwLockReadGuard::read(arc, &cx).await` or
`OwnedRwLockWriteGuard::write(arc, &cx).await` when the task must own the lock
without borrowing it. The corresponding `try_read` / `try_write` constructors
do not wait.

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
notify.wait_until(|| condition()).await; // condition-check/register loop
notify.notify_one();           // wake one waiter
notify.notify_waiters();       // wake all waiters
```

`Notified` and `wait_until` have no `&Cx` input and return `()`. `wait_until`
closes the condition-check/waiter-registration race by rechecking a notification
generation; it does not add context cancellation. Dropping either wait future
unregisters safely, but an in-scope `Cx` cancellation does not by itself wake it
or produce a typed cancellation result. Use a `&Cx`-aware wait/combinator, or an
explicit cancellation wake plus checkpoint, when acknowledgement is part of
the protocol.

### OnceCell

Source: `src/sync/once_cell.rs`

```rust
let cell = OnceCell::new();
let val = cell.get_or_init(|| async { compute().await }).await;
```

Takes an `FnOnce() -> Future` closure (not a bare future); `get_or_try_init`
and `get_or_init_blocking` also exist. Dropping a cancelled initialization
future leaves the cell uninitialized and lets a later caller retry. That async
initializer does not accept `&Cx`; use `cell.wait(&cx).await` when waiting for
some other initializer must return typed `OnceCellError::Cancelled` on context
cancellation.

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
| MPSC send | asynchronous `reserve(&cx).await` | `permit.send()` |
| Oneshot send | synchronous `reserve(&cx)?` | `permit.send()` |
| Broadcast send | synchronous `reserve(&cx)?` | `permit.send()` |
| Mutex lock | waiting for lock | guard held |
| RwLock read/write | waiting in the reader/writer queue | read/write guard held |
| Semaphore acquire | waiting for permits | permit held |
| Barrier wait | waiting for peers | post-barrier |
| OnceCell init | initialization future before publication | initialized value published |

v0.4.0 hardened this layer: waiter-ID wraparound prevented, completed MPSC
reserve repolls rejected, interrupted semaphore acquisitions restored, RwLock
queue order preserved, OnceCell waiter state linearized, and mutex rank
released before wakeup (see CHANGELOG v0.4.0).

## Waker Dedup Pattern

The exact waiter representation is primitive-specific. Common patterns include:

- `Waker::will_wake()` checks to skip redundant clones;
- identity/generation tokens that reject stale registrations;
- queued flags such as watch's `Arc<AtomicBool>` waiter marker.

Do not assume one primitive's waiter implementation applies to another; inspect
the current source before relying on an internal shape.

## Telemetry Snapshots

Opt-in redacted `telemetry_snapshot(id)` APIs exist on the MPSC, oneshot,
broadcast, watch, and session channel handles. Semaphore, Barrier, and OnceCell
expose sync-primitive snapshots. These are observational snapshots, not a
synchronization or delivery guarantee.

## Waiter Registration Race Prevention

Waiters must couple the condition check with registration or recheck after
registration. Bounded MPSC reserve loops recheck cancellation, disconnection,
FIFO position, and capacity around waker installation; `Notify::wait_until`
captures a notification generation before evaluating its predicate. Preserve
these patterns when changing waiter storage—the first poll is part of the
protocol, not boilerplate.
