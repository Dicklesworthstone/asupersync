# Loser-Drain Correctness Audit for Race/Join Combinators (asupersync-umelq.6.2)

This document audits the loser-drain invariant across all race and join
combinators to verify correctness in the WASM browser single-threaded context.

## Invariant

**Loser-drain**: When a race combinator picks a winner, all losers MUST be
cancelled AND awaited to terminal state before the winner is returned. This
ensures structured concurrency — no detached work outlives the scope.

## Methodology

1. Traced cancellation chain from Select through JoinFuture::drop to abort
2. Verified each race variant drains losers explicitly
3. Identified non-draining APIs and their documentation contracts
4. Assessed correctness under single-threaded WASM executor model

Files audited:
- `src/cx/scope.rs` (Scope::race, race_all, join_all)
- `src/runtime/task_handle.rs` (JoinFuture, abort_with_reason)
- `src/combinator/select.rs` (Select primitive)
- `src/combinator/race.rs` (value types, Cancel trait)
- `src/cx/cx.rs` (Cx::race, Cx::race_timeout)

## Core Mechanism: JoinFuture::drop

`src/runtime/task_handle.rs:285`

```rust
impl Drop for JoinFuture<'_, T> {
    fn drop(&mut self) {
        if !self.completed && !self.inner.receiver_finished() {
            self.inner.abort_with_reason(self.drop_reason);
        }
    }
}
```

When a `JoinFuture` is dropped before completion:
1. Checks `!self.completed` (not yet yielded a result)
2. Checks `!inner.receiver_finished()` (receiver still active)
3. Calls `abort_with_reason()` which sets `cancel_requested` on the task

This is the **trigger** for cancellation but NOT the drain. The drain
requires an explicit `join(cx).await` after abort.

## Combinator Analysis

### Scope::race() — CORRECT (drains losers)

`src/cx/scope.rs:976`

```
1. Spawns both futures as tasks via scope.spawn()
2. Creates JoinFutures with drop_reason = DropReason::RaceLoser
3. Wraps in Select combinator (biased left-first polling)
4. Select returns winner → loser JoinFuture DROPPED
5. JoinFuture::drop triggers abort_with_reason(RaceLoser) on loser
6. Explicit: loser_handle.join(cx).await drains the loser
7. If loser panicked, panic is propagated
```

The drain step (6) is critical — it awaits the cancelled task until it
reaches terminal state. The task observes cancellation via `checkpoint()`
and completes cooperatively.

**Verdict: SAFE. Full drain with panic propagation.**

### Scope::race_all() — CORRECT (drains all losers)

`src/cx/scope.rs:1146`

```
1. Spawns all futures as tasks
2. Creates JoinFutures wrapped in poll_fn
3. poll_fn polls each future; first Ready wins
4. drop(futures) — triggers JoinFuture::drop on all pending losers
   (completed futures have self.completed = true, skip abort)
5. Explicit loop: for each pending handle, abort_with_reason + join(cx).await
6. Panics from any loser are propagated
```

Step 4 triggers abort on pending tasks. Step 5 explicitly drains each one.
Completed losers (those that finished but weren't the first) are joined
without abort since their JoinFuture already set `completed = true`.

**Verdict: SAFE. All losers drained, panics propagated.**

### Scope::join_all() — CORRECT (no losers)

`src/cx/scope.rs:1245`

Sequentially joins all handles. No cancellation needed — all tasks run to
completion. If any panics, all remaining are aborted and drained.

**Verdict: SAFE. No loser-drain concern.**

### Cx::race() — DOCUMENTED NON-DRAINING

`src/cx/cx.rs:1993`

```rust
// WARNING: This drops losers but does NOT drain them.
// Use Scope::race() for the drain guarantee.
```

Uses `SelectAll` internally. Losers are dropped (triggering abort via
JoinFuture::drop) but NOT awaited. The cancelled tasks will complete
asynchronously and be collected by the runtime's task reaper.

This is intentional — `Cx::race()` is the "fire and forget cancellation"
variant for cases where the caller doesn't need drain guarantees.

**Verdict: BY DESIGN. Documented contract. Not a bug.**

### Cx::race_timeout() — DOCUMENTED NON-DRAINING

`src/cx/cx.rs:2027`

Same behavior as `Cx::race()` — drops losers without drain. Documentation
at lines 2019-2021 explicitly states the non-draining contract.

**Verdict: BY DESIGN. Documented contract. Not a bug.**

### Select primitive — LOW-LEVEL, CALLER MUST DRAIN

`src/combinator/select.rs:72`

```rust
// "Dropping a loser is NOT the same as draining it."
```

Select is the raw building block. It picks a winner and returns the loser
as the "other" value. The caller is responsible for draining. Both
`Scope::race()` and `Scope::race_all()` correctly handle this.

**Verdict: SAFE. Contract correctly documented and upheld by callers.**

### Race value types — NO CONCURRENCY CONCERN

`src/combinator/race.rs`

Pure value types (`Race`, `RaceAll`, `Race2`-`Race16`) with `PhantomData`.
Outcome interpretation functions (`race2_outcomes`, `race_all_outcomes`)
are pure. `Cancel` trait defines the cancellation protocol interface.

**Verdict: SAFE. Pure types, no execution logic.**

## WASM Browser Single-Threaded Analysis

### Cancellation Delivery

In the single-threaded WASM executor (lab runtime):
1. `abort_with_reason()` sets `cancel_requested = true` on the task
2. The lab runtime reschedules cancelled tasks for one final poll
3. On that poll, `checkpoint()` observes cancellation and returns `Err`
4. The task's future completes cooperatively

This works correctly because:
- The lab runtime's `poll_once()` loop processes all ready tasks
- Cancelled tasks are marked ready and polled
- The drain `join(cx).await` will complete on the next executor tick

### No Starvation Risk

In single-threaded context, the drain `join(cx).await` cannot deadlock:
- The cancelled task is already marked for cancellation
- The executor will poll it on the next tick
- The task will observe cancellation at its next checkpoint
- Tasks that never checkpoint are a general liveness concern (not specific
  to WASM or race combinators)

### Ordering Guarantee

`Scope::race()` drain order:
1. Winner result captured
2. Loser abort triggered (synchronous flag set)
3. Loser join awaited (yields to executor, loser runs to completion)
4. Winner returned

This is deterministic in single-threaded execution — no interleaving
concerns.

## Summary

| Combinator | Drains Losers | WASM Safe | Notes |
|------------|--------------|-----------|-------|
| `Scope::race()` | YES | YES | Full drain + panic propagation |
| `Scope::race_all()` | YES | YES | All losers drained |
| `Scope::join_all()` | N/A | YES | No losers |
| `Cx::race()` | NO | YES* | Documented non-draining |
| `Cx::race_timeout()` | NO | YES* | Documented non-draining |
| `Select` | Caller's job | YES | Low-level primitive |

*`Cx::race()` and `Cx::race_timeout()` are safe in the sense that they
don't violate their documented contract. However, they do NOT provide the
structured concurrency drain guarantee. Browser code should prefer
`Scope::race()` for correctness.

## Recommendations

1. **(P2)** Consider adding a `#[cfg(target_arch = "wasm32")]` compile
   warning or lint when `Cx::race()` is used in browser builds, steering
   users toward `Scope::race()` which provides the drain guarantee.

2. **(P3)** Document in the WASM porting guide that `Scope::race()` is the
   preferred race API for browser targets due to the drain guarantee.

**Overall verdict: Loser-drain correctness is fully preserved for all
draining combinators. Non-draining variants are correctly documented.
No bugs found. No remediation required.**
