# Acknowledged, bounded work delivery

`asupersync::channel::ack` implements the v4 plan's receive-side acknowledgement
workflow. Use it when cancellation or a worker panic must leave unprocessed work
available to a surviving/replacement worker. Existing channel APIs are unchanged.

## One capacity bound across the full lifecycle

```
free credit -> SendPermit -> ready item -> Delivery -> ack -> free credit
                                ^             |
                                +--- nack/Drop+
```

At every queue transition:

```
ready items + send reservations + unacknowledged deliveries <= capacity
```

Taking an item does not release its credit. With the default unlimited policy,
nack/drop returns the same owned value to the ready tail without allocating
additional ready-buffer capacity or waiting for a producer. Senders and receivers are cloneable; payloads need not be
Clone or Sync. Moving endpoints between threads requires only Send payloads.
Ready items are selected FIFO; retries join the tail. Waiting task admission is
not FIFO, and no performance superiority is claimed for broadcast wakeups.

The receive result is a `Delivery<T>`, rather than an independently movable
`(T, Ack)` pair. It borrows/dereferences to T, so a forgotten acknowledgement can
still recover a non-Clone value. `ack()` consumes the guard, releases capacity,
and returns the acknowledged value to the worker. `nack()` or Drop requeues it
while its delivery allowance remains. Mutations to T remain present on retries;
arbitrary external side effects are not rolled back.

```rust,ignore
use asupersync::{Cx, main};
use asupersync::channel::ack;

#[main]
async fn main(cx: &Cx) {
    let (producer, worker) = ack::channel(8);
    producer.send(cx, String::from("job")).await.unwrap();
    let mut delivery = worker.recv_with_ack(cx).await.unwrap();
    let identity = delivery.sequence();
    delivery.push_str(" / prepared");
    drop(delivery); // interruption before acknowledgment: return the owned value

    let retry = worker.recv_with_ack(cx).await.unwrap();
    assert_eq!(retry.sequence(), identity);
    assert_eq!(retry.attempts(), 2);
    assert_eq!(retry.ack(), "job / prepared");
    producer.close_and_drain(cx).await.unwrap();
}
```

`try_send` and a refused `send` return `SendError<T>` with the unpublished value.
The owning async `send` future owns its argument; dropping it before publication
can destroy that argument. For cancellation-safe retention by the producer,
await `reserve` while keeping the value outside the borrowing wait, then commit
the permit synchronously. Committing an issued permit or acknowledging a delivery
does not use a cancellation-rejecting send/checkpoint after the terminal decision.

## Producer receipts and bounded retries

`try_send_tracked`, `send_tracked`, and `SendPermit::send_tracked` return an owned
`Receipt<T>` after publication, not after processing. Its identity matches the
worker's `Delivery::sequence`. Neither enqueue, receive nor nack acknowledges
work. `Receipt::try_take` reports readiness; `wait(cx)` is cancellation-aware;
`wait_uninterruptible()` has no caller-cancellation shortcut. Both waits borrow
the receipt, so dropping a wait preserves it. Cancelling the observer does not
cancel, reject, retract or duplicate the job. Dropping the receipt itself
relinquishes its eventual result, not the work.

A `Settlement<T>` contains the item's sequence, physical `attempts`, issued
`deliveries`, and one of these dispositions:

| Disposition | Value owner after settlement |
|---|---|
| `Acknowledged` | The worker receives T from `Delivery::ack`; the producer receives metadata only. |
| `Rejected(T)` | The producer regains the possibly mutated payload after explicit worker rejection. |
| `RetryExhausted(T)` | The producer regains the payload after the opted-in delivery allowance is spent. |
| `Abandoned(T)` | The producer regains the payload because no receiver remains to retry it. |

`Delivery::reject()` is available for tracked work. An untracked delivery returns
`Err(original_delivery)` unchanged; no payload is discarded by the refusal. A
caller that ignores and drops this returned guard gets the normal nack behavior.
The receipt's Debug output never requires or displays T's Debug representation.
A closed receipt without a terminal result means unknown or already consumed,
not acknowledgement. These are physical queue dispositions: they do not certify
external side effects, persistent storage, runtime ledger projection or task join.

Existing untracked sends and ordinary tracked sends retain unlimited retries.
Use `*_tracked_with_policy(..., RetryPolicy::limited(nonzero_limit))` to bound
issued deliveries for a particular item. The limit includes the first delivery.
It counts guards actually returned to workers, not quota/admission refusals or
cancellation before handoff. `attempts()` keeps its original physical-attempt
meaning; `deliveries()` provides the separate budget count. Policies and both
counts survive task-to-task handoff. The policy is checked only on nack/Drop:
acknowledging the final allowed delivery succeeds, and a live delivery is never
expired, stolen or timed out.

```rust,ignore
use asupersync::channel::ack::{self, QueueError, RetryPolicy, SettlementOutcome};
use std::num::NonZeroU64;

// Inside an existing runtime-owned async task holding &Cx:
let (producer, worker) = ack::channel(8);
let mut receipt = producer.send_tracked_with_policy(
    cx,
    String::from("retryable job"),
    RetryPolicy::limited(NonZeroU64::new(2).unwrap()),
).await.unwrap();

for _ in 0..2 {
    let mut delivery = worker.recv_with_ack(cx).await.unwrap();
    delivery.push_str(" / attempted");
    delivery.nack();
}
let settled = receipt.wait(cx).await.unwrap();
assert_eq!(settled.deliveries, 2);
match settled.outcome {
    SettlementOutcome::RetryExhausted(value) => {
        assert_eq!(value, "retryable job / attempted / attempted");
        // Persist, inspect, repair or explicitly resubmit this owned value.
        // A resubmission is a new queue identity, never an implicit retry.
    }
    other => panic!("unexpected disposition: {other:?}"),
}
assert_eq!(producer.stats().unfinished(), 0);
assert_eq!(producer.close_and_drain(cx).await, Err(QueueError::Rejected));
```

Returning an exhausted job frees its item credit without requiring a second
queue, new send admission, a user-supplied rejection callback, or a free dead-letter
slot. A repeatedly
failing job therefore cannot retain the queue credit forever through nacks.
The producer receipt owns the returned payload: no queue-internal completion
history or unbounded dead-letter list is created. Unread caller-held results
and pending producer futures are outside the queue capacity/byte accounting.
Dropping a result or relinquishing its receipt allows ordinary payload retirement.
There is no retry timer, backoff, automatic resubmission or rollback of external
effects; callers can combine this policy with the existing managed supervisors.

## Real runtime obligations and explicit handoff

Send reservations and returned deliveries use checked `SendPermit` and `Ack`
obligation admission respectively. A runtime quota, closed holder, or region
refusal restores the physical slot/item and returns `QueueError::Admission`.
Physical receive attempts, including refused Ack admission, increment the
saturating attempt count. Refusal may move that item to the retry tail.
A deliberately runtime-free testing context remains explicitly untracked.

A Rust move alone does not change the task holding the obligation. Resolve each
guard before its original holder exits, or use `guard.try_transfer(&destination)`
with an actual live destination task context from the same runtime. This delegates
to the runtime's checked holder-transfer implementation, including same-region
quota reuse. Success preserves the item's sequence, attempt count, payload and
physical capacity. Retry policy, issued-delivery count and receipt routing also
remain unchanged. `TransferFailure` returns both the exact reason and original
guard. Untracked guards refuse transfer; they never invent tracked ownership.
Dropping a failed transfer aborts/nacks the returned guard normally.

No listener, runtime, detached task, worker pool or ambient I/O is created. The
queue is owned by its endpoints/guards; committed ready items are ordinary queued
values, not tasks or pending Ack obligations. A region close and a queue drain
answer different questions and neither replaces the other.

## Sealing, draining and abandonment

`close()` seals NEW reservations but preserves issued permits. A closed queue
can therefore still receive committed pre-close sends and redeliveries. Workers
see `Closed` only after the ready queue is empty and no reservation or delivery
can return work. Closing admission never means cancelling a held delivery.

`wait_drained(cx)` waits for all three physical counts to reach zero. Without
sealing, it is only a point-in-time observation. `close_and_drain(cx)` seals first.
Dropping/cancelling either borrowing wait preserves item ownership; cancelling
an initiated close-and-drain does not reopen admission. A fresh live context can
observe it again. Both waits use actual notification/cancellation registrations,
not polling timers. Runtime ledger projection and worker-task joins remain the
responsibility of the containing region barrier.

Keep a receiver outside restartable worker generations. Dropping the LAST
receiver is explicit abandonment, not graceful drain: pending producers refuse,
queued tracked values return through their receipts and untracked values are
destroyed outside the lock. Later nacks follow the same abandonment path. This
negative disposition is latched, even when a producer recovers its payload.
Once all outstanding guards settle,
`wait_drained` returns `Abandoned`, never `Ok`, when any accepted work was
abandoned. A last receiver disappearing after all items were acknowledged need
not manufacture a loss. Preissued sends refused because every receiver vanished
return their still-unpublished values.

Explicit rejection and retry exhaustion latch `QueueStats::rejected`. After all
outstanding work settles, `wait_drained` returns `Rejected` rather than `Ok` if
that latch is set. When both kinds of negative disposition occurred, `Abandoned`
takes precedence; both snapshot flags and individual receipts remain available.
Reading receipts or successfully processing later work cannot clear these facts.
Worker EOF means no work remains available, not that every job was acknowledged.
All terminal callbacks run outside the queue mutex and after physical accounting.
Abandonment publishes every tracked result before propagating an unrelated
untracked-payload teardown panic.

## Limits and validation

This is in-memory at-least-once delivery, NOT a disk-backed broker, process-crash
recovery, exactly-once external effects or transactional rollback. The opt-in
poison-job policy bounds issued deliveries only; it is not a time or CPU bound.
Use application idempotency/deduplication for repeatable external effects.
No timeout steals live deliveries. Forgotten guards, non-progressing workers,
blocking callbacks or repeated nacks under an unlimited policy can prevent drain.
Item capacity is not a payload-byte, waiter-memory or CPU-work bound. The ordinary runtime progress
premises still apply.

The source contains twelve original primitive tests, eight original lifecycle/
checked-holder tests, twelve receipt tests and twelve retry-policy tests. The
native target contains twelve current-thread/two-worker tests, including six
new producer-receipt/bounded-retry journeys. The new journeys witness a parked
receipt before observer cancellation, a producer blocked by unacknowledged
capacity before exhaustion, and real managed-worker panics followed by healthy
job completion and return of the exhausted payload. Every native journey finishes
with an enclosing-region close. Two new lab tests cover repeated checked-quota
refusal and successful holder handoff before source-task exit at a full quota.
None of these descriptions is a claim of executed Rust behavioral proof.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib channel::ack::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test ack_queue_native
```

No Rust compiler, Cargo, rustfmt or RCH was available in the authoring environment.
These Rust tests were authored but not compiled or run. Source review, Git blob
comparisons and the separately executed finite-state accounting model do not
establish Rust typing, native scheduling behavior, performance or release readiness.
