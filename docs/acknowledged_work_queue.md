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

Taking an item does not release its credit. Nack/drop returns the same owned
value to the ready tail without allocating additional ready-buffer capacity or
waiting for a producer. Senders and receivers are cloneable; payloads need not be
Clone or Sync. Moving endpoints between threads requires only Send payloads.
Ready items are selected FIFO; retries join the tail. Waiting task admission is
not FIFO, and no performance superiority is claimed for broadcast wakeups.

The receive result is a `Delivery<T>`, rather than an independently movable
`(T, Ack)` pair. It borrows/dereferences to T, so a forgotten acknowledgement can
still recover a non-Clone value. `ack()` consumes the guard, releases capacity,
and returns the acknowledged value. `nack()` or Drop requeues it. Mutations to T
remain present on retries; arbitrary external side effects are not rolled back.

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
physical capacity. `TransferFailure` returns both the exact reason and original
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
queued values are destroyed outside the lock, and later nacks destroy their
values. This loss is latched. Once all outstanding guards settle,
`wait_drained` returns `Abandoned`, never `Ok`, when any accepted work was
abandoned. A last receiver disappearing after all items were acknowledged need
not manufacture a loss. Preissued sends refused because every receiver vanished
return their still-unpublished values.

## Limits and validation

This is in-memory at-least-once delivery, NOT a disk-backed broker, process-crash
recovery, exactly-once external effects, transactional rollback or a poison-job
policy. Use application idempotency/deduplication for repeatable external effects.
No timeout steals live deliveries. Forgotten guards, non-progressing workers,
blocking callbacks or repeated nacks can prevent drain. Item capacity is not a
payload-byte, waiter-memory or CPU-work bound. The ordinary runtime progress
premises still apply.

The source contains twelve primitive regressions, eight lifecycle/checked-holder
regressions, and six native current-thread/two-worker tests. Native journeys
witness real Pending before task abort or a controlled worker panic, verify the
same item returns, exercise actual ManagedSupervisor restarts, and finish with
an enclosing region close. They are not a claim of executed behavioral proof.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib channel::ack::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test ack_queue_native
```

No Rust compiler, Cargo, rustfmt or RCH was available in the authoring environment.
These Rust tests were authored but not compiled or run. Source review, Git blob
comparisons and the separately executed finite-state accounting model do not
establish Rust typing, native scheduling behavior, performance or release readiness.
