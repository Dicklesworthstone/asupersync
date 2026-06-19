//! Process-group monitor-stream delivery conformance (8y37kz.1 / [DIST-OTP]).
//!
//! These integration tests link the library in non-test mode (immune to peer
//! `#[cfg(test)]` breakage) and pin the **monitor-stream async wiring** of
//! `spork::process_group` — the two-phase
//! `GroupEventSubscriber::deliver_pending_to` path that reserves a broadcast
//! send permit, commits the batch to live monitor receivers, and advances the
//! subscriber cursor *only after* delivery succeeds.
//!
//! That surface (`deliver_pending_to`, [`GroupMonitorDelivery`],
//! [`GroupMonitorDeliveryError`]) had zero external coverage: the other
//! `process_group` test files exercise the value-layer `pending_batch`/`commit`
//! cursor mechanics but never drive a real `broadcast::channel` + `Cx` through
//! the monitor delivery path. This file closes that gap, oracle-free:
//!
//! - **AC5 (monitor stream, exactly-once):** a live receiver gets the exact
//!   pending batch and the cursor advances exactly once; a caught-up subscriber
//!   delivers an empty batch and never enqueues a spurious payload; redelivery
//!   after commit carries only the new tail; incremental delivery is
//!   metamorphically identical to a single one-shot delivery.
//! - **AC2 (two-phase, no silent drop) applied to the monitor stream:** a
//!   closed monitor (no live receivers) and a cancelled `Cx` both fail closed —
//!   the cursor never advances, the undelivered batch is preserved in the error,
//!   nothing is committed to the channel, and a retry to a fresh receiver / a
//!   fresh `Cx` delivers the same events exactly once with no loss.
//!
//! Scope note: this is node-local value/wiring coverage on committed `HEAD`.
//! It makes no claim about the still-open runtime ACs (lease-backed async join,
//! real `execute_broadcast` mailbox delivery/backpressure, the AC1 oracle death
//! matrix) and does not touch `src/spork.rs`.

#![allow(missing_docs)]

use asupersync::channel::broadcast;
use asupersync::cx::Cx;
use asupersync::monitor::DownReason;
use asupersync::remote::NodeId;
use asupersync::spork::process_group::{
    GroupEvent, GroupEventBatch, GroupEventCursor, GroupEventSubscriber, GroupMemberId,
    GroupMonitorDeliveryError, GroupName, ProcessGroupState,
};
use asupersync::types::{CancelKind, TaskId, Time};

/// Deterministic node-qualified member id.
fn member(node: &str, task: u32) -> GroupMemberId {
    GroupMemberId::new(NodeId::new(node), TaskId::new_for_test(task, 0))
}

/// A group with a known 4-event log: Joined(0), Joined(1), Left(2), Down(3).
fn populated_group() -> ProcessGroupState {
    let mut state = ProcessGroupState::new(GroupName::new("workers").expect("valid group name"));
    state
        .join(member("n1", 1), Time::from_nanos(1))
        .expect("first join of m1 succeeds");
    state
        .join(member("n1", 2), Time::from_nanos(2))
        .expect("first join of m2 succeeds");
    state
        .leave(&member("n1", 1), Time::from_nanos(3))
        .expect("explicit leave of active member succeeds");
    state
        .mark_down(&member("n1", 2), DownReason::Normal, Time::from_nanos(4))
        .expect("down of active member succeeds");
    state
}

/// Flatten the event sequence numbers carried by a batch in emission order.
fn seqs(batch: &GroupEventBatch) -> Vec<u64> {
    batch.events().iter().map(GroupEvent::sequence).collect()
}

/// Drain every currently-buffered batch from a monitor receiver, returning the
/// flattened sequence numbers observed across all batches in delivery order.
fn drain_receiver(rx: &mut broadcast::Receiver<GroupEventBatch>) -> Vec<u64> {
    let mut observed = Vec::new();
    while let Ok(batch) = rx.try_recv() {
        observed.extend(batch.events().iter().map(GroupEvent::sequence));
    }
    observed
}

#[test]
fn monitor_delivery_reaches_live_receiver_and_advances_cursor_exactly_once() {
    let cx = Cx::for_testing();
    let state = populated_group();
    let (tx, mut rx) = broadcast::channel::<GroupEventBatch>(8);
    let mut sub = GroupEventSubscriber::new();

    let delivery = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect("delivery to a live receiver succeeds");

    // Two-phase commit: exactly one live receiver accepted the batch, and the
    // subscriber cursor advanced exactly once as a result.
    assert_eq!(delivery.delivered_receiver_count(), 1);
    assert!(delivery.cursor_advanced());

    // The delivered batch is the whole pending log in deterministic order.
    assert_eq!(seqs(delivery.batch()), vec![0, 1, 2, 3]);

    // The receiver observes the exact same batch — no payload divergence.
    let received = rx.try_recv().expect("receiver gets the broadcast batch");
    assert_eq!(&received, delivery.batch());

    // The cursor now sits past the entire log and matches the batch's commit
    // point, so a subsequent caught-up delivery has nothing to send.
    assert_eq!(sub.cursor().next_sequence(), state.next_event_sequence());
    assert_eq!(sub.cursor(), delivery.batch().next_cursor());
}

#[test]
fn caught_up_subscriber_delivers_empty_and_never_touches_the_stream() {
    let cx = Cx::for_testing();
    let state = populated_group();
    let (tx, mut rx) = broadcast::channel::<GroupEventBatch>(8);
    let mut sub = GroupEventSubscriber::new();

    // First delivery drains the whole log to the receiver.
    let first = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect("first delivery ok");
    assert!(first.cursor_advanced());
    let _ = rx.try_recv().expect("first batch delivered");
    let cursor_after_first = sub.cursor();

    // No new events: delivery is Ok with an empty batch, no receiver was
    // touched, and the cursor does not move.
    let second = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect("empty delivery is still Ok");
    assert!(second.batch().is_empty());
    assert_eq!(second.delivered_receiver_count(), 0);
    assert!(!second.cursor_advanced());
    assert_eq!(
        sub.cursor(),
        cursor_after_first,
        "an empty delivery must not move the cursor"
    );

    // The empty short-circuit must not enqueue a spurious empty batch onto the
    // monitor stream — the receiver sees nothing further.
    assert!(
        rx.try_recv().is_err(),
        "no spurious batch should reach the monitor stream"
    );
}

#[test]
fn closed_monitor_rolls_back_then_retry_delivers_the_same_events_once() {
    let cx = Cx::for_testing();
    let state = populated_group();
    let (tx, rx) = broadcast::channel::<GroupEventBatch>(8);
    drop(rx); // no live monitor receivers remain

    let mut sub = GroupEventSubscriber::new();
    let err = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect_err("delivery to a closed monitor fails closed");

    match &err {
        GroupMonitorDeliveryError::Closed(batch) => {
            assert_eq!(
                seqs(batch),
                vec![0, 1, 2, 3],
                "the undelivered batch must carry every pending event"
            );
        }
        GroupMonitorDeliveryError::Cancelled(reason) => {
            panic!("expected Closed, got Cancelled({reason:?})")
        }
    }
    assert!(err.to_string().contains("closed"));

    // Rollback: the cursor never advanced, so nothing was silently dropped.
    assert_eq!(sub.cursor(), GroupEventCursor::new());

    // A fresh monitor subscribes; retrying delivers the SAME events exactly once.
    let mut rx2 = tx.subscribe();
    let delivery = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect("retry to a live receiver succeeds");
    assert!(delivery.cursor_advanced());

    let received = rx2.try_recv().expect("retry batch delivered");
    assert_eq!(seqs(&received), vec![0, 1, 2, 3]);
    assert_eq!(sub.cursor().next_sequence(), state.next_event_sequence());

    // Exactly-once: there is nothing further to deliver after the retry.
    assert!(rx2.try_recv().is_err());
}

#[test]
fn cancelled_cx_rolls_back_without_sending_then_fresh_cx_recovers() {
    let cx = Cx::for_testing();
    let state = populated_group();
    let (tx, mut rx) = broadcast::channel::<GroupEventBatch>(8);
    let mut sub = GroupEventSubscriber::new();

    // Cancel before delivery: reserve must surface the cancel as an error and
    // commit nothing (cancel-correctness), even though a receiver is live.
    cx.cancel_fast(CancelKind::Shutdown);
    let err = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect_err("delivery under a cancelled cx fails closed");

    assert!(matches!(err, GroupMonitorDeliveryError::Cancelled(_)));
    assert_eq!(
        err.batch().len(),
        4,
        "the undelivered batch is preserved in the error"
    );
    assert!(err.to_string().contains("cancelled"));

    // No batch was committed to the live receiver, and the cursor stayed put.
    assert!(
        rx.try_recv().is_err(),
        "a cancelled delivery must not send anything"
    );
    assert_eq!(sub.cursor(), GroupEventCursor::new());

    // A fresh, non-cancelled cx delivers the same events with no loss.
    let cx2 = Cx::for_testing();
    let delivery = sub
        .deliver_pending_to(&cx2, &state, &tx)
        .expect("a fresh cx delivers the preserved batch");
    assert!(delivery.cursor_advanced());

    let received = rx.try_recv().expect("batch delivered under the fresh cx");
    assert_eq!(seqs(&received), vec![0, 1, 2, 3]);
    assert_eq!(sub.cursor().next_sequence(), state.next_event_sequence());
}

#[test]
fn incremental_delivery_equals_one_shot_delivery_metamorphic() {
    // Metamorphic relation: subscriber A delivers after every mutation, while
    // subscriber B delivers once at the very end. Both monitor streams must
    // observe the identical event sequence, each event exactly once, in order.
    let cx = Cx::for_testing();

    let mut state_a = ProcessGroupState::new(GroupName::new("g").expect("valid group name"));
    let mut state_b = ProcessGroupState::new(GroupName::new("g").expect("valid group name"));

    let (tx_a, mut rx_a) = broadcast::channel::<GroupEventBatch>(32);
    let (tx_b, mut rx_b) = broadcast::channel::<GroupEventBatch>(32);
    let mut sub_a = GroupEventSubscriber::new();
    let mut sub_b = GroupEventSubscriber::new();

    let steps: u32 = 6;
    for i in 0..steps {
        let m = member("n", i);
        let at = Time::from_nanos(u64::from(i));
        state_a.join(m.clone(), at).expect("join into state_a");
        state_b.join(m, at).expect("join into state_b");
        // Incremental: A delivers the single new event now.
        let d = sub_a
            .deliver_pending_to(&cx, &state_a, &tx_a)
            .expect("incremental join delivery ok");
        assert!(d.cursor_advanced());
    }
    for i in 0..3u32 {
        let m = member("n", i);
        let at = Time::from_nanos(u64::from(steps + i));
        state_a.leave(&m, at).expect("leave from state_a");
        state_b.leave(&m, at).expect("leave from state_b");
        let d = sub_a
            .deliver_pending_to(&cx, &state_a, &tx_a)
            .expect("incremental leave delivery ok");
        assert!(d.cursor_advanced());
    }

    // One-shot: B delivers the entire accumulated log in a single batch.
    let one_shot = sub_b
        .deliver_pending_to(&cx, &state_b, &tx_b)
        .expect("one-shot delivery ok");

    let observed_a = drain_receiver(&mut rx_a);
    let observed_b = drain_receiver(&mut rx_b);

    // Metamorphic equality of the two delivery strategies.
    assert_eq!(observed_a, observed_b);

    // ...and both equal the full deterministic event log.
    let log_seqs: Vec<u64> = state_a
        .event_log()
        .iter()
        .map(GroupEvent::sequence)
        .collect();
    assert_eq!(observed_a, log_seqs);

    // Exactly-once: strictly increasing sequence, no repeats or gaps in delivery.
    assert!(observed_a.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(one_shot.batch().len(), log_seqs.len());

    // Both subscribers are fully caught up: any further delivery is empty.
    assert!(
        sub_a
            .deliver_pending_to(&cx, &state_a, &tx_a)
            .expect("caught-up a")
            .batch()
            .is_empty()
    );
    assert!(
        sub_b
            .deliver_pending_to(&cx, &state_b, &tx_b)
            .expect("caught-up b")
            .batch()
            .is_empty()
    );
}

#[test]
fn redelivery_after_commit_delivers_only_the_new_tail() {
    let cx = Cx::for_testing();
    let (tx, mut rx) = broadcast::channel::<GroupEventBatch>(8);
    let mut sub = GroupEventSubscriber::new();
    let mut state = ProcessGroupState::new(GroupName::new("g").expect("valid group name"));

    // First wave: two joins, delivered.
    state.join(member("n", 0), Time::from_nanos(0)).expect("j0");
    state.join(member("n", 1), Time::from_nanos(1)).expect("j1");
    let first = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect("first delivery ok");
    assert_eq!(seqs(first.batch()), vec![0, 1]);

    // Second wave: new events appended, delivered.
    state
        .leave(&member("n", 0), Time::from_nanos(2))
        .expect("l0");
    state.join(member("n", 2), Time::from_nanos(3)).expect("j2");
    let second = sub
        .deliver_pending_to(&cx, &state, &tx)
        .expect("second delivery ok");

    // Only the new tail is delivered — committed events are never repeated.
    assert_eq!(seqs(second.batch()), vec![2, 3]);

    // The two received batches concatenate to the full log with no overlap.
    let b1 = rx.try_recv().expect("batch 1 delivered");
    let b2 = rx.try_recv().expect("batch 2 delivered");
    let mut all = seqs(&b1);
    all.extend(seqs(&b2));
    assert_eq!(all, vec![0, 1, 2, 3]);
    assert_eq!(sub.cursor().next_sequence(), state.next_event_sequence());
}
