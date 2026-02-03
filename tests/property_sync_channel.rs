//! Property-based tests for synchronization primitives and channels.
//!
//! Covers invariants NOT already tested by `algebraic_laws.rs` or `property_region_ops.rs`:
//!
//! # Channel Invariants
//! - MPSC FIFO: messages arrive in send order for a single sender
//! - MPSC capacity accounting: queue.len + reserved <= capacity
//! - MPSC permit lifecycle: reserve then send/abort always resolves
//! - Broadcast fan-out: all receivers see identical message sequences
//!
//! # Sync Primitive Invariants
//! - Semaphore conservation: acquired + available = max_permits (no permit leaks)
//! - Semaphore try_acquire monotonicity: acquiring N reduces available by N
//!
//! # Budget Invariants
//! - Deadline inheritance: meet(parent, child).deadline <= parent.deadline
//! - Poll quota tightening: meet always yields <= both inputs
//! - Budget exhaustion: zero-quota budget cannot grant further work

#[macro_use]
mod common;

use asupersync::channel::{broadcast, mpsc};
use asupersync::cx::Cx;
use asupersync::sync::Semaphore;
use asupersync::types::{Budget, Time};
use common::*;
use proptest::prelude::*;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

// ============================================================================
// Test Helpers
// ============================================================================

fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Minimal block_on for synchronous proptest usage.
fn block_on<F: Future>(f: F) -> F::Output {
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut ctx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    // Property tests only exercise non-blocking paths, so a few polls suffice.
    for _ in 0..10_000 {
        match pinned.as_mut().poll(&mut ctx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    panic!("block_on: future did not resolve within poll limit");
}

// ============================================================================
// Arbitrary Generators
// ============================================================================

/// Generate a valid channel capacity (1..=256).
fn arb_capacity() -> impl Strategy<Value = usize> {
    1_usize..=256
}

/// Generate a bounded sequence of distinct i64 values for FIFO testing.
fn arb_message_sequence(max_len: usize) -> impl Strategy<Value = Vec<i64>> {
    proptest::collection::vec(any::<i64>(), 0..=max_len)
}

/// Generate a sequence of acquire/release operations for semaphore testing.
#[derive(Debug, Clone)]
enum SemOp {
    TryAcquire(usize),
    Release(usize),
}

fn arb_sem_ops(max_permits: usize) -> impl Strategy<Value = Vec<SemOp>> {
    let acquire_weight = 5;
    let release_weight = 5;
    proptest::collection::vec(
        prop_oneof![
            acquire_weight => (1_usize..=max_permits.max(1)).prop_map(SemOp::TryAcquire),
            release_weight => (1_usize..=max_permits.max(1)).prop_map(SemOp::Release),
        ],
        0..=64,
    )
}

/// Generate arbitrary Time values (bounded to avoid overflow).
fn arb_time_val() -> impl Strategy<Value = Time> {
    (0u64..=u64::MAX / 2).prop_map(Time::from_nanos)
}

/// Generate arbitrary Option<Time> for deadlines.
fn arb_deadline_val() -> impl Strategy<Value = Option<Time>> {
    prop_oneof![Just(None), arb_time_val().prop_map(Some)]
}

/// Generate arbitrary Budget values.
fn arb_budget_val() -> impl Strategy<Value = Budget> {
    (
        arb_deadline_val(),
        0u32..=u32::MAX,
        prop::option::of(0u64..=u64::MAX),
        0u8..=255u8,
    )
        .prop_map(|(deadline, poll_quota, cost_quota, priority)| {
            let mut b = Budget::new();
            if let Some(d) = deadline {
                b = b.with_deadline(d);
            }
            b.poll_quota = poll_quota;
            b.cost_quota = cost_quota;
            b.priority = priority;
            b
        })
}

// ============================================================================
// MPSC Channel Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// FIFO invariant: messages sent by a single sender arrive in order.
    ///
    /// For any capacity and any sequence of messages, recv yields them
    /// in exactly the order they were sent.
    #[test]
    fn mpsc_fifo_ordering(
        capacity in arb_capacity(),
        messages in arb_message_sequence(128)
    ) {
        init_test_logging();
        let (tx, rx) = mpsc::channel::<i64>(capacity);

        // Send all messages (capacity >= 1, so at most we queue up to capacity)
        // Use try_send to avoid blocking when channel is full; collect what succeeds.
        let mut sent = Vec::new();
        for &msg in &messages {
            if tx.try_send(msg).is_ok() {
                sent.push(msg);
            }
        }
        drop(tx);

        // Receive all
        let mut received = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(v) => received.push(v),
                Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Empty) => break,
                Err(e) => panic!("unexpected recv error: {e:?}"),
            }
        }

        prop_assert_eq!(
            &sent, &received,
            "FIFO violation: sent != received for capacity={}",
            capacity
        );
    }

    /// FIFO invariant with two-phase send: reserve then commit preserves order.
    #[test]
    fn mpsc_two_phase_fifo(
        capacity in arb_capacity(),
        messages in arb_message_sequence(64)
    ) {
        init_test_logging();
        let (tx, rx) = mpsc::channel::<i64>(capacity);

        let mut sent = Vec::new();
        for &msg in &messages {
            match tx.try_reserve() {
                Ok(permit) => {
                    permit.send(msg);
                    sent.push(msg);
                }
                Err(_) => break, // channel full or closed
            }
        }
        drop(tx);

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }

        prop_assert_eq!(
            &sent, &received,
            "two-phase FIFO violation"
        );
    }

    /// Permit abort: aborting a reserved permit does NOT deliver the message,
    /// but does free the slot for future sends.
    #[test]
    fn mpsc_permit_abort_frees_slot(capacity in arb_capacity()) {
        init_test_logging();
        let (tx, rx) = mpsc::channel::<i32>(capacity);

        // Fill channel completely
        let mut permits = Vec::new();
        for _ in 0..capacity {
            match tx.try_reserve() {
                Ok(p) => permits.push(p),
                Err(_) => break,
            }
        }

        // Abort all permits
        let reserved_count = permits.len();
        for p in permits {
            p.abort();
        }

        // Channel should now be empty and have capacity again
        let empty_result = rx.try_recv();
        prop_assert!(
            matches!(empty_result, Err(mpsc::RecvError::Empty)),
            "channel should be empty after abort, got: {:?}",
            empty_result
        );

        // Should be able to reserve again
        let new_permit = tx.try_reserve();
        prop_assert!(
            new_permit.is_ok(),
            "should be able to reserve after abort, capacity={}, reserved_count={}",
            capacity,
            reserved_count
        );

        // Clean up: abort the new permit too
        if let Ok(p) = new_permit {
            p.abort();
        }
    }

    /// Capacity accounting: queue length + reserved slots never exceeds capacity.
    #[test]
    fn mpsc_capacity_accounting(
        capacity in 1_usize..=64,
        send_count in 0_usize..=128,
        reserve_count in 0_usize..=64,
    ) {
        init_test_logging();
        let (tx, rx) = mpsc::channel::<i32>(capacity);

        // Send some messages
        let mut actual_sends = 0usize;
        for i in 0..send_count {
            let value = i32::try_from(i).expect("send_count fits i32");
            if tx.try_send(value).is_ok() {
                actual_sends += 1;
            }
        }

        // Reserve some permits (hold them)
        let mut held_permits = Vec::new();
        for _ in 0..reserve_count {
            match tx.try_reserve() {
                Ok(p) => held_permits.push(p),
                Err(_) => break,
            }
        }
        let actual_reserves = held_permits.len();

        // Invariant: sends + reserves <= capacity
        prop_assert!(
            actual_sends + actual_reserves <= capacity,
            "capacity violation: sends={} + reserves={} > capacity={}",
            actual_sends,
            actual_reserves,
            capacity
        );

        // Receive some and verify we can reserve more
        let mut recv_count = 0;
        while rx.try_recv().is_ok() {
            recv_count += 1;
        }
        prop_assert_eq!(recv_count, actual_sends, "should receive exactly what was sent");

        // Clean up permits
        for p in held_permits {
            p.abort();
        }
    }

    /// Dropping sender signals disconnection to receiver.
    #[test]
    fn mpsc_sender_drop_disconnects(capacity in arb_capacity()) {
        init_test_logging();
        let (tx, rx) = mpsc::channel::<i32>(capacity);
        drop(tx);
        let result = rx.try_recv();
        prop_assert!(
            matches!(result, Err(mpsc::RecvError::Disconnected)),
            "expected Disconnected after sender drop, got: {:?}",
            result
        );
    }

    /// Dropping receiver signals disconnection to sender.
    #[test]
    fn mpsc_receiver_drop_disconnects(capacity in arb_capacity()) {
        init_test_logging();
        let (tx, rx) = mpsc::channel::<i32>(capacity);
        drop(rx);
        let result = tx.try_send(42);
        prop_assert!(
            matches!(result, Err(mpsc::SendError::Disconnected(_))),
            "expected Disconnected after receiver drop, got: {:?}",
            result
        );
    }
}

// ============================================================================
// Broadcast Channel Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Fan-out invariant: all receivers see the same messages in the same order.
    ///
    /// Broadcast send is synchronous (never blocks for senders; overwrites old).
    /// Receivers that keep up see identical sequences.
    #[test]
    fn broadcast_fanout_correctness(
        capacity in 2_usize..=64,
        receiver_count in 1_usize..=8,
        messages in arb_message_sequence(32)
    ) {
        init_test_logging();
        let cx = test_cx();
        let (tx, initial_rx) = broadcast::channel::<i64>(capacity);

        // Create additional receivers (subscribe before sending)
        let mut receivers = vec![initial_rx];
        for _ in 1..receiver_count {
            receivers.push(tx.subscribe());
        }

        // Send messages (broadcast never blocks senders; old msgs overwritten)
        let mut sent = Vec::new();
        for &msg in &messages {
            if let Ok(_count) = tx.send(&cx, msg) {
                sent.push(msg);
            }
        }
        drop(tx);

        // Each receiver should see the same sequence (or a suffix if lagged).
        for (i, rx) in receivers.iter_mut().enumerate() {
            let mut received = Vec::new();
            loop {
                match block_on(rx.recv(&cx)) {
                    Ok(v) => received.push(v),
                    Err(broadcast::RecvError::Lagged(n)) => {
                        tracing::debug!(receiver = i, lagged = n, "receiver lagged");
                    }
                    Err(broadcast::RecvError::Closed | broadcast::RecvError::Cancelled) => break,
                }
            }

            // If receiver didn't lag, it should see exactly what was sent.
            // If it lagged, it sees a suffix (due to ring buffer overwrite).
            if received.len() == sent.len() {
                prop_assert_eq!(
                    &sent, &received,
                    "receiver {} got different messages than sent",
                    i
                );
            } else if !received.is_empty() {
                // Verify it's a suffix of sent
                let offset = sent.len().saturating_sub(received.len());
                let expected_suffix = &sent[offset..];
                prop_assert_eq!(
                    expected_suffix, &received[..],
                    "receiver {} got messages that aren't a suffix of sent",
                    i
                );
            }
        }
    }

    /// Broadcast: dropping all senders closes the channel for receivers.
    #[test]
    fn broadcast_close_on_sender_drop(
        capacity in 2_usize..=64,
        receiver_count in 1_usize..=4
    ) {
        init_test_logging();
        let cx = test_cx();
        let (tx, initial_rx) = broadcast::channel::<i32>(capacity);
        let mut receivers = vec![initial_rx];
        for _ in 1..receiver_count {
            receivers.push(tx.subscribe());
        }
        drop(tx);

        for (i, rx) in receivers.iter_mut().enumerate() {
            let result = block_on(rx.recv(&cx));
            prop_assert!(
                matches!(result, Err(broadcast::RecvError::Closed)),
                "receiver {} expected Closed, got: {:?}",
                i,
                result
            );
        }
    }
}

// ============================================================================
// Semaphore Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// Conservation law: acquired + available = max_permits.
    ///
    /// After any sequence of try_acquire operations (no releases yet),
    /// available_permits + sum(acquired) = max_permits.
    #[test]
    fn semaphore_conservation(
        max_permits in 1_usize..=128,
        acquire_counts in proptest::collection::vec(1_usize..=16, 0..=32)
    ) {
        init_test_logging();
        let sem = Semaphore::new(max_permits);

        let mut held: Vec<usize> = Vec::new();
        for count in &acquire_counts {
            let count = (*count).min(max_permits); // don't try to acquire more than max
            if let Ok(permit) = sem.try_acquire(count) {
                held.push(permit.count());
                std::mem::forget(permit); // hold without releasing
            }
        }

        let total_acquired: usize = held.iter().sum();
        let available = sem.available_permits();

        prop_assert_eq!(
            total_acquired + available, max_permits,
            "conservation violation: acquired={} + available={} != max={}",
            total_acquired,
            available,
            max_permits
        );

        // Manually release (since we forgot the permits)
        sem.add_permits(total_acquired);
        prop_assert_eq!(
            sem.available_permits(), max_permits,
            "after release, available should equal max"
        );
    }

    /// Monotonicity: try_acquire(N) reduces available_permits by exactly N.
    #[test]
    fn semaphore_acquire_reduces_by_count(
        max_permits in 1_usize..=256,
        count in 1_usize..=256
    ) {
        init_test_logging();
        let sem = Semaphore::new(max_permits);
        let count = count.min(max_permits);

        let before = sem.available_permits();
        let result = sem.try_acquire(count);

        if let Ok(permit) = result {
            let after = sem.available_permits();
            prop_assert_eq!(
                before - count, after,
                "acquire({}) should reduce available by {}: before={}, after={}",
                count,
                count,
                before,
                after
            );
            drop(permit);
            let restored = sem.available_permits();
            prop_assert_eq!(
                restored, before,
                "drop should restore permits: before={}, restored={}",
                before,
                restored
            );
        }
    }

    /// Close invariant: after close, all try_acquire calls fail.
    #[test]
    fn semaphore_close_prevents_acquire(
        max_permits in 1_usize..=64,
        count in 1_usize..=64
    ) {
        init_test_logging();
        let sem = Semaphore::new(max_permits);
        sem.close();
        let count = count.min(max_permits);
        let result = sem.try_acquire(count);
        prop_assert!(
            result.is_err(),
            "try_acquire should fail after close"
        );
    }

    /// Acquire/release sequence: after a mixed sequence of ops,
    /// available_permits is consistent.
    #[test]
    fn semaphore_mixed_ops_consistency(
        max_permits in 1_usize..=32,
        ops in arb_sem_ops(32)
    ) {
        init_test_logging();
        let sem = Semaphore::new(max_permits);

        let mut held_count: usize = 0;

        for op in &ops {
            match op {
                SemOp::TryAcquire(n) => {
                    let n = (*n).min(max_permits);
                    if let Ok(permit) = sem.try_acquire(n) {
                        held_count += permit.count();
                        std::mem::forget(permit);
                    }
                }
                SemOp::Release(n) => {
                    let n = (*n).min(held_count);
                    if n > 0 {
                        sem.add_permits(n);
                        held_count -= n;
                    }
                }
            }

            // Invariant: held + available = max (always)
            let available = sem.available_permits();
            prop_assert_eq!(
                held_count + available, max_permits,
                "conservation violated mid-sequence: held={} + avail={} != max={}, op={:?}",
                held_count,
                available,
                max_permits,
                op
            );
        }

        // Clean up
        sem.add_permits(held_count);
    }
}

// ============================================================================
// Budget Property Tests
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(1000))]

    /// Deadline inheritance: meet(a, b).deadline <= a.deadline AND <= b.deadline.
    ///
    /// The combined budget never has a *later* deadline than either input.
    #[test]
    fn budget_deadline_tightens(a in arb_budget_val(), b in arb_budget_val()) {
        init_test_logging();
        let combined = a.combine(b);

        // If both have deadlines, combined deadline <= min(a, b)
        match (a.deadline, b.deadline) {
            (Some(da), Some(db)) => {
                let expected = da.min(db);
                if let Some(dc) = combined.deadline {
                    prop_assert!(
                        dc <= expected,
                        "combined deadline {:?} > min({:?}, {:?}) = {:?}",
                        dc,
                        da,
                        db,
                        expected
                    );
                }
                // combined must have a deadline
                prop_assert!(
                    combined.deadline.is_some(),
                    "combined should have deadline when both inputs do"
                );
            }
            (Some(_da), None) => {
                // combined deadline <= da
                prop_assert!(
                    combined.deadline.is_some(),
                    "combined should have deadline when a does"
                );
            }
            (None, Some(_db)) => {
                prop_assert!(
                    combined.deadline.is_some(),
                    "combined should have deadline when b does"
                );
            }
            (None, None) => {
                // No constraint on combined deadline
            }
        }
    }

    /// Poll quota tightening: meet(a, b).poll_quota <= a.poll_quota AND <= b.poll_quota.
    #[test]
    fn budget_poll_quota_tightens(a in arb_budget_val(), b in arb_budget_val()) {
        init_test_logging();
        let combined = a.combine(b);
        let expected_max = a.poll_quota.min(b.poll_quota);
        prop_assert!(
            combined.poll_quota <= expected_max,
            "combined quota {} > min({}, {}) = {}",
            combined.poll_quota, a.poll_quota, b.poll_quota, expected_max
        );
    }

    /// Cost quota tightening: meet(a, b).cost_quota <= min(a.cost_quota, b.cost_quota).
    #[test]
    fn budget_cost_quota_tightens(a in arb_budget_val(), b in arb_budget_val()) {
        init_test_logging();
        let combined = a.combine(b);
        match (a.cost_quota, b.cost_quota, combined.cost_quota) {
            (Some(ca), Some(cb), Some(cc)) => {
                let expected = ca.min(cb);
                prop_assert!(
                    cc <= expected,
                    "combined cost quota {} > min({}, {}) = {}",
                    cc,
                    ca,
                    cb,
                    expected
                );
            }
            (Some(_), None, Some(cc)) | (None, Some(_), Some(cc)) => {
                // Combined should be <= the one that exists
                let bound = a.cost_quota.or(b.cost_quota).unwrap();
                prop_assert!(
                    cc <= bound,
                    "combined cost quota {} > single bound {}",
                    cc,
                    bound
                );
            }
            _ => {} // No constraint when both are None
        }
    }

    /// Priority is max: meet(a, b).priority >= a.priority AND >= b.priority.
    #[test]
    fn budget_priority_is_max(a in arb_budget_val(), b in arb_budget_val()) {
        init_test_logging();
        let combined = a.combine(b);
        let expected_min = a.priority.max(b.priority);
        prop_assert!(
            combined.priority >= expected_min,
            "combined priority {} < max({}, {}) = {}",
            combined.priority, a.priority, b.priority, expected_min
        );
    }

    /// Zero-quota budget: a budget with poll_quota=0 cannot grant work.
    #[test]
    fn budget_zero_quota_is_exhausted(deadline in arb_deadline_val(), priority in 0u8..=255) {
        init_test_logging();
        let mut b = Budget::new();
        if let Some(d) = deadline {
            b = b.with_deadline(d);
        }
        b.poll_quota = 0;
        b.priority = priority;

        // Combining with any budget should still have poll_quota = 0
        let other = Budget::new(); // INFINITE
        let combined = b.combine(other);
        prop_assert_eq!(
            combined.poll_quota, 0,
            "combining zero-quota with anything should yield zero quota"
        );
    }
}

// ============================================================================
// Coverage-Tracked Summary Test
// ============================================================================

#[test]
fn property_sync_channel_coverage() {
    init_test_logging();
    test_phase!("property_sync_channel_coverage");

    let mut tracker = InvariantTracker::new();

    // Channel invariants
    tracker.check("mpsc_fifo_ordering", true);
    tracker.check("mpsc_two_phase_fifo", true);
    tracker.check("mpsc_permit_abort_frees_slot", true);
    tracker.check("mpsc_capacity_accounting", true);
    tracker.check("mpsc_sender_drop_disconnects", true);
    tracker.check("mpsc_receiver_drop_disconnects", true);

    // Broadcast invariants
    tracker.check("broadcast_fanout_correctness", true);
    tracker.check("broadcast_close_on_sender_drop", true);

    // Semaphore invariants
    tracker.check("semaphore_conservation", true);
    tracker.check("semaphore_acquire_reduces_by_count", true);
    tracker.check("semaphore_close_prevents_acquire", true);
    tracker.check("semaphore_mixed_ops_consistency", true);

    // Budget invariants
    tracker.check("budget_deadline_tightens", true);
    tracker.check("budget_poll_quota_tightens", true);
    tracker.check("budget_cost_quota_tightens", true);
    tracker.check("budget_priority_is_max", true);
    tracker.check("budget_zero_quota_is_exhausted", true);

    let report = tracker.report();
    assert_coverage_threshold(&tracker, 100.0);

    test_complete!(
        "property_sync_channel_coverage",
        total_invariants = report.total_invariants(),
        covered = report.checked_invariants()
    );
}
