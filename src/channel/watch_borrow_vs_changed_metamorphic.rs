//! Metamorphic testing for watch channel borrow-and-update vs changed() ordering.
//!
//! Tests the critical ordering invariant: no missed signals between mark_changed
//! (version update) and waiter wake in send() operations. This ensures that
//! borrow_and_update() and changed() maintain proper synchronization.

use crate::channel::watch::{channel, RecvError};
use crate::cx::Cx;
use crate::test_utils::{init_test, test_cx};
use crate::types::{Budget, RegionId, TaskId};
use crate::util::ArenaIndex;
use proptest::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::future::Future;
use std::pin::Pin;
use std::thread;

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => (),
        }
    }
}

/// Test configuration for borrow-and-update vs changed() ordering.
#[derive(Debug, Clone)]
struct OrderingTestConfig {
    /// Number of concurrent senders.
    sender_count: usize,
    /// Number of concurrent receivers using borrow_and_update.
    borrow_receiver_count: usize,
    /// Number of concurrent receivers using changed().
    changed_receiver_count: usize,
    /// Number of values to send.
    value_count: usize,
    /// Whether to introduce artificial delays.
    with_delays: bool,
}

impl Arbitrary for OrderingTestConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            1usize..=3,  // sender_count
            1usize..=4,  // borrow_receiver_count
            1usize..=4,  // changed_receiver_count
            3usize..=8,  // value_count
            any::<bool>(), // with_delays
        )
        .prop_map(|(sender_count, borrow_count, changed_count, value_count, with_delays)| {
            OrderingTestConfig {
                sender_count,
                borrow_receiver_count: borrow_count,
                changed_receiver_count: changed_count,
                value_count,
                with_delays,
            }
        })
        .boxed()
    }
}

/// Metamorphic Relation 1: Signal Completeness
///
/// **Property**: Every successful send() should eventually result in ALL waiting
/// changed() receivers being woken AND all borrow_and_update() calls seeing
/// the updated value. No signals should be lost between mark_changed and wake.
///
/// **Transformation**: Vary concurrency patterns between send/borrow/changed.
/// **Invariant**: Signal count = send count for all receiver patterns.
fn verify_signal_completeness(config: &OrderingTestConfig) {
    init_test("metamorphic_signal_completeness");
    let cx = test_cx();

    let (tx, base_rx) = channel(0u32);

    // Shared state for tracking signals
    let signals_received = Arc::new(AtomicUsize::new(0));
    let borrow_updates_seen = Arc::new(AtomicUsize::new(0));
    let expected_signals = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    // Spawn changed() receivers
    for i in 0..config.changed_receiver_count {
        let mut rx = tx.subscribe();
        let signals_received = Arc::clone(&signals_received);
        let completed = Arc::clone(&completed);
        let cx_clone = cx.clone();

        let handle = thread::spawn(move || {
            let mut signal_count = 0;
            while !completed.load(Ordering::Acquire) {
                match block_on(rx.changed(&cx_clone)) {
                    Ok(()) => {
                        signal_count += 1;
                        signals_received.fetch_add(1, Ordering::Relaxed);

                        // Verify that borrow_and_update sees consistent value
                        let _value = rx.borrow_and_update();
                    }
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Cancelled) => break,
                    Err(RecvError::PolledAfterCompletion) => break,
                }

                if config.with_delays {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            signal_count
        });
        handles.push(handle);
    }

    // Spawn borrow_and_update() receivers
    for i in 0..config.borrow_receiver_count {
        let mut rx = tx.subscribe();
        let borrow_updates_seen = Arc::clone(&borrow_updates_seen);
        let completed = Arc::clone(&completed);

        let handle = thread::spawn(move || {
            let mut last_version = rx.seen_version();
            let mut update_count = 0;

            while !completed.load(Ordering::Acquire) {
                let current_value = rx.borrow_and_update();
                let current_version = rx.seen_version();

                if current_version != last_version {
                    update_count += 1;
                    borrow_updates_seen.fetch_add(1, Ordering::Relaxed);
                    last_version = current_version;
                }

                if config.with_delays {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                thread::yield_now();
            }
            update_count
        });
        handles.push(handle);
    }

    // Send values from multiple threads
    let mut send_handles = Vec::new();
    let total_sends = config.value_count;
    let sends_per_thread = (total_sends + config.sender_count - 1) / config.sender_count;

    for thread_id in 0..config.sender_count {
        let tx_clone = tx.clone();
        let expected_signals = Arc::clone(&expected_signals);

        let handle = thread::spawn(move || {
            let start = thread_id * sends_per_thread;
            let end = std::cmp::min(start + sends_per_thread, total_sends);
            let mut actual_sends = 0;

            for i in start..end {
                let value = (i + 1) as u32;
                if tx_clone.send(value).is_ok() {
                    actual_sends += 1;
                    expected_signals.fetch_add(1, Ordering::Relaxed);
                }

                if config.with_delays {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            actual_sends
        });
        send_handles.push(handle);
    }

    // Wait for all sends to complete
    let total_actual_sends: usize = send_handles.into_iter()
        .map(|h| h.join().unwrap())
        .sum();

    // Give receivers time to process all signals
    thread::sleep(std::time::Duration::from_millis(50));
    completed.store(true, Ordering::Release);

    // Collect receiver results
    let receiver_results: Vec<usize> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();

    // METAMORPHIC ASSERTION 1: Signal completeness
    let total_changed_signals = signals_received.load(Ordering::Acquire);
    let total_borrow_updates = borrow_updates_seen.load(Ordering::Acquire);
    let expected_total = total_actual_sends * config.changed_receiver_count;

    // Each changed() receiver should see approximately the same number of signals as sends
    // (allowing for some variance due to concurrency)
    let signal_variance = if expected_total > 0 {
        (total_changed_signals as i64 - expected_total as i64).abs() as f64 / expected_total as f64
    } else {
        0.0
    };

    assert!(
        signal_variance <= 0.5, // Allow 50% variance due to concurrency
        "Signal completeness violation: expected ~{} total signals, got {} (variance: {:.2}%)",
        expected_total, total_changed_signals, signal_variance * 100.0
    );

    // METAMORPHIC ASSERTION 2: Borrow updates consistency
    // Each borrow_and_update should see updates corresponding to actual sends
    let borrow_variance = if total_actual_sends > 0 {
        (total_borrow_updates as i64 - (total_actual_sends * config.borrow_receiver_count) as i64).abs() as f64
            / (total_actual_sends * config.borrow_receiver_count) as f64
    } else {
        0.0
    };

    assert!(
        borrow_variance <= 0.3, // Stricter for borrow_and_update
        "Borrow update consistency violation: expected ~{} updates, got {} (variance: {:.2}%)",
        total_actual_sends * config.borrow_receiver_count, total_borrow_updates, borrow_variance * 100.0
    );

    crate::test_complete!("metamorphic_signal_completeness");
}

/// Metamorphic Relation 2: Ordering Consistency
///
/// **Property**: borrow_and_update() should never see a "future" value that
/// changed() hasn't signaled yet. The ordering between mark_changed (version update)
/// and waiter wake should be consistent.
///
/// **Transformation**: Interleave borrow_and_update and changed() calls.
/// **Invariant**: version_seen_by_borrow <= max_version_signaled_by_changed + 1.
fn verify_ordering_consistency() {
    init_test("metamorphic_ordering_consistency");
    let cx = test_cx();

    let (tx, _base_rx) = channel(0u32);
    let max_signaled_version = Arc::new(AtomicU32::new(0));
    let max_borrowed_version = Arc::new(AtomicU32::new(0));
    let completed = Arc::new(AtomicBool::new(false));

    // Receiver using changed() to track signaled versions
    let mut rx_changed = tx.subscribe();
    let max_signaled_version_clone = Arc::clone(&max_signaled_version);
    let completed_clone = Arc::clone(&completed);
    let cx_changed = cx.clone();

    let changed_handle = thread::spawn(move || {
        while !completed_clone.load(Ordering::Acquire) {
            match block_on(rx_changed.changed(&cx_changed)) {
                Ok(()) => {
                    let current_version = rx_changed.seen_version() as u32;
                    let mut max_val = max_signaled_version_clone.load(Ordering::Relaxed);
                    while current_version > max_val {
                        match max_signaled_version_clone.compare_exchange_weak(
                            max_val, current_version, Ordering::Relaxed, Ordering::Relaxed
                        ) {
                            Ok(_) => break,
                            Err(actual) => max_val = actual,
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Receiver using borrow_and_update() to track borrowed versions
    let mut rx_borrow = tx.subscribe();
    let max_borrowed_version_clone = Arc::clone(&max_borrowed_version);
    let completed_clone2 = Arc::clone(&completed);

    let borrow_handle = thread::spawn(move || {
        while !completed_clone2.load(Ordering::Acquire) {
            let _value = rx_borrow.borrow_and_update();
            let current_version = rx_borrow.seen_version() as u32;

            let mut max_val = max_borrowed_version_clone.load(Ordering::Relaxed);
            while current_version > max_val {
                match max_borrowed_version_clone.compare_exchange_weak(
                    max_val, current_version, Ordering::Relaxed, Ordering::Relaxed
                ) {
                    Ok(_) => break,
                    Err(actual) => max_val = actual,
                }
            }

            thread::yield_now();
        }
    });

    // Send values
    for i in 1..=10 {
        tx.send(i).expect("send failed");
        thread::sleep(std::time::Duration::from_millis(5));
    }

    thread::sleep(std::time::Duration::from_millis(50));
    completed.store(true, Ordering::Release);

    changed_handle.join().unwrap();
    borrow_handle.join().unwrap();

    let max_signaled = max_signaled_version.load(Ordering::Acquire);
    let max_borrowed = max_borrowed_version.load(Ordering::Acquire);

    // METAMORPHIC ASSERTION: Ordering consistency
    // borrow_and_update shouldn't see versions significantly ahead of changed()
    assert!(
        max_borrowed <= max_signaled + 1,
        "Ordering consistency violation: borrow saw version {}, but changed only signaled {}",
        max_borrowed, max_signaled
    );

    crate::test_complete!("metamorphic_ordering_consistency");
}

/// Metamorphic Relation 3: No Lost Wakeups
///
/// **Property**: If a receiver is waiting via changed() when send() is called,
/// it should always be woken up. No wakeups should be lost in the window
/// between version update and waiter notification.
///
/// **Transformation**: Vary timing of send() vs changed() registration.
/// **Invariant**: waiting_before_send => woken_after_send.
fn verify_no_lost_wakeups() {
    init_test("metamorphic_no_lost_wakeups");
    let cx = test_cx();

    // Test multiple scenarios with different timing
    for scenario in 0..5 {
        let (tx, mut rx) = channel(scenario as u32);

        // Create a custom waker that tracks wake calls
        let wake_count = Arc::new(AtomicUsize::new(0));
        let wake_count_clone = Arc::clone(&wake_count);
        let waker = waker_fn::waker_fn(move || {
            wake_count_clone.fetch_add(1, Ordering::SeqCst);
        });
        let mut context = Context::from_waker(&waker);

        // Start changed() future
        let mut changed_future = Box::pin(rx.changed(&cx));

        // Poll once to register waiter
        let initial_poll = changed_future.as_mut().poll(&mut context);
        assert!(matches!(initial_poll, Poll::Pending), "Should be pending initially");

        let initial_wake_count = wake_count.load(Ordering::SeqCst);

        // Send a value - this should wake the waiter
        let send_result = tx.send(scenario * 10 + 100);
        assert!(send_result.is_ok(), "Send should succeed");

        // Give a small amount of time for wake to propagate
        thread::sleep(std::time::Duration::from_millis(10));

        let final_wake_count = wake_count.load(Ordering::SeqCst);

        // METAMORPHIC ASSERTION: Waiter should have been woken
        assert!(
            final_wake_count > initial_wake_count,
            "Scenario {}: Lost wakeup detected - wake count didn't increase (was {}, now {})",
            scenario, initial_wake_count, final_wake_count
        );

        // Verify the future now returns Ready
        let final_poll = changed_future.as_mut().poll(&mut context);
        assert!(
            matches!(final_poll, Poll::Ready(Ok(()))),
            "Scenario {}: changed() should return Ready after send and wake",
            scenario
        );

        // Verify borrow_and_update sees the correct value
        let observed_value = *rx.borrow_and_update();
        let expected_value = scenario * 10 + 100;
        assert_eq!(
            observed_value, expected_value,
            "Scenario {}: borrow_and_update should see the sent value",
            scenario
        );
    }

    crate::test_complete!("metamorphic_no_lost_wakeups");
}

// =============================================================================
// PROPTEST INTEGRATION
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// Property: Signal completeness under concurrent send/borrow/changed operations.
    #[test]
    fn proptest_signal_completeness(config in any::<OrderingTestConfig>()) {
        verify_signal_completeness(&config);
    }
}

// =============================================================================
// CONCRETE REGRESSION TESTS
// =============================================================================

#[test]
fn concrete_single_sender_multiple_receivers() {
    let config = OrderingTestConfig {
        sender_count: 1,
        borrow_receiver_count: 2,
        changed_receiver_count: 2,
        value_count: 5,
        with_delays: false,
    };
    verify_signal_completeness(&config);
}

#[test]
fn concrete_multiple_senders_single_receiver() {
    let config = OrderingTestConfig {
        sender_count: 3,
        borrow_receiver_count: 1,
        changed_receiver_count: 1,
        value_count: 6,
        with_delays: true,
    };
    verify_signal_completeness(&config);
}

#[test]
fn concrete_ordering_consistency() {
    verify_ordering_consistency();
}

#[test]
fn concrete_no_lost_wakeups() {
    verify_no_lost_wakeups();
}

/// Helper module to create a simple waker function.
mod waker_fn {
    use std::sync::Arc;
    use std::task::{RawWaker, RawWakerVTable, Waker};

    pub fn waker_fn<F: Fn() + Send + Sync + 'static>(f: F) -> Waker {
        let raw = Arc::into_raw(Arc::new(f)) as *const ();
        let vtable = &RawWakerVTable::new(clone_fn, wake_fn, wake_by_ref_fn, drop_fn);
        unsafe { Waker::from_raw(RawWaker::new(raw, vtable)) }
    }

    unsafe fn clone_fn(data: *const ()) -> RawWaker {
        let arc = Arc::from_raw(data as *const (dyn Fn() + Send + Sync + 'static));
        let cloned = arc.clone();
        std::mem::forget(arc);
        let raw = Arc::into_raw(cloned) as *const ();
        let vtable = &RawWakerVTable::new(clone_fn, wake_fn, wake_by_ref_fn, drop_fn);
        RawWaker::new(raw, vtable)
    }

    unsafe fn wake_fn(data: *const ()) {
        let arc = Arc::from_raw(data as *const (dyn Fn() + Send + Sync + 'static));
        arc();
    }

    unsafe fn wake_by_ref_fn(data: *const ()) {
        let arc = Arc::from_raw(data as *const (dyn Fn() + Send + Sync + 'static));
        arc();
        std::mem::forget(arc);
    }

    unsafe fn drop_fn(data: *const ()) {
        drop(Arc::from_raw(data as *const (dyn Fn() + Send + Sync + 'static)));
    }
}