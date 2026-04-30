//! Metamorphic testing for watch channel borrow-and-update vs changed() ordering.
//!
//! Tests the critical ordering invariant: no missed signals between mark_changed
//! (version update) and waiter wake in send() operations. This ensures that
//! borrow_and_update() and changed() maintain proper synchronization.

use crate::channel::watch::{RecvError, channel};
use proptest::prelude::*;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::thread;

fn init_test(_name: &str) {
    crate::test_utils::init_test_logging();
}

fn test_cx() -> crate::cx::Cx {
    crate::cx::Cx::for_testing()
}

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => thread::yield_now(),
        }
    }
}

/// Test configuration for borrow-and-update vs changed() ordering.
#[derive(Debug, Clone)]
struct OrderingTestConfig {
    /// Number of sender pacing batches. Watch channels are single-producer.
    send_batch_count: usize,
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
            1usize..=3,    // send_batch_count
            1usize..=4,    // borrow_receiver_count
            1usize..=4,    // changed_receiver_count
            3usize..=8,    // value_count
            any::<bool>(), // with_delays
        )
            .prop_map(
                |(send_batch_count, borrow_count, changed_count, value_count, with_delays)| {
                    OrderingTestConfig {
                        send_batch_count,
                        borrow_receiver_count: borrow_count,
                        changed_receiver_count: changed_count,
                        value_count,
                        with_delays,
                    }
                },
            )
            .boxed()
    }
}

/// Metamorphic Relation 1: Signal Completeness
///
/// **Property**: Every successful send() should leave all receiver styles able
/// to converge on the latest value. Watch channels coalesce intermediate values,
/// so receivers are not required to observe every version.
///
/// **Transformation**: Vary concurrency patterns between send/borrow/changed.
/// **Invariant**: all receiver patterns eventually observe the latest value.
fn verify_signal_completeness(config: &OrderingTestConfig) {
    init_test("metamorphic_signal_completeness");
    let cx = test_cx();

    let (tx, _base_rx) = channel(0u32);

    // Shared state for tracking signals
    let signals_received = Arc::new(AtomicUsize::new(0));
    let borrow_updates_seen = Arc::new(AtomicUsize::new(0));
    let max_changed_value = Arc::new(AtomicU32::new(0));
    let max_borrow_value = Arc::new(AtomicU32::new(0));
    let completed = Arc::new(AtomicBool::new(false));
    let with_delays = config.with_delays;

    let mut handles = Vec::new();

    // Spawn changed() receivers
    for _ in 0..config.changed_receiver_count {
        let mut rx = tx.subscribe();
        let signals_received = Arc::clone(&signals_received);
        let max_changed_value = Arc::clone(&max_changed_value);
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
                        let value = *rx.borrow_and_update();
                        max_changed_value.fetch_max(value, Ordering::Relaxed);
                    }
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Cancelled) => break,
                    Err(RecvError::PolledAfterCompletion) => break,
                }

                if with_delays {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            let value = *rx.borrow_and_update();
            max_changed_value.fetch_max(value, Ordering::Relaxed);
            signal_count
        });
        handles.push(handle);
    }

    // Spawn borrow_and_update() receivers
    for _ in 0..config.borrow_receiver_count {
        let mut rx = tx.subscribe();
        let borrow_updates_seen = Arc::clone(&borrow_updates_seen);
        let max_borrow_value = Arc::clone(&max_borrow_value);
        let completed = Arc::clone(&completed);

        let handle = thread::spawn(move || {
            let mut last_version = rx.seen_version();
            let mut update_count = 0;

            while !completed.load(Ordering::Acquire) {
                let value = *rx.borrow_and_update();
                max_borrow_value.fetch_max(value, Ordering::Relaxed);
                let current_version = rx.seen_version();

                if current_version != last_version {
                    update_count += 1;
                    borrow_updates_seen.fetch_add(1, Ordering::Relaxed);
                    last_version = current_version;
                }

                if with_delays {
                    thread::sleep(std::time::Duration::from_millis(1));
                }
                thread::yield_now();
            }
            let value = *rx.borrow_and_update();
            max_borrow_value.fetch_max(value, Ordering::Relaxed);
            update_count
        });
        handles.push(handle);
    }

    // Send values in paced batches. The watch channel is intentionally
    // single-producer, so the interleaving pressure comes from receivers.
    let total_sends = config.value_count;
    let sends_per_batch = total_sends.div_ceil(config.send_batch_count);
    let mut total_actual_sends = 0;

    for batch_id in 0..config.send_batch_count {
        let start = batch_id * sends_per_batch;
        let end = std::cmp::min(start + sends_per_batch, total_sends);

        for i in start..end {
            let value = (i + 1) as u32;
            if tx.send(value).is_ok() {
                total_actual_sends += 1;
            }

            if with_delays {
                thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        thread::yield_now();
    }

    // Give receivers time to process all signals
    thread::sleep(std::time::Duration::from_millis(50));
    completed.store(true, Ordering::Release);
    drop(tx);

    // Join receivers after closing the sender so changed() waiters cannot park forever.
    for handle in handles {
        handle.join().unwrap();
    }

    // METAMORPHIC ASSERTION 1: eventual convergence to the latest watch value.
    let total_changed_signals = signals_received.load(Ordering::Acquire);
    let total_borrow_updates = borrow_updates_seen.load(Ordering::Acquire);
    let expected_latest = total_actual_sends as u32;
    assert_eq!(
        max_changed_value.load(Ordering::Acquire),
        expected_latest,
        "changed receivers should converge to the latest watch value"
    );
    assert_eq!(
        max_borrow_value.load(Ordering::Acquire),
        expected_latest,
        "borrow_and_update receivers should converge to the latest watch value"
    );
    assert!(
        total_changed_signals > 0,
        "at least one changed receiver should observe a wake"
    );
    assert!(
        total_borrow_updates > 0,
        "at least one borrow receiver should observe an update"
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
                            max_val,
                            current_version,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
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
            {
                let _snapshot = rx_borrow.borrow_and_update();
            }
            let current_version = rx_borrow.seen_version() as u32;

            let mut max_val = max_borrowed_version_clone.load(Ordering::Relaxed);
            while current_version > max_val {
                match max_borrowed_version_clone.compare_exchange_weak(
                    max_val,
                    current_version,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
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
    drop(tx);

    changed_handle.join().unwrap();
    borrow_handle.join().unwrap();

    let max_signaled = max_signaled_version.load(Ordering::Acquire);
    let max_borrowed = max_borrowed_version.load(Ordering::Acquire);

    // METAMORPHIC ASSERTION: Ordering consistency
    // borrow_and_update shouldn't see versions significantly ahead of changed()
    assert!(
        max_borrowed <= max_signaled + 1,
        "Ordering consistency violation: borrow saw version {}, but changed only signaled {}",
        max_borrowed,
        max_signaled
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
        let (tx, mut rx) = channel(scenario);

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
        assert!(
            matches!(initial_poll, Poll::Pending),
            "Should be pending initially"
        );

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
            scenario,
            initial_wake_count,
            final_wake_count
        );

        // Verify the future now returns Ready
        let final_poll = changed_future.as_mut().poll(&mut context);
        assert!(
            matches!(final_poll, Poll::Ready(Ok(()))),
            "Scenario {}: changed() should return Ready after send and wake",
            scenario
        );
        drop(changed_future);

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
        send_batch_count: 1,
        borrow_receiver_count: 2,
        changed_receiver_count: 2,
        value_count: 5,
        with_delays: false,
    };
    verify_signal_completeness(&config);
}

#[test]
fn concrete_multiple_send_batches_single_receiver() {
    let config = OrderingTestConfig {
        send_batch_count: 3,
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
    use std::task::{Wake, Waker};

    struct FnWaker<F>(F);

    impl<F: Fn() + Send + Sync + 'static> Wake for FnWaker<F> {
        fn wake(self: Arc<Self>) {
            (self.0)();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            (self.0)();
        }
    }

    pub fn waker_fn<F: Fn() + Send + Sync + 'static>(f: F) -> Waker {
        Waker::from(Arc::new(FnWaker(f)))
    }
}
