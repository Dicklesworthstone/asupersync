#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use asupersync::sync::Notify;

#[derive(Debug, Clone)]
struct MultiWaiterTracker {
    waiters_state: Arc<Mutex<HashMap<usize, WaiterState>>>,
    notify_calls: Arc<Mutex<Vec<String>>>,
}

#[derive(Debug, Clone, PartialEq)]
enum WaiterState {
    Created,
    Polled,
    Ready,
    Pending,
}

impl MultiWaiterTracker {
    fn new() -> Self {
        Self {
            waiters_state: Arc::new(Mutex::new(HashMap::new())),
            notify_calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_waiter_state(&self, waiter_id: usize, state: WaiterState) {
        if let Ok(mut states) = self.waiters_state.lock() {
            states.insert(waiter_id, state);
        }
    }

    fn record_notify_call(&self, call: &str) {
        if let Ok(mut calls) = self.notify_calls.lock() {
            calls.push(call.to_string());
        }
    }

    fn get_ready_count(&self) -> usize {
        if let Ok(states) = self.waiters_state.lock() {
            states
                .values()
                .filter(|&state| *state == WaiterState::Ready)
                .count()
        } else {
            0
        }
    }

    fn get_pending_count(&self) -> usize {
        if let Ok(states) = self.waiters_state.lock() {
            states
                .values()
                .filter(|&state| *state == WaiterState::Pending)
                .count()
        } else {
            0
        }
    }

    fn validate_notify_one_invariant(&self, expected_ready: usize) {
        let ready_count = self.get_ready_count();
        let pending_count = self.get_pending_count();

        // Core invariant: notify_one() should wake exactly expected_ready waiters
        assert_eq!(
            ready_count, expected_ready,
            "notify_one() violated single-wakeup invariant. Expected {} ready, got {} ready, {} pending",
            expected_ready, ready_count, pending_count
        );

        // Additional invariant: ready + pending should match total registered waiters
        let total_waiters = if let Ok(states) = self.waiters_state.lock() {
            states.len()
        } else {
            0
        };

        if total_waiters > 0 {
            assert!(
                ready_count + pending_count <= total_waiters,
                "Ready + pending ({}) exceeds total waiters ({})",
                ready_count + pending_count,
                total_waiters
            );
        }
    }
}

struct TrackedWaker {
    waiter_id: usize,
    tracker: MultiWaiterTracker,
    waked: Arc<Mutex<bool>>,
}

impl TrackedWaker {
    fn new(waiter_id: usize, tracker: MultiWaiterTracker) -> Self {
        Self {
            waiter_id,
            tracker,
            waked: Arc::new(Mutex::new(false)),
        }
    }

    fn was_waked(&self) -> bool {
        self.waked
            .lock()
            .unwrap_or_else(|_| std::sync::MutexGuard::new(&false))
            .clone()
    }

    fn create_waker(&self) -> Waker {
        let data = Arc::new(self.clone());
        let raw = RawWaker::new(Arc::into_raw(data) as *const (), &TRACKED_WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}

impl Clone for TrackedWaker {
    fn clone(&self) -> Self {
        Self {
            waiter_id: self.waiter_id,
            tracker: self.tracker.clone(),
            waked: Arc::clone(&self.waked),
        }
    }
}

// RawWaker vtable for TrackedWaker
static TRACKED_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    tracked_waker_clone,
    tracked_waker_wake,
    tracked_waker_wake_by_ref,
    tracked_waker_drop,
);

unsafe fn tracked_waker_clone(data: *const ()) -> RawWaker {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    let cloned = arc.clone();
    std::mem::forget(arc); // Don't drop the original
    let new_data = Arc::into_raw(cloned) as *const ();
    RawWaker::new(new_data, &TRACKED_WAKER_VTABLE)
}

unsafe fn tracked_waker_wake(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker
        .record_waiter_state(arc.waiter_id, WaiterState::Ready);
}

unsafe fn tracked_waker_wake_by_ref(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker
        .record_waiter_state(arc.waiter_id, WaiterState::Ready);
    std::mem::forget(arc); // Don't drop, we only borrowed
}

unsafe fn tracked_waker_drop(data: *const ()) {
    let _arc = Arc::from_raw(data as *const TrackedWaker);
    // Arc drop happens automatically
}

#[derive(Debug, Clone, Arbitrary)]
struct MultiWaiterConfig {
    waiter_count: u8, // Number of waiters to create
    notify_pattern: NotifyPattern,
}

#[derive(Debug, Clone, Arbitrary)]
enum NotifyPattern {
    SingleNotifyOne,
    MultipleNotifyOne { count: u8 },
    NotifyOneThenWaiters { additional_waiters: u8 },
    InterleavedCreateNotify { interleaving: Vec<bool> }, // true=create, false=notify
    RapidNotifyOne { rapid_count: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum MultiWaiterOperation {
    CreateWaiter { waiter_id: u8 },
    PollWaiter { waiter_id: u8 },
    NotifyOne,
    NotifyWaiters { count: u8 },
    CheckInvariants,
    ValidateExactlyOneReady,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Generate test configuration
    let config: MultiWaiterConfig = u.arbitrary().unwrap_or(MultiWaiterConfig {
        waiter_count: 3,
        notify_pattern: NotifyPattern::SingleNotifyOne,
    });

    if config.waiter_count == 0 || config.waiter_count > 10 {
        return; // Reasonable bounds
    }

    let tracker = MultiWaiterTracker::new();
    let notify = Arc::new(Notify::new());
    let mut waiters = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create the specified number of waiters
    for i in 0..config.waiter_count {
        let notified = notify.notified();
        waiters.push(notified);

        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        tracked_wakers.push(tracked_waker);

        tracker.record_waiter_state(i as usize, WaiterState::Created);
    }

    // Execute the notify pattern
    match config.notify_pattern {
        NotifyPattern::SingleNotifyOne => {
            // Poll all waiters first to register them
            for (i, waiter) in waiters.iter_mut().enumerate() {
                let waker = tracked_wakers[i].create_waker();
                let mut context = Context::from_waker(&waker);

                let poll_result = Pin::new(waiter).poll(&mut context);
                match poll_result {
                    Poll::Ready(()) => {
                        tracker.record_waiter_state(i, WaiterState::Ready);
                    }
                    Poll::Pending => {
                        tracker.record_waiter_state(i, WaiterState::Pending);
                    }
                }
            }

            // Now call notify_one() - should wake exactly one
            tracker.record_notify_call("notify_one");
            notify.notify_one();

            // Poll all waiters again to see who became ready
            for (i, waiter) in waiters.iter_mut().enumerate() {
                let waker = tracked_wakers[i].create_waker();
                let mut context = Context::from_waker(&waker);

                let poll_result = Pin::new(waiter).poll(&mut context);
                match poll_result {
                    Poll::Ready(()) => {
                        tracker.record_waiter_state(i, WaiterState::Ready);
                    }
                    Poll::Pending => {
                        tracker.record_waiter_state(i, WaiterState::Pending);
                    }
                }
            }

            // Validate: exactly one should be ready
            tracker.validate_notify_one_invariant(1);
        }

        NotifyPattern::MultipleNotifyOne { count } => {
            let notify_count = (count.min(10).max(1)) as usize;

            // Poll all waiters first
            for (i, waiter) in waiters.iter_mut().enumerate() {
                let waker = tracked_wakers[i].create_waker();
                let mut context = Context::from_waker(&waker);
                let _ = Pin::new(waiter).poll(&mut context);
                tracker.record_waiter_state(i, WaiterState::Pending);
            }

            // Call notify_one() multiple times
            for _ in 0..notify_count {
                tracker.record_notify_call("notify_one");
                notify.notify_one();

                // Poll all waiters to check state after each notify
                for (i, waiter) in waiters.iter_mut().enumerate() {
                    let waker = tracked_wakers[i].create_waker();
                    let mut context = Context::from_waker(&waker);

                    if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
                        tracker.record_waiter_state(i, WaiterState::Ready);
                    }
                }
            }

            // Validate: at most notify_count waiters should be ready
            let expected_ready = notify_count.min(config.waiter_count as usize);
            let ready_count = tracker.get_ready_count();
            assert!(
                ready_count <= expected_ready,
                "Too many waiters ready: {} > {}",
                ready_count,
                expected_ready
            );
        }

        NotifyPattern::NotifyOneThenWaiters { additional_waiters } => {
            // Poll initial waiters
            for (i, waiter) in waiters.iter_mut().enumerate() {
                let waker = tracked_wakers[i].create_waker();
                let mut context = Context::from_waker(&waker);
                let _ = Pin::new(waiter).poll(&mut context);
                tracker.record_waiter_state(i, WaiterState::Pending);
            }

            // Call notify_one() first
            tracker.record_notify_call("notify_one");
            notify.notify_one();

            // Poll to see who became ready
            for (i, waiter) in waiters.iter_mut().enumerate() {
                let waker = tracked_wakers[i].create_waker();
                let mut context = Context::from_waker(&waker);

                if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
                    tracker.record_waiter_state(i, WaiterState::Ready);
                }
            }

            // Should have exactly one ready at this point
            tracker.validate_notify_one_invariant(1);

            // Create additional waiters
            let additional = additional_waiters.min(5) as usize;
            for i in 0..additional {
                let notified = notify.notified();
                let extra_waker =
                    TrackedWaker::new(config.waiter_count as usize + i, tracker.clone());

                let waker = extra_waker.create_waker();
                let mut context = Context::from_waker(&waker);
                let _ = Pin::new(&mut Box::pin(notified)).poll(&mut context);
            }
        }

        NotifyPattern::InterleavedCreateNotify { interleaving } => {
            let mut waiter_idx = 0;

            for &is_create in interleaving.iter().take(20) {
                // Limit operations
                if is_create && waiter_idx < waiters.len() {
                    // Poll a waiter to register it
                    let waker =
                        std::task::Waker::from(Arc::new(tracked_wakers[waiter_idx].clone()));
                    let mut context = Context::from_waker(&waker);
                    let _ = Pin::new(&mut waiters[waiter_idx]).poll(&mut context);
                    tracker.record_waiter_state(waiter_idx, WaiterState::Pending);
                    waiter_idx += 1;
                } else {
                    // Call notify_one()
                    tracker.record_notify_call("notify_one");
                    notify.notify_one();

                    // Poll all registered waiters to update states
                    for i in 0..waiter_idx {
                        let waker = tracked_wakers[i].create_waker();
                        let mut context = Context::from_waker(&waker);

                        if let Poll::Ready(()) = Pin::new(&mut waiters[i]).poll(&mut context) {
                            tracker.record_waiter_state(i, WaiterState::Ready);
                        }
                    }
                }
            }
        }

        NotifyPattern::RapidNotifyOne { rapid_count } => {
            // Register all waiters first
            for (i, waiter) in waiters.iter_mut().enumerate() {
                let waker = tracked_wakers[i].create_waker();
                let mut context = Context::from_waker(&waker);
                let _ = Pin::new(waiter).poll(&mut context);
                tracker.record_waiter_state(i, WaiterState::Pending);
            }

            // Rapid notify_one() calls
            let rapid_calls = rapid_count.min(20) as usize;
            for _ in 0..rapid_calls {
                notify.notify_one();

                // Poll all waiters after each notify
                for (i, waiter) in waiters.iter_mut().enumerate() {
                    let waker = tracked_wakers[i].create_waker();
                    let mut context = Context::from_waker(&waker);

                    if let Poll::Ready(()) = Pin::new(waiter).poll(&mut context) {
                        tracker.record_waiter_state(i, WaiterState::Ready);
                    }
                }
            }

            // Validate that we didn't wake more than the number of available waiters
            let ready_count = tracker.get_ready_count();
            let max_possible = config.waiter_count as usize;
            assert!(
                ready_count <= max_possible,
                "Rapid notify_one woke too many: {} > {}",
                ready_count,
                max_possible
            );
        }
    }

    // Final validation: check that we haven't violated the fundamental notify_one() invariant
    // (this varies by pattern, but we should never wake more waiters than we have)
    let final_ready = tracker.get_ready_count();
    let total_waiters = config.waiter_count as usize;
    assert!(
        final_ready <= total_waiters,
        "Final invariant violation: {} ready waiters > {} total",
        final_ready,
        total_waiters
    );
});
