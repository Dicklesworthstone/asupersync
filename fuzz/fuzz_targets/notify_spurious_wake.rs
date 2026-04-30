#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::future::Future;
use std::pin::Pin;
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

use asupersync::sync::Notify;

#[derive(Debug, Clone)]
struct SpuriousWakeTracker {
    operations: Arc<Mutex<Vec<String>>>,
    poll_results: Arc<Mutex<Vec<PollResult>>>,
    spurious_wakes: Arc<Mutex<Vec<SpuriousWake>>>,
}

#[derive(Debug, Clone)]
struct PollResult {
    waiter_id: usize,
    poll_attempt: usize,
    result: PollOutcome,
    operation_id: usize,
    notify_sent_before: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum PollOutcome {
    Pending,
    Ready,
}

#[derive(Debug, Clone)]
struct SpuriousWake {
    waiter_id: usize,
    poll_attempt: usize,
    operation_id: usize,
    description: String,
}

impl SpuriousWakeTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(Mutex::new(Vec::new())),
            poll_results: Arc::new(Mutex::new(Vec::new())),
            spurious_wakes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_poll_result(&self, result: PollResult) {
        if let Ok(mut results) = self.poll_results.lock() {
            results.push(result);
        }
    }

    fn record_spurious_wake(&self, wake: SpuriousWake) {
        if let Ok(mut wakes) = self.spurious_wakes.lock() {
            wakes.push(wake);
        }
    }

    fn validate_no_spurious_wakes(&self) {
        if let Ok(results) = self.poll_results.lock() {
            for result in results.iter() {
                // Core invariant: without notify, polling should stay Pending
                if !result.notify_sent_before && result.result == PollOutcome::Ready {
                    self.record_spurious_wake(SpuriousWake {
                        waiter_id: result.waiter_id,
                        poll_attempt: result.poll_attempt,
                        operation_id: result.operation_id,
                        description: format!(
                            "Waiter {} became Ready on poll attempt {} without prior notification",
                            result.waiter_id, result.poll_attempt
                        ),
                    });
                }
            }
        }

        // Check for any spurious wakes and panic if found
        if let Ok(wakes) = self.spurious_wakes.lock() {
            if !wakes.is_empty() {
                for wake in wakes.iter() {
                    self.record_operation(&format!(
                        "SPURIOUS_WAKE: Waiter {} - {}",
                        wake.waiter_id, wake.description
                    ));
                }
                panic!("Spurious wake violations detected: {} spurious wakes", wakes.len());
            }
        }
    }
}

struct TrackedWaker {
    waiter_id: usize,
    tracker: SpuriousWakeTracker,
    waked: Arc<Mutex<bool>>,
}

impl TrackedWaker {
    fn new(waiter_id: usize, tracker: SpuriousWakeTracker) -> Self {
        Self {
            waiter_id,
            tracker,
            waked: Arc::new(Mutex::new(false)),
        }
    }

    fn was_waked(&self) -> bool {
        if let Ok(waked) = self.waked.lock() {
            *waked
        } else {
            false
        }
    }

    fn create_waker(&self) -> Waker {
        let data = Arc::new(self.clone());
        let raw = RawWaker::new(
            Arc::into_raw(data) as *const (),
            &TRACKED_WAKER_VTABLE,
        );
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
    std::mem::forget(arc);
    let new_data = Arc::into_raw(cloned) as *const ();
    RawWaker::new(new_data, &TRACKED_WAKER_VTABLE)
}

unsafe fn tracked_waker_wake(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker.record_operation(&format!("waker_wake_{}", arc.waiter_id));
}

unsafe fn tracked_waker_wake_by_ref(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker.record_operation(&format!("waker_wake_by_ref_{}", arc.waiter_id));
    std::mem::forget(arc);
}

unsafe fn tracked_waker_drop(data: *const ()) {
    let _arc = Arc::from_raw(data as *const TrackedWaker);
}

#[derive(Debug, Clone, Arbitrary)]
struct SpuriousWakeConfig {
    waiter_count: u8,
    pattern: SpuriousPattern,
}

#[derive(Debug, Clone, Arbitrary)]
enum SpuriousPattern {
    SimplePollWithoutNotify,
    RepeatedPolls { poll_count: u8 },
    MultipleWaitersNoNotify { waiters: u8 },
    InterleavedPollsNoNotify { interleaving: Vec<Operation> },
    ConcurrentPollingNoNotify { thread_count: u8, polls_per_thread: u8 },
    MixedNotifyAndNonNotify { notify_some: bool, notify_count: u8 },
    PollingAfterOperations { operations: Vec<NonNotifyOperation> },
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    PollWaiter { waiter_id: u8 },
    CreateWaiter { waiter_id: u8 },
    DropWaiter { waiter_id: u8 },
    CheckWaiterCount,
    Sleep { duration_us: u16 },
}

#[derive(Debug, Clone, Arbitrary)]
enum NonNotifyOperation {
    RegisterWaiter,
    CancelWaiter { waiter_id: u8 },
    MultiPoll { waiter_id: u8, count: u8 },
    CheckStoredNotifications,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: SpuriousWakeConfig = u.arbitrary().unwrap_or(SpuriousWakeConfig {
        waiter_count: 3,
        pattern: SpuriousPattern::SimplePollWithoutNotify,
    });

    // Limit the number of waiters to prevent excessive test time
    if config.waiter_count == 0 || config.waiter_count > 8 {
        return;
    }

    let tracker = SpuriousWakeTracker::new();
    let notify = Arc::new(Notify::new());

    // Execute the pattern
    match config.pattern {
        SpuriousPattern::SimplePollWithoutNotify => {
            test_simple_poll_without_notify(&tracker, &notify, config.waiter_count);
        }

        SpuriousPattern::RepeatedPolls { poll_count } => {
            test_repeated_polls(&tracker, &notify, config.waiter_count, poll_count.min(10));
        }

        SpuriousPattern::MultipleWaitersNoNotify { waiters } => {
            test_multiple_waiters_no_notify(&tracker, &notify, waiters.min(8).max(1));
        }

        SpuriousPattern::InterleavedPollsNoNotify { interleaving } => {
            test_interleaved_polls_no_notify(&tracker, &notify, config.waiter_count, interleaving);
        }

        SpuriousPattern::ConcurrentPollingNoNotify { thread_count, polls_per_thread } => {
            test_concurrent_polling_no_notify(&tracker, &notify, config.waiter_count,
                                             thread_count.min(6), polls_per_thread.min(5));
        }

        SpuriousPattern::MixedNotifyAndNonNotify { notify_some, notify_count } => {
            test_mixed_notify_and_non_notify(&tracker, &notify, config.waiter_count,
                                            notify_some, notify_count.min(5));
        }

        SpuriousPattern::PollingAfterOperations { operations } => {
            test_polling_after_operations(&tracker, &notify, config.waiter_count, operations);
        }
    }

    // Validate no spurious wakes occurred
    tracker.validate_no_spurious_wakes();
});

fn test_simple_poll_without_notify(tracker: &SpuriousWakeTracker, notify: &Notify, waiter_count: u8) {
    tracker.record_operation("test_simple_poll_without_notify");

    let mut waiters = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create waiters
    for i in 0..waiter_count {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.push(waiter);
        tracked_wakers.push(tracked_waker);
    }

    // Poll each waiter once - should all be Pending
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = tracked_wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);

        let poll_result = Pin::new(waiter).poll(&mut context);
        let outcome = match poll_result {
            Poll::Ready(()) => PollOutcome::Ready,
            Poll::Pending => PollOutcome::Pending,
        };

        tracker.record_poll_result(PollResult {
            waiter_id: i,
            poll_attempt: 1,
            result: outcome,
            operation_id: 1,
            notify_sent_before: false, // No notify was sent
        });
    }
}

fn test_repeated_polls(tracker: &SpuriousWakeTracker, notify: &Notify, waiter_count: u8, poll_count: u8) {
    tracker.record_operation("test_repeated_polls");

    let mut waiters = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create waiters
    for i in 0..waiter_count {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.push(waiter);
        tracked_wakers.push(tracked_waker);
    }

    // Poll each waiter multiple times - all should stay Pending
    for poll_attempt in 1..=poll_count {
        for (i, waiter) in waiters.iter_mut().enumerate() {
            let waker = tracked_wakers[i].create_waker();
            let mut context = Context::from_waker(&waker);

            let poll_result = Pin::new(waiter).poll(&mut context);
            let outcome = match poll_result {
                Poll::Ready(()) => PollOutcome::Ready,
                Poll::Pending => PollOutcome::Pending,
            };

            tracker.record_poll_result(PollResult {
                waiter_id: i,
                poll_attempt: poll_attempt as usize,
                result: outcome,
                operation_id: 2,
                notify_sent_before: false,
            });
        }
    }
}

fn test_multiple_waiters_no_notify(tracker: &SpuriousWakeTracker, notify: &Notify, waiter_count: u8) {
    tracker.record_operation("test_multiple_waiters_no_notify");

    let mut waiters = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create many waiters
    for i in 0..waiter_count {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.push(waiter);
        tracked_wakers.push(tracked_waker);
    }

    // Poll all waiters - should all be Pending
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = tracked_wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);

        let poll_result = Pin::new(waiter).poll(&mut context);
        let outcome = match poll_result {
            Poll::Ready(()) => PollOutcome::Ready,
            Poll::Pending => PollOutcome::Pending,
        };

        tracker.record_poll_result(PollResult {
            waiter_id: i,
            poll_attempt: 1,
            result: outcome,
            operation_id: 3,
            notify_sent_before: false,
        });
    }
}

fn test_interleaved_polls_no_notify(
    tracker: &SpuriousWakeTracker,
    notify: &Notify,
    waiter_count: u8,
    operations: Vec<Operation>
) {
    tracker.record_operation("test_interleaved_polls_no_notify");

    let mut waiters = HashMap::new();
    let mut tracked_wakers = HashMap::new();
    let mut poll_attempts = HashMap::new();

    // Pre-create initial waiters
    for i in 0..waiter_count.min(4) {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.insert(i as usize, waiter);
        tracked_wakers.insert(i as usize, tracked_waker);
        poll_attempts.insert(i as usize, 0);
    }

    // Execute operations - NO notify operations
    for operation in operations.iter().take(20) {
        match operation {
            Operation::PollWaiter { waiter_id } => {
                let waiter_idx = (*waiter_id as usize) % waiters.len().max(1);
                if let (Some(waiter), Some(tracked_waker)) =
                    (waiters.get_mut(&waiter_idx), tracked_wakers.get(&waiter_idx)) {

                    let attempt_num = poll_attempts.get_mut(&waiter_idx).unwrap();
                    *attempt_num += 1;

                    let waker = tracked_waker.create_waker();
                    let mut context = Context::from_waker(&waker);

                    let poll_result = Pin::new(waiter).poll(&mut context);
                    let outcome = match poll_result {
                        Poll::Ready(()) => PollOutcome::Ready,
                        Poll::Pending => PollOutcome::Pending,
                    };

                    tracker.record_poll_result(PollResult {
                        waiter_id: waiter_idx,
                        poll_attempt: *attempt_num,
                        result: outcome,
                        operation_id: 4,
                        notify_sent_before: false,
                    });
                }
            }

            Operation::CreateWaiter { waiter_id } => {
                let waiter_idx = *waiter_id as usize;
                if !waiters.contains_key(&waiter_idx) && waiters.len() < 8 {
                    let waiter = notify.notified();
                    let tracked_waker = TrackedWaker::new(waiter_idx, tracker.clone());
                    waiters.insert(waiter_idx, waiter);
                    tracked_wakers.insert(waiter_idx, tracked_waker);
                    poll_attempts.insert(waiter_idx, 0);
                }
            }

            Operation::DropWaiter { waiter_id } => {
                let waiter_idx = (*waiter_id as usize) % waiters.len().max(1);
                waiters.remove(&waiter_idx);
                tracked_wakers.remove(&waiter_idx);
                poll_attempts.remove(&waiter_idx);
            }

            Operation::CheckWaiterCount => {
                let count = notify.waiter_count();
                tracker.record_operation(&format!("waiter_count_{}", count));
            }

            Operation::Sleep { duration_us } => {
                if *duration_us > 0 {
                    thread::sleep(Duration::from_micros((*duration_us).min(1000) as u64));
                }
            }
        }
    }
}

fn test_concurrent_polling_no_notify(
    tracker: &SpuriousWakeTracker,
    notify: &Notify,
    waiter_count: u8,
    thread_count: u8,
    polls_per_thread: u8
) {
    tracker.record_operation("test_concurrent_polling_no_notify");

    let mut waiters = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create waiters
    for i in 0..waiter_count {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.push(waiter);
        tracked_wakers.push(tracked_waker);
    }

    // Poll all waiters once to register them
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = tracked_wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);
        let _ = Pin::new(waiter).poll(&mut context);
    }

    let notify = Arc::new(notify);
    let mut handles = Vec::new();

    // Spawn threads that poll without notify
    for thread_id in 0..thread_count {
        let notify_clone = Arc::clone(notify);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            for poll_num in 1..=polls_per_thread {
                let waiter = notify_clone.notified();
                let tracked_waker = TrackedWaker::new(
                    (thread_id as usize) * 100 + (poll_num as usize),
                    tracker_clone.clone()
                );

                // Create and poll the waiter
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);
                let mut waiter = waiter;

                let poll_result = Pin::new(&mut waiter).poll(&mut context);
                let outcome = match poll_result {
                    Poll::Ready(()) => PollOutcome::Ready,
                    Poll::Pending => PollOutcome::Pending,
                };

                tracker_clone.record_poll_result(PollResult {
                    waiter_id: tracked_waker.waiter_id,
                    poll_attempt: poll_num as usize,
                    result: outcome,
                    operation_id: 5,
                    notify_sent_before: false,
                });
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }
}

fn test_mixed_notify_and_non_notify(
    tracker: &SpuriousWakeTracker,
    notify: &Notify,
    waiter_count: u8,
    notify_some: bool,
    notify_count: u8
) {
    tracker.record_operation("test_mixed_notify_and_non_notify");

    let mut waiters = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create waiters
    for i in 0..waiter_count {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.push(waiter);
        tracked_wakers.push(tracked_waker);
    }

    // Poll all waiters to register them
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = tracked_wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);
        let _ = Pin::new(waiter).poll(&mut context);
    }

    let mut notifications_sent = 0;

    // Optionally send some notifications
    if notify_some {
        for _ in 0..notify_count.min(waiter_count) {
            notify.notify_one();
            notifications_sent += 1;
            tracker.record_operation(&format!("notify_one_{}", notifications_sent));
        }
    }

    // Poll all waiters and record results
    for (i, waiter) in waiters.iter_mut().enumerate() {
        let waker = tracked_wakers[i].create_waker();
        let mut context = Context::from_waker(&waker);

        let poll_result = Pin::new(waiter).poll(&mut context);
        let outcome = match poll_result {
            Poll::Ready(()) => PollOutcome::Ready,
            Poll::Pending => PollOutcome::Pending,
        };

        // Only the first `notifications_sent` waiters should be Ready
        let should_be_notified = notify_some && (i < notifications_sent as usize);

        tracker.record_poll_result(PollResult {
            waiter_id: i,
            poll_attempt: 1,
            result: outcome,
            operation_id: 6,
            notify_sent_before: should_be_notified,
        });
    }
}

fn test_polling_after_operations(
    tracker: &SpuriousWakeTracker,
    notify: &Notify,
    waiter_count: u8,
    operations: Vec<NonNotifyOperation>
) {
    tracker.record_operation("test_polling_after_operations");

    let mut waiters = HashMap::new();
    let mut tracked_wakers = HashMap::new();

    // Create initial waiters
    for i in 0..waiter_count.min(4) {
        let waiter = notify.notified();
        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        waiters.insert(i as usize, waiter);
        tracked_wakers.insert(i as usize, tracked_waker);
    }

    // Execute non-notify operations
    for operation in operations.iter().take(15) {
        match operation {
            NonNotifyOperation::RegisterWaiter => {
                if waiters.len() < 8 {
                    let waiter_id = waiters.len();
                    let waiter = notify.notified();
                    let tracked_waker = TrackedWaker::new(waiter_id, tracker.clone());

                    // Register the waiter by polling once
                    let waker = tracked_waker.create_waker();
                    let mut context = Context::from_waker(&waker);
                    let mut waiter = waiter;
                    let _ = Pin::new(&mut waiter).poll(&mut context);

                    waiters.insert(waiter_id, waiter);
                    tracked_wakers.insert(waiter_id, tracked_waker);
                }
            }

            NonNotifyOperation::CancelWaiter { waiter_id } => {
                let waiter_idx = (*waiter_id as usize) % waiters.len().max(1);
                waiters.remove(&waiter_idx);
                tracked_wakers.remove(&waiter_idx);
            }

            NonNotifyOperation::MultiPoll { waiter_id, count } => {
                let waiter_idx = (*waiter_id as usize) % waiters.len().max(1);
                if let (Some(waiter), Some(tracked_waker)) =
                    (waiters.get_mut(&waiter_idx), tracked_wakers.get(&waiter_idx)) {

                    for poll_attempt in 1..=(*count).min(5) {
                        let waker = tracked_waker.create_waker();
                        let mut context = Context::from_waker(&waker);

                        let poll_result = Pin::new(waiter).poll(&mut context);
                        let outcome = match poll_result {
                            Poll::Ready(()) => PollOutcome::Ready,
                            Poll::Pending => PollOutcome::Pending,
                        };

                        tracker.record_poll_result(PollResult {
                            waiter_id: waiter_idx,
                            poll_attempt: poll_attempt as usize,
                            result: outcome,
                            operation_id: 7,
                            notify_sent_before: false,
                        });
                    }
                }
            }

            NonNotifyOperation::CheckStoredNotifications => {
                let stored = notify.stored_notifications.load(std::sync::atomic::Ordering::Acquire);
                tracker.record_operation(&format!("stored_notifications_{}", stored));
            }
        }
    }

    // Final poll of all remaining waiters - should all be Pending
    for (waiter_id, waiter) in waiters.iter_mut() {
        if let Some(tracked_waker) = tracked_wakers.get(waiter_id) {
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            let poll_result = Pin::new(waiter).poll(&mut context);
            let outcome = match poll_result {
                Poll::Ready(()) => PollOutcome::Ready,
                Poll::Pending => PollOutcome::Pending,
            };

            tracker.record_poll_result(PollResult {
                waiter_id: *waiter_id,
                poll_attempt: 99, // Final poll marker
                result: outcome,
                operation_id: 7,
                notify_sent_before: false,
            });
        }
    }
}