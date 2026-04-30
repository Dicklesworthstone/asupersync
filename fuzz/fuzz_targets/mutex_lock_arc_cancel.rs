#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::collections::HashMap;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::future::Future;
use std::pin::Pin;

use asupersync::sync::{Mutex, OwnedMutexGuard, LockError};
use asupersync::cx::Cx;
use asupersync::cx::cap;
use asupersync::types::CancelKind;

// TrackedWaker implementation for manual polling
#[derive(Debug)]
struct TrackedWaker {
    context_id: usize,
    operation_id: usize,
    tracker: LockArcCancelTracker,
}

impl TrackedWaker {
    fn new(context_id: usize, operation_id: usize, tracker: LockArcCancelTracker) -> Self {
        Self { context_id, operation_id, tracker }
    }

    fn create_waker(&self) -> Waker {
        unsafe fn wake(_ptr: *const ()) {
            // Wake implementation for testing - just record that wake was called
        }

        unsafe fn wake_by_ref(_: *const ()) {
            // Wake by ref implementation
        }

        unsafe fn clone(ptr: *const ()) -> RawWaker {
            RawWaker::new(ptr, &WAKER_VTABLE)
        }

        unsafe fn drop(_: *const ()) {
            // Drop implementation
        }

        static WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        let raw = RawWaker::new(self as *const _ as *const (), &WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}

#[derive(Debug, Clone)]
struct LockArcCancelTracker {
    operations: Arc<StdMutex<Vec<String>>>,
    lock_attempts: Arc<StdMutex<Vec<LockAttemptResult>>>,
    invariant_violations: Arc<StdMutex<Vec<InvariantViolation>>>,
}

#[derive(Debug, Clone)]
struct LockAttemptResult {
    operation_id: usize,
    result: LockOutcome,
    cancel_timing: CancelTiming,
    waiters_before: usize,
    waiters_after: usize,
    locked_before: bool,
    locked_after: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum LockOutcome {
    Success,
    Cancelled,
    Poisoned,
    PolledAfterCompletion,
    Panicked,
}

#[derive(Debug, Clone, PartialEq)]
enum CancelTiming {
    BeforePoll,
    DuringPoll,
    AfterPoll,
    NeverCancelled,
}

#[derive(Debug, Clone)]
struct InvariantViolation {
    violation_type: String,
    description: String,
    operation_id: usize,
}

impl LockArcCancelTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(StdMutex::new(Vec::new())),
            lock_attempts: Arc::new(StdMutex::new(Vec::new())),
            invariant_violations: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_lock_attempt(&self, result: LockAttemptResult) {
        if let Ok(mut attempts) = self.lock_attempts.lock() {
            attempts.push(result);
        }
    }

    fn record_violation(&self, violation: InvariantViolation) {
        if let Ok(mut violations) = self.invariant_violations.lock() {
            violations.push(violation);
        }
    }

    fn validate_lock_cancel_invariants(&self) {
        if let Ok(attempts) = self.lock_attempts.lock() {
            for attempt in attempts.iter() {
                // Invariant: waiter count should not increase after cancellation
                if attempt.result == LockOutcome::Cancelled {
                    if attempt.waiters_after > attempt.waiters_before {
                        self.record_violation(InvariantViolation {
                            violation_type: "waiter_leak_on_cancel".to_string(),
                            description: format!(
                                "Operation {}: waiters increased from {} to {} after cancellation",
                                attempt.operation_id, attempt.waiters_before, attempt.waiters_after
                            ),
                            operation_id: attempt.operation_id,
                        });
                    }
                }

                // Invariant: no panics should occur during lock_arc operations
                if attempt.result == LockOutcome::Panicked {
                    self.record_violation(InvariantViolation {
                        violation_type: "panic_during_lock_arc".to_string(),
                        description: format!(
                            "Operation {} panicked during lock_arc operation",
                            attempt.operation_id
                        ),
                        operation_id: attempt.operation_id,
                    });
                }

                // Invariant: successful lock should not change waiter count unexpectedly
                if attempt.result == LockOutcome::Success {
                    // A successful lock might decrease waiters if this waiter was queued
                    if attempt.waiters_after > attempt.waiters_before + 1 {
                        self.record_violation(InvariantViolation {
                            violation_type: "waiter_count_anomaly_on_success".to_string(),
                            description: format!(
                                "Operation {}: waiters unexpectedly increased from {} to {} on success",
                                attempt.operation_id, attempt.waiters_before, attempt.waiters_after
                            ),
                            operation_id: attempt.operation_id,
                        });
                    }
                }
            }
        }

        // Check for any violations and panic if found
        if let Ok(violations) = self.invariant_violations.lock() {
            if !violations.is_empty() {
                for violation in violations.iter() {
                    self.record_operation(&format!(
                        "VIOLATION: {} - {}",
                        violation.violation_type, violation.description
                    ));
                }
                panic!("Mutex lock_arc cancel invariant violations detected: {} violations", violations.len());
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct LockArcCancelConfig {
    pattern: CancelPattern,
    concurrent_count: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum CancelPattern {
    SimpleLockCancel,
    ConcurrentLockCancel { delays: Vec<u16> },
    SequentialLockCancel { attempts: u8 },
    InterleavedLockCancel { operations: Vec<Operation> },
    RapidCancelSequence { sequence: Vec<RapidOp> },
    HoldAndCancel { hold_duration_us: u16, cancel_delay_us: u16 },
    MultiContextCancel { context_count: u8, cancel_pattern: Vec<bool> },
}

#[derive(Debug, Clone, Arbitrary)]
enum Operation {
    StartLock { context_id: u8 },
    CancelContext { context_id: u8 },
    Sleep { duration_us: u16 },
    CheckState,
    TryLock,
}

#[derive(Debug, Clone, Arbitrary)]
enum RapidOp {
    Lock { context_id: u8 },
    Cancel { context_id: u8 },
    CheckWaiters,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: LockArcCancelConfig = u.arbitrary().unwrap_or(LockArcCancelConfig {
        pattern: CancelPattern::SimpleLockCancel,
        concurrent_count: 3,
    });

    // Limit concurrent operations to prevent excessive resource usage
    if config.concurrent_count == 0 || config.concurrent_count > 8 {
        return;
    }

    let tracker = LockArcCancelTracker::new();

    // Execute the pattern
    match config.pattern {
        CancelPattern::SimpleLockCancel => {
            test_simple_lock_cancel(&tracker);
        }

        CancelPattern::ConcurrentLockCancel { delays } => {
            test_concurrent_lock_cancel(&tracker, &delays, config.concurrent_count);
        }

        CancelPattern::SequentialLockCancel { attempts } => {
            test_sequential_lock_cancel(&tracker, attempts.min(10));
        }

        CancelPattern::InterleavedLockCancel { operations } => {
            test_interleaved_lock_cancel(&tracker, operations);
        }

        CancelPattern::RapidCancelSequence { sequence } => {
            test_rapid_cancel_sequence(&tracker, sequence);
        }

        CancelPattern::HoldAndCancel { hold_duration_us, cancel_delay_us } => {
            test_hold_and_cancel(&tracker, hold_duration_us, cancel_delay_us);
        }

        CancelPattern::MultiContextCancel { context_count, cancel_pattern } => {
            test_multi_context_cancel(&tracker, context_count.min(6), cancel_pattern);
        }
    }

    // Validate all invariants
    tracker.validate_lock_cancel_invariants();
});

fn test_simple_lock_cancel(tracker: &LockArcCancelTracker) {
    tracker.record_operation("test_simple_lock_cancel");

    let mutex = Arc::new(Mutex::new(42u32));
    let cx = Cx::<cap::All>::for_testing();

    let waiters_before = mutex.waiters();
    let locked_before = mutex.is_locked();

    // Cancel the context before attempting lock
    cx.cancel_fast(CancelKind::User);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mutex_clone = Arc::clone(&mutex);
        let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, &cx));
        let tracked_waker = TrackedWaker::new(0, 1, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        // Poll the lock future once
        match lock_future.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
        }
    }));

    let waiters_after = mutex.waiters();
    let locked_after = mutex.is_locked();

    let outcome = match result {
        Ok(Ok(_guard)) => LockOutcome::Success,
        Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
        Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
        Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
        Err(_) => LockOutcome::Panicked,
    };

    tracker.record_lock_attempt(LockAttemptResult {
        operation_id: 1,
        result: outcome,
        cancel_timing: CancelTiming::BeforePoll,
        waiters_before,
        waiters_after,
        locked_before,
        locked_after,
    });
}

fn test_concurrent_lock_cancel(tracker: &LockArcCancelTracker, delays: &[u16], concurrent_count: u8) {
    tracker.record_operation("test_concurrent_lock_cancel");

    let mutex = Arc::new(Mutex::new(42u32));
    let mut handles = Vec::new();

    // Start multiple concurrent lock attempts
    for i in 0..concurrent_count.min(6) {
        let mutex_clone = Arc::clone(&mutex);
        let tracker_clone = tracker.clone();
        let delay_us = delays.get(i as usize).copied().unwrap_or(0).min(1000);

        let handle = thread::spawn(move || {
            let cx = Cx::<cap::All>::for_testing();

            let waiters_before = mutex_clone.waiters();
            let locked_before = mutex_clone.is_locked();

            // Delay before attempting lock
            if delay_us > 0 {
                thread::sleep(Duration::from_micros(delay_us as u64));
            }

            // Cancel context after half the operations start
            if i >= concurrent_count / 2 {
                cx.cancel_fast(CancelKind::User);
            }

            let result = catch_unwind(AssertUnwindSafe(|| {
                let mutex_for_lock = Arc::clone(&mutex_clone);
                let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_for_lock, &cx));
                let tracked_waker = TrackedWaker::new(i as usize, i as usize + 1, tracker_clone.clone());
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);

                // Poll the lock future once
                match lock_future.as_mut().poll(&mut context) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
                }
            }));

            let waiters_after = mutex_clone.waiters();
            let locked_after = mutex_clone.is_locked();

            let outcome = match result {
                Ok(Ok(_guard)) => LockOutcome::Success,
                Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
                Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
                Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
                Err(_) => LockOutcome::Panicked,
            };

            let cancel_timing = if i >= concurrent_count / 2 {
                CancelTiming::BeforePoll
            } else {
                CancelTiming::NeverCancelled
            };

            tracker_clone.record_lock_attempt(LockAttemptResult {
                operation_id: i as usize + 1,
                result: outcome,
                cancel_timing,
                waiters_before,
                waiters_after,
                locked_before,
                locked_after,
            });
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }
}

fn test_sequential_lock_cancel(tracker: &LockArcCancelTracker, attempts: u8) {
    tracker.record_operation("test_sequential_lock_cancel");

    let mutex = Arc::new(Mutex::new(42u32));

    for i in 0..attempts {
        let cx = Cx::<cap::All>::for_testing();
        let waiters_before = mutex.waiters();
        let locked_before = mutex.is_locked();

        // Cancel every other attempt
        let should_cancel = i % 2 == 1;
        if should_cancel {
            cx.cancel_fast(CancelKind::User);
        }

        let result = catch_unwind(AssertUnwindSafe(|| {
            let mutex_clone = Arc::clone(&mutex);
            let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, &cx));
            let tracked_waker = TrackedWaker::new(0, i as usize + 1, tracker.clone());
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            // Poll the lock future once
            match lock_future.as_mut().poll(&mut context) {
                Poll::Ready(result) => result,
                Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
            }
        }));

        let waiters_after = mutex.waiters();
        let locked_after = mutex.is_locked();

        let outcome = match result {
            Ok(Ok(_guard)) => LockOutcome::Success,
            Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
            Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
            Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
            Err(_) => LockOutcome::Panicked,
        };

        let cancel_timing = if should_cancel {
            CancelTiming::BeforePoll
        } else {
            CancelTiming::NeverCancelled
        };

        tracker.record_lock_attempt(LockAttemptResult {
            operation_id: i as usize + 1,
            result: outcome,
            cancel_timing,
            waiters_before,
            waiters_after,
            locked_before,
            locked_after,
        });
    }
}

fn test_interleaved_lock_cancel(tracker: &LockArcCancelTracker, operations: Vec<Operation>) {
    tracker.record_operation("test_interleaved_lock_cancel");

    let mutex = Arc::new(Mutex::new(42u32));
    let mut contexts: HashMap<u8, Cx<cap::All>> = HashMap::new();
    let mut operation_id = 0;

    for operation in operations.iter().take(20) {
        operation_id += 1;

        match operation {
            Operation::StartLock { context_id } => {
                let cx = contexts.entry(*context_id).or_insert_with(|| Cx::<cap::All>::new());

                let waiters_before = mutex.waiters();
                let locked_before = mutex.is_locked();

                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mutex_clone = Arc::clone(&mutex);
                    let cx_ref = &*cx;
                    let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, cx_ref));
                    let tracked_waker = TrackedWaker::new(*context_id as usize, operation_id, tracker.clone());
                    let waker = tracked_waker.create_waker();
                    let mut context = Context::from_waker(&waker);

                    // Poll the lock future once
                    match lock_future.as_mut().poll(&mut context) {
                        Poll::Ready(result) => result,
                        Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
                    }
                }));

                let waiters_after = mutex.waiters();
                let locked_after = mutex.is_locked();

                let outcome = match result {
                    Ok(Ok(_guard)) => LockOutcome::Success,
                    Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
                    Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
                    Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
                    Err(_) => LockOutcome::Panicked,
                };

                let cancel_timing = if cx.is_cancel_requested() {
                    CancelTiming::BeforePoll
                } else {
                    CancelTiming::NeverCancelled
                };

                tracker.record_lock_attempt(LockAttemptResult {
                    operation_id,
                    result: outcome,
                    cancel_timing,
                    waiters_before,
                    waiters_after,
                    locked_before,
                    locked_after,
                });
            }

            Operation::CancelContext { context_id } => {
                if let Some(cx) = contexts.get(context_id) {
                    cx.cancel_fast(CancelKind::User);
                    tracker.record_operation(&format!("cancelled_context_{}", context_id));
                }
            }

            Operation::Sleep { duration_us } => {
                if *duration_us > 0 {
                    thread::sleep(Duration::from_micros((*duration_us).min(500) as u64));
                }
            }

            Operation::CheckState => {
                let waiters = mutex.waiters();
                let locked = mutex.is_locked();
                let poisoned = mutex.is_poisoned();
                tracker.record_operation(&format!("state_check_waiters_{}_locked_{}_poisoned_{}",
                    waiters, locked, poisoned));
            }

            Operation::TryLock => {
                let try_result = catch_unwind(AssertUnwindSafe(|| {
                    mutex.try_lock()
                }));

                match try_result {
                    Ok(Ok(_guard)) => {
                        tracker.record_operation("try_lock_success");
                        // Guard automatically released when dropped
                    }
                    Ok(Err(_)) => {
                        tracker.record_operation("try_lock_failed");
                    }
                    Err(_) => {
                        tracker.record_operation("try_lock_panicked");
                    }
                }
            }
        }
    }
}

fn test_rapid_cancel_sequence(tracker: &LockArcCancelTracker, sequence: Vec<RapidOp>) {
    tracker.record_operation("test_rapid_cancel_sequence");

    let mutex = Arc::new(Mutex::new(42u32));
    let mut contexts: HashMap<u8, Cx<cap::All>> = HashMap::new();
    let mut operation_id = 0;

    for op in sequence.iter().take(15) {
        operation_id += 1;

        match op {
            RapidOp::Lock { context_id } => {
                let cx = contexts.entry(*context_id).or_insert_with(|| Cx::<cap::All>::new());

                let waiters_before = mutex.waiters();
                let locked_before = mutex.is_locked();

                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mutex_clone = Arc::clone(&mutex);
                    let cx_ref = &*cx;
                    let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, cx_ref));
                    let tracked_waker = TrackedWaker::new(*context_id as usize, operation_id, tracker.clone());
                    let waker = tracked_waker.create_waker();
                    let mut context = Context::from_waker(&waker);

                    // Poll the lock future once
                    match lock_future.as_mut().poll(&mut context) {
                        Poll::Ready(result) => result,
                        Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
                    }
                }));

                let waiters_after = mutex.waiters();
                let locked_after = mutex.is_locked();

                let outcome = match result {
                    Ok(Ok(_guard)) => LockOutcome::Success,
                    Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
                    Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
                    Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
                    Err(_) => LockOutcome::Panicked,
                };

                let cancel_timing = if cx.is_cancel_requested() {
                    CancelTiming::BeforePoll
                } else {
                    CancelTiming::NeverCancelled
                };

                tracker.record_lock_attempt(LockAttemptResult {
                    operation_id,
                    result: outcome,
                    cancel_timing,
                    waiters_before,
                    waiters_after,
                    locked_before,
                    locked_after,
                });
            }

            RapidOp::Cancel { context_id } => {
                if let Some(cx) = contexts.get(context_id) {
                    cx.cancel_fast(CancelKind::User);
                }
            }

            RapidOp::CheckWaiters => {
                let waiters = mutex.waiters();
                tracker.record_operation(&format!("rapid_waiters_{}", waiters));
            }
        }
    }
}

fn test_hold_and_cancel(tracker: &LockArcCancelTracker, hold_duration_us: u16, cancel_delay_us: u16) {
    tracker.record_operation("test_hold_and_cancel");

    let mutex = Arc::new(Mutex::new(42u32));

    // First, acquire the lock and hold it
    let holder_cx = Cx::<cap::All>::new();
    let guard = {
        let mutex_clone = Arc::clone(&mutex);
        let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, &holder_cx));
        let tracked_waker = TrackedWaker::new(0, 1, tracker.clone());
        let waker = tracked_waker.create_waker();
        let mut context = Context::from_waker(&waker);

        // Poll the lock future once
        match lock_future.as_mut().poll(&mut context) {
            Poll::Ready(result) => result.ok(),
            Poll::Pending => None, // Treat pending as None for testing
        }
    };

    if guard.is_some() {
        tracker.record_operation("holder_acquired_lock");

        // Start a waiter that will be cancelled
        let waiter_cx = Cx::<cap::All>::new();
        let tracker_clone = tracker.clone();
        let mutex_clone = Arc::clone(&mutex);

        let waiter_handle = thread::spawn(move || {
            let waiters_before = mutex_clone.waiters();
            let locked_before = mutex_clone.is_locked();

            // Delay before cancelling
            if cancel_delay_us > 0 {
                thread::sleep(Duration::from_micros(cancel_delay_us.min(1000) as u64));
            }
            waiter_cx.cancel();

            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, &waiter_cx));
                let tracked_waker = TrackedWaker::new(1, 1, tracker_clone.clone());
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);

                // Poll the lock future once
                match lock_future.as_mut().poll(&mut context) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
                }
            }));

            let waiters_after = mutex_clone.waiters();
            let locked_after = mutex_clone.is_locked();

            let outcome = match result {
                Ok(Ok(_guard)) => LockOutcome::Success,
                Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
                Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
                Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
                Err(_) => LockOutcome::Panicked,
            };

            tracker_clone.record_lock_attempt(LockAttemptResult {
                operation_id: 1,
                result: outcome,
                cancel_timing: CancelTiming::DuringPoll,
                waiters_before,
                waiters_after,
                locked_before,
                locked_after,
            });
        });

        // Hold the lock for specified duration
        if hold_duration_us > 0 {
            thread::sleep(Duration::from_micros(hold_duration_us.min(2000) as u64));
        }

        // Release the lock by dropping guard
        drop(guard);
        tracker.record_operation("holder_released_lock");

        // Wait for waiter thread
        let _ = waiter_handle.join();
    }
}

fn test_multi_context_cancel(tracker: &LockArcCancelTracker, context_count: u8, cancel_pattern: Vec<bool>) {
    tracker.record_operation("test_multi_context_cancel");

    let mutex = Arc::new(Mutex::new(42u32));
    let mut handles = Vec::new();

    for i in 0..context_count {
        let should_cancel = cancel_pattern.get(i as usize).copied().unwrap_or(false);
        let mutex_clone = Arc::clone(&mutex);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            let cx = Cx::<cap::All>::for_testing();

            if should_cancel {
                cx.cancel_fast(CancelKind::User);
            }

            let waiters_before = mutex_clone.waiters();
            let locked_before = mutex_clone.is_locked();

            let result = catch_unwind(AssertUnwindSafe(|| {
                let mut lock_future = Box::pin(OwnedMutexGuard::lock(mutex_clone, &cx));
                let tracked_waker = TrackedWaker::new(i as usize, i as usize + 1, tracker_clone.clone());
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);

                // Poll the lock future once
                match lock_future.as_mut().poll(&mut context) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(LockError::Cancelled), // Treat pending as cancelled for testing
                }
            }));

            let waiters_after = mutex_clone.waiters();
            let locked_after = mutex_clone.is_locked();

            let outcome = match result {
                Ok(Ok(_guard)) => LockOutcome::Success,
                Ok(Err(LockError::Cancelled)) => LockOutcome::Cancelled,
                Ok(Err(LockError::Poisoned)) => LockOutcome::Poisoned,
                Ok(Err(LockError::PolledAfterCompletion)) => LockOutcome::PolledAfterCompletion,
                Err(_) => LockOutcome::Panicked,
            };

            let cancel_timing = if should_cancel {
                CancelTiming::BeforePoll
            } else {
                CancelTiming::NeverCancelled
            };

            tracker_clone.record_lock_attempt(LockAttemptResult {
                operation_id: i as usize + 1,
                result: outcome,
                cancel_timing,
                waiters_before,
                waiters_after,
                locked_before,
                locked_after,
            });
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }
}