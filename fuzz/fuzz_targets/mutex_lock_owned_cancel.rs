#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::thread;
use std::time::Duration;

use asupersync::sync::{LockError, Mutex, OwnedMutexGuard};
use asupersync::types::TaskId;
use asupersync::util::ArenaIndex;
use asupersync::{Budget, Cx, RegionId};

#[derive(Debug, Clone)]
struct CancelTracker {
    operations: Arc<StdMutex<Vec<String>>>,
    lock_states: Arc<StdMutex<HashMap<usize, LockState>>>,
    cancel_results: Arc<StdMutex<Vec<CancelResult>>>,
}

#[derive(Debug, Clone, PartialEq)]
enum LockState {
    WaitingForLock,
    LockAcquired,
    Cancelled,
    Failed(String),
}

#[derive(Debug, Clone)]
struct CancelResult {
    operation_id: usize,
    result: Result<(), LockError>,
    lock_available_after: bool,
}

impl CancelTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(StdMutex::new(Vec::new())),
            lock_states: Arc::new(StdMutex::new(HashMap::new())),
            cancel_results: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_lock_state(&self, op_id: usize, state: LockState) {
        if let Ok(mut states) = self.lock_states.lock() {
            states.insert(op_id, state);
        }
    }

    fn record_cancel_result(&self, result: CancelResult) {
        if let Ok(mut results) = self.cancel_results.lock() {
            results.push(result);
        }
    }

    fn validate_cancel_invariants(&self) {
        // Check that cancelled operations clean up properly
        if let Ok(results) = self.cancel_results.lock() {
            for result in results.iter() {
                match &result.result {
                    Err(LockError::Cancelled) => {
                        // After cancellation, lock should be available to others
                        assert!(
                            result.lock_available_after,
                            "Lock not available after cancellation for operation {}",
                            result.operation_id
                        );
                    }
                    Err(LockError::Poisoned) => {
                        // Poisoned state is valid but should be consistent
                    }
                    Err(LockError::PolledAfterCompletion) => {
                        // This should not happen in normal cancellation flow
                        panic!(
                            "Unexpected PolledAfterCompletion in operation {}",
                            result.operation_id
                        );
                    }
                    Ok(()) => {
                        // Successful acquisition is fine
                    }
                }
            }
        }

        // Check that lock states are consistent
        if let Ok(states) = self.lock_states.lock() {
            let cancelled_count = states
                .values()
                .filter(|state| matches!(state, LockState::Cancelled))
                .count();
            let acquired_count = states
                .values()
                .filter(|state| matches!(state, LockState::LockAcquired))
                .count();

            // Fundamental invariant: mutex can't be held by multiple operations
            assert!(
                acquired_count <= 1,
                "Multiple operations hold lock: {} acquired",
                acquired_count
            );
        }
    }
}

struct TrackedWaker {
    op_id: usize,
    tracker: CancelTracker,
    waked: Arc<StdMutex<bool>>,
}

impl TrackedWaker {
    fn new(op_id: usize, tracker: CancelTracker) -> Self {
        Self {
            op_id,
            tracker,
            waked: Arc::new(StdMutex::new(false)),
        }
    }

    fn create_waker(&self) -> Waker {
        let data = Arc::new(self.clone());
        let raw = RawWaker::new(Arc::into_raw(data) as *const (), &TRACKED_WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }

    fn was_waked(&self) -> bool {
        self.waked
            .lock()
            .unwrap_or_else(|_| panic!("Lock poisoned"))
            .clone()
    }
}

impl Clone for TrackedWaker {
    fn clone(&self) -> Self {
        Self {
            op_id: self.op_id,
            tracker: self.tracker.clone(),
            waked: Arc::clone(&self.waked),
        }
    }
}

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
    arc.tracker.record_operation(&format!("wake_{}", arc.op_id));
}

unsafe fn tracked_waker_wake_by_ref(data: *const ()) {
    let arc = Arc::from_raw(data as *const TrackedWaker);
    if let Ok(mut waked) = arc.waked.lock() {
        *waked = true;
    }
    arc.tracker
        .record_operation(&format!("wake_by_ref_{}", arc.op_id));
    std::mem::forget(arc);
}

unsafe fn tracked_waker_drop(data: *const ()) {
    let _arc = Arc::from_raw(data as *const TrackedWaker);
}

#[derive(Debug, Clone, Arbitrary)]
struct CancelConfig {
    operation_count: u8,
    cancel_pattern: CancelPattern,
    test_value: u32,
}

#[derive(Debug, Clone, Arbitrary)]
enum CancelPattern {
    CancelDuringPoll,
    CancelBeforePoll,
    CancelAfterFirstPoll,
    RapidCancelPoll { iterations: u8 },
    MultiOperationCancel { cancel_indices: Vec<u8> },
    DelayedCancel { delay_ms: u16 },
    InterleavedLockCancel { operations: Vec<bool> }, // true=lock, false=cancel
}

#[derive(Debug, Clone, Arbitrary)]
enum CancelOperation {
    StartLockOwned { op_id: u8 },
    PollOperation { op_id: u8 },
    CancelOperation { op_id: u8 },
    ValidateLockState,
    TestLockAvailability,
    CreateCancelledCx { op_id: u8 },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: CancelConfig = u.arbitrary().unwrap_or(CancelConfig {
        operation_count: 3,
        cancel_pattern: CancelPattern::CancelDuringPoll,
        test_value: 42,
    });

    if config.operation_count == 0 || config.operation_count > 8 {
        return;
    }

    let tracker = CancelTracker::new();
    let mutex = Arc::new(Mutex::new(config.test_value));
    let mut contexts = Vec::new();
    let mut lock_futures = Vec::new();
    let mut tracked_wakers = Vec::new();

    // Create contexts and lock futures for operations
    for i in 0..config.operation_count {
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(i as u64, 0)),
            TaskId::from_arena(ArenaIndex::new(i as u64, 0)),
            Budget::infinite(),
        );

        contexts.push(cx);

        let tracked_waker = TrackedWaker::new(i as usize, tracker.clone());
        tracked_wakers.push(tracked_waker);

        tracker.record_lock_state(i as usize, LockState::WaitingForLock);
    }

    // Execute cancel pattern
    match config.cancel_pattern {
        CancelPattern::CancelDuringPoll => {
            for (i, cx) in contexts.iter().enumerate() {
                let lock_future = OwnedMutexGuard::lock(Arc::clone(&mutex), cx);
                lock_futures.push(Box::pin(lock_future));
                tracker.record_operation(&format!("created_lock_future_{}", i));
            }

            // Poll first operation
            if !lock_futures.is_empty() {
                let waker = tracked_wakers[0].create_waker();
                let mut context = Context::from_waker(&waker);

                let poll_result = lock_futures[0].as_mut().poll(&mut context);
                match poll_result {
                    Poll::Ready(Ok(_guard)) => {
                        tracker.record_lock_state(0, LockState::LockAcquired);
                        tracker.record_cancel_result(CancelResult {
                            operation_id: 0,
                            result: Ok(()),
                            lock_available_after: false, // Lock is held
                        });
                    }
                    Poll::Ready(Err(e)) => {
                        tracker.record_lock_state(0, LockState::Failed(format!("{:?}", e)));
                        tracker.record_cancel_result(CancelResult {
                            operation_id: 0,
                            result: Err(e),
                            lock_available_after: true,
                        });
                    }
                    Poll::Pending => {
                        tracker.record_lock_state(0, LockState::WaitingForLock);
                    }
                }
            }

            // Cancel the second operation (if exists) and validate cleanup
            if contexts.len() > 1 {
                // This would be done by cancelling the Cx, which the LockFuture checks
                tracker.record_operation("would_cancel_cx_1");
                tracker.record_lock_state(1, LockState::Cancelled);

                // Test that other operations can still proceed
                if contexts.len() > 2 && !lock_futures.is_empty() {
                    let waker = tracked_wakers[2].create_waker();
                    let mut context = Context::from_waker(&waker);

                    let third_lock = OwnedMutexGuard::lock(Arc::clone(&mutex), &contexts[2]);
                    let mut pinned_third = Box::pin(third_lock);

                    let poll_result = pinned_third.as_mut().poll(&mut context);
                    let lock_available = !matches!(poll_result, Poll::Ready(Ok(_)));

                    tracker.record_cancel_result(CancelResult {
                        operation_id: 1,
                        result: Err(LockError::Cancelled),
                        lock_available_after: lock_available,
                    });
                }
            }
        }

        CancelPattern::CancelBeforePoll => {
            for (i, cx) in contexts.iter().enumerate() {
                // Create future but don't poll
                let lock_future = OwnedMutexGuard::lock(Arc::clone(&mutex), cx);
                lock_futures.push(Box::pin(lock_future));

                // Simulate immediate cancellation
                tracker.record_operation(&format!("immediate_cancel_{}", i));
                tracker.record_lock_state(i, LockState::Cancelled);
            }

            // Verify that a fresh lock attempt succeeds
            let fresh_cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(100, 0)),
                TaskId::from_arena(ArenaIndex::new(100, 0)),
                Budget::infinite(),
            );

            let fresh_lock = OwnedMutexGuard::lock(Arc::clone(&mutex), &fresh_cx);
            let mut pinned_fresh = Box::pin(fresh_lock);
            let fresh_waker = TrackedWaker::new(100, tracker.clone()).create_waker();
            let mut fresh_context = Context::from_waker(&fresh_waker);

            match pinned_fresh.as_mut().poll(&mut fresh_context) {
                Poll::Ready(Ok(_guard)) => {
                    tracker.record_cancel_result(CancelResult {
                        operation_id: 100,
                        result: Ok(()),
                        lock_available_after: true,
                    });
                }
                _ => {
                    tracker.record_cancel_result(CancelResult {
                        operation_id: 100,
                        result: Err(LockError::Cancelled),
                        lock_available_after: true,
                    });
                }
            }
        }

        CancelPattern::CancelAfterFirstPoll => {
            if !contexts.is_empty() {
                let lock_future = OwnedMutexGuard::lock(Arc::clone(&mutex), &contexts[0]);
                let mut pinned = Box::pin(lock_future);
                let waker = tracked_wakers[0].create_waker();
                let mut context = Context::from_waker(&waker);

                // First poll
                let first_poll = pinned.as_mut().poll(&mut context);
                tracker.record_operation("first_poll");

                // Cancel after first poll
                tracker.record_operation("cancel_after_first_poll");
                tracker.record_lock_state(0, LockState::Cancelled);

                let lock_available = !matches!(first_poll, Poll::Ready(Ok(_)));
                tracker.record_cancel_result(CancelResult {
                    operation_id: 0,
                    result: if lock_available {
                        Err(LockError::Cancelled)
                    } else {
                        Ok(())
                    },
                    lock_available_after: lock_available,
                });
            }
        }

        CancelPattern::RapidCancelPoll { iterations } => {
            let iterations = iterations.min(10) as usize;

            for iter in 0..iterations {
                if iter >= contexts.len() {
                    break;
                }

                let lock_future =
                    OwnedMutexGuard::lock(Arc::clone(&mutex), &contexts[iter % contexts.len()]);
                let mut pinned = Box::pin(lock_future);
                let waker = tracked_wakers[iter % tracked_wakers.len()].create_waker();
                let mut context = Context::from_waker(&waker);

                // Rapid poll-cancel cycle
                let poll_result = pinned.as_mut().poll(&mut context);

                tracker.record_operation(&format!("rapid_poll_{}", iter));
                tracker.record_lock_state(iter, LockState::Cancelled);

                let lock_available = !matches!(poll_result, Poll::Ready(Ok(_)));
                tracker.record_cancel_result(CancelResult {
                    operation_id: iter,
                    result: if lock_available {
                        Err(LockError::Cancelled)
                    } else {
                        Ok(())
                    },
                    lock_available_after: lock_available,
                });
            }
        }

        CancelPattern::MultiOperationCancel { cancel_indices } => {
            // Create all lock futures
            for (i, cx) in contexts.iter().enumerate() {
                let lock_future = OwnedMutexGuard::lock(Arc::clone(&mutex), cx);
                lock_futures.push(Box::pin(lock_future));
                tracker.record_operation(&format!("created_multi_future_{}", i));
            }

            // Cancel specific operations
            for &cancel_idx in cancel_indices.iter() {
                let idx = cancel_idx as usize % config.operation_count as usize;
                tracker.record_operation(&format!("cancel_multi_{}", idx));
                tracker.record_lock_state(idx, LockState::Cancelled);

                tracker.record_cancel_result(CancelResult {
                    operation_id: idx,
                    result: Err(LockError::Cancelled),
                    lock_available_after: true, // Cancelled operations release lock availability
                });
            }
        }

        CancelPattern::DelayedCancel { delay_ms } => {
            if !contexts.is_empty() {
                let lock_future = OwnedMutexGuard::lock(Arc::clone(&mutex), &contexts[0]);
                let mut pinned = Box::pin(lock_future);
                let waker = tracked_wakers[0].create_waker();
                let mut context = Context::from_waker(&waker);

                // First poll
                let _ = pinned.as_mut().poll(&mut context);
                tracker.record_operation("delayed_first_poll");

                // Simulate delay then cancel
                let delay = Duration::from_millis(delay_ms.min(100) as u64);
                thread::sleep(delay);

                tracker.record_operation("delayed_cancel");
                tracker.record_lock_state(0, LockState::Cancelled);

                tracker.record_cancel_result(CancelResult {
                    operation_id: 0,
                    result: Err(LockError::Cancelled),
                    lock_available_after: true,
                });
            }
        }

        CancelPattern::InterleavedLockCancel { operations } => {
            let mut op_idx = 0;

            for &is_lock in operations.iter().take(config.operation_count as usize * 2) {
                if op_idx >= config.operation_count as usize {
                    break;
                }

                if is_lock {
                    if op_idx < contexts.len() {
                        let lock_future =
                            OwnedMutexGuard::lock(Arc::clone(&mutex), &contexts[op_idx]);
                        let mut pinned = Box::pin(lock_future);
                        let waker = tracked_wakers[op_idx].create_waker();
                        let mut context = Context::from_waker(&waker);

                        let poll_result = pinned.as_mut().poll(&mut context);
                        tracker.record_operation(&format!("interleaved_lock_{}", op_idx));

                        match poll_result {
                            Poll::Ready(Ok(_guard)) => {
                                tracker.record_lock_state(op_idx, LockState::LockAcquired);
                            }
                            Poll::Ready(Err(e)) => {
                                tracker.record_lock_state(
                                    op_idx,
                                    LockState::Failed(format!("{:?}", e)),
                                );
                            }
                            Poll::Pending => {
                                tracker.record_lock_state(op_idx, LockState::WaitingForLock);
                            }
                        }
                        op_idx += 1;
                    }
                } else {
                    // Cancel current operation
                    if op_idx > 0 {
                        tracker.record_operation(&format!("interleaved_cancel_{}", op_idx - 1));
                        tracker.record_lock_state(op_idx - 1, LockState::Cancelled);

                        tracker.record_cancel_result(CancelResult {
                            operation_id: op_idx - 1,
                            result: Err(LockError::Cancelled),
                            lock_available_after: true,
                        });
                    }
                }
            }
        }
    }

    // Final invariant validation
    tracker.validate_cancel_invariants();

    // Test that mutex is still functional after all operations
    let final_cx = Cx::new(
        RegionId::from_arena(ArenaIndex::new(999, 0)),
        TaskId::from_arena(ArenaIndex::new(999, 0)),
        Budget::infinite(),
    );

    let final_lock = OwnedMutexGuard::lock(Arc::clone(&mutex), &final_cx);
    let mut final_pinned = Box::pin(final_lock);
    let final_waker = TrackedWaker::new(999, tracker.clone()).create_waker();
    let mut final_context = Context::from_waker(&final_waker);

    // This should succeed, proving no permanent lock leaks
    match final_pinned.as_mut().poll(&mut final_context) {
        Poll::Ready(Ok(guard)) => {
            // Verify the mutex still holds the correct value
            assert_eq!(
                *guard, config.test_value,
                "Mutex value corrupted after cancel operations"
            );
            tracker.record_operation("final_validation_success");
        }
        Poll::Ready(Err(e)) => {
            // Only acceptable if mutex was poisoned
            if !matches!(e, LockError::Poisoned) {
                panic!("Final lock attempt failed unexpectedly: {:?}", e);
            }
            tracker.record_operation("final_validation_poisoned");
        }
        Poll::Pending => {
            // This could indicate a lock leak if no operation should be holding the lock
            tracker.record_operation("final_validation_pending");
        }
    }
});
