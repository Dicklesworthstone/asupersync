#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::thread;
use std::time::Duration;

use asupersync::cx::cap;
use asupersync::sync::{RwLock, RwLockError, TryReadError, TryWriteError};
use asupersync::types::TaskId;
use asupersync::util::ArenaIndex;
use asupersync::{Budget, Cx, RegionId};

#[derive(Debug, Clone)]
struct PoisonTracker {
    operations: Arc<StdMutex<Vec<String>>>,
    poison_events: Arc<StdMutex<Vec<PoisonEvent>>>,
    acquisition_results: Arc<StdMutex<Vec<AcquisitionResult>>>,
}

#[derive(Debug, Clone)]
struct PoisonEvent {
    writer_id: usize,
    panic_message: String,
    lock_poisoned_after: bool,
}

#[derive(Debug, Clone)]
struct AcquisitionResult {
    operation_id: usize,
    operation_type: AcquisitionType,
    result: AcquisitionOutcome,
    lock_was_poisoned: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum AcquisitionType {
    TryRead,
    TryWrite,
    AsyncRead,
    AsyncWrite,
}

#[derive(Debug, Clone, PartialEq)]
enum AcquisitionOutcome {
    Success,
    Locked,
    Poisoned,
    Cancelled,
    Other(String),
}

impl PoisonTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(StdMutex::new(Vec::new())),
            poison_events: Arc::new(StdMutex::new(Vec::new())),
            acquisition_results: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_poison_event(&self, event: PoisonEvent) {
        if let Ok(mut events) = self.poison_events.lock() {
            events.push(event);
        }
    }

    fn record_acquisition_result(&self, result: AcquisitionResult) {
        if let Ok(mut results) = self.acquisition_results.lock() {
            results.push(result);
        }
    }

    fn validate_poison_invariants(&self, rwlock: &RwLock<u32>) {
        let lock_is_poisoned = rwlock.is_poisoned();

        // Check poison event consistency
        if let Ok(events) = self.poison_events.lock() {
            let poison_events_occurred = !events.is_empty();
            assert_eq!(
                lock_is_poisoned, poison_events_occurred,
                "Lock poison state ({}) inconsistent with poison events ({})",
                lock_is_poisoned, poison_events_occurred
            );
        }

        // Validate that all acquisitions after poisoning return Poisoned errors
        if let Ok(results) = self.acquisition_results.lock() {
            for result in results.iter() {
                if result.lock_was_poisoned {
                    assert_eq!(
                        result.result,
                        AcquisitionOutcome::Poisoned,
                        "Acquisition {:?} type {:?} should return Poisoned when lock was poisoned, got {:?}",
                        result.operation_id,
                        result.operation_type,
                        result.result
                    );
                }
            }
        }

        // Validate that successful acquisitions only happen when lock wasn't poisoned
        if let Ok(results) = self.acquisition_results.lock() {
            for result in results.iter() {
                if result.result == AcquisitionOutcome::Success {
                    assert!(
                        !result.lock_was_poisoned,
                        "Acquisition {:?} type {:?} succeeded but lock was poisoned",
                        result.operation_id, result.operation_type
                    );
                }
            }
        }
    }
}

struct TrackedWaker {
    op_id: usize,
    tracker: PoisonTracker,
}

impl TrackedWaker {
    fn new(op_id: usize, tracker: PoisonTracker) -> Self {
        Self { op_id, tracker }
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
            op_id: self.op_id,
            tracker: self.tracker.clone(),
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
    let arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
    let cloned = arc.clone();
    std::mem::forget(arc);
    let new_data = Arc::into_raw(cloned) as *const ();
    RawWaker::new(new_data, &TRACKED_WAKER_VTABLE)
}

unsafe fn tracked_waker_wake(data: *const ()) {
    let arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
    arc.tracker.record_operation(&format!("wake_{}", arc.op_id));
}

unsafe fn tracked_waker_wake_by_ref(data: *const ()) {
    let arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
    arc.tracker
        .record_operation(&format!("wake_by_ref_{}", arc.op_id));
    std::mem::forget(arc);
}

unsafe fn tracked_waker_drop(data: *const ()) {
    let _arc = unsafe { Arc::from_raw(data as *const TrackedWaker) };
}

#[derive(Debug, Clone, Arbitrary)]
struct PoisonConfig {
    writer_count: u8,
    poison_pattern: PoisonPattern,
    test_value: u32,
}

#[derive(Debug, Clone, Arbitrary)]
enum PoisonPattern {
    SinglePanicWriter,
    MultiplePanicWriters { panic_indices: Vec<u8> },
    PanicDuringWrite { delay_before_panic_ms: u16 },
    PanicAfterAcquire,
    InterleavedPanicAcquire { operations: Vec<bool> }, // true=acquire, false=panic
    RapidPanicAcquire { iterations: u8 },
    PanicThenMultipleReads { reader_count: u8 },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: PoisonConfig = u.arbitrary().unwrap_or(PoisonConfig {
        writer_count: 2,
        poison_pattern: PoisonPattern::SinglePanicWriter,
        test_value: 42,
    });

    if config.writer_count == 0 || config.writer_count > 6 {
        return;
    }

    let tracker = PoisonTracker::new();
    let rwlock = Arc::new(RwLock::new(config.test_value));
    let mut contexts = Vec::new();

    // Create contexts for operations
    for i in 0..config.writer_count {
        let cx: Cx<cap::All> = Cx::new(
            RegionId::from_arena(ArenaIndex::new(i as u32, 0)),
            TaskId::from_arena(ArenaIndex::new(i as u32, 0)),
            Budget::unlimited(),
        );
        contexts.push(cx);
    }

    // Execute poison pattern
    match config.poison_pattern {
        PoisonPattern::SinglePanicWriter => {
            if !contexts.is_empty() {
                let lock_clone = Arc::clone(&rwlock);
                let tracker_clone = tracker.clone();

                // Simulate writer that panics
                let panic_result = catch_unwind(AssertUnwindSafe(|| {
                    let write_guard = lock_clone.try_write().expect("Should acquire write lock");
                    tracker_clone.record_operation("acquired_write_guard");

                    // Simulate panic during write
                    panic!("Intentional panic during write operation");
                }));

                tracker.record_operation("caught_panic");

                if panic_result.is_err() {
                    tracker.record_poison_event(PoisonEvent {
                        writer_id: 0,
                        panic_message: "Intentional panic during write operation".to_string(),
                        lock_poisoned_after: rwlock.is_poisoned(),
                    });
                }

                // Test subsequent acquisitions
                test_post_poison_acquisitions(&rwlock, &tracker, 0);
            }
        }

        PoisonPattern::MultiplePanicWriters { panic_indices } => {
            for (i, &panic_idx) in panic_indices.iter().enumerate() {
                let writer_idx = panic_idx as usize % config.writer_count as usize;
                let lock_clone = Arc::clone(&rwlock);
                let tracker_clone = tracker.clone();

                let panic_result = catch_unwind(AssertUnwindSafe(|| {
                    let write_guard = lock_clone.try_write();
                    match write_guard {
                        Ok(_guard) => {
                            tracker_clone
                                .record_operation(&format!("writer_{}_acquired", writer_idx));
                            panic!("Multi-writer panic {}", i);
                        }
                        Err(_) => {
                            // Lock already held or poisoned
                            tracker_clone
                                .record_operation(&format!("writer_{}_blocked", writer_idx));
                        }
                    }
                }));

                if panic_result.is_err() {
                    tracker.record_poison_event(PoisonEvent {
                        writer_id: writer_idx,
                        panic_message: format!("Multi-writer panic {}", i),
                        lock_poisoned_after: rwlock.is_poisoned(),
                    });
                }

                // Test acquisitions after each panic
                test_post_poison_acquisitions(&rwlock, &tracker, writer_idx);
            }
        }

        PoisonPattern::PanicDuringWrite {
            delay_before_panic_ms,
        } => {
            if !contexts.is_empty() {
                let lock_clone = Arc::clone(&rwlock);
                let tracker_clone = tracker.clone();
                let delay = Duration::from_millis(delay_before_panic_ms.min(100) as u64);

                let panic_result = catch_unwind(AssertUnwindSafe(|| {
                    let mut write_guard =
                        lock_clone.try_write().expect("Should acquire write lock");
                    tracker_clone.record_operation("acquired_for_delayed_panic");

                    // Simulate some work before panic
                    thread::sleep(delay);
                    *write_guard = 999; // Modify data

                    panic!("Delayed panic after write");
                }));

                if panic_result.is_err() {
                    tracker.record_poison_event(PoisonEvent {
                        writer_id: 0,
                        panic_message: "Delayed panic after write".to_string(),
                        lock_poisoned_after: rwlock.is_poisoned(),
                    });
                }

                test_post_poison_acquisitions(&rwlock, &tracker, 0);
            }
        }

        PoisonPattern::PanicAfterAcquire => {
            if !contexts.is_empty() {
                let lock_clone = Arc::clone(&rwlock);
                let tracker_clone = tracker.clone();

                let panic_result = catch_unwind(AssertUnwindSafe(|| {
                    let _write_guard = lock_clone.try_write().expect("Should acquire write lock");
                    tracker_clone.record_operation("acquired_then_immediate_panic");
                    panic!("Immediate panic after acquire");
                }));

                if panic_result.is_err() {
                    tracker.record_poison_event(PoisonEvent {
                        writer_id: 0,
                        panic_message: "Immediate panic after acquire".to_string(),
                        lock_poisoned_after: rwlock.is_poisoned(),
                    });
                }

                test_post_poison_acquisitions(&rwlock, &tracker, 0);
            }
        }

        PoisonPattern::InterleavedPanicAcquire { operations } => {
            let mut op_count = 0;

            for &is_acquire in operations.iter().take(config.writer_count as usize * 2) {
                if op_count >= config.writer_count as usize {
                    break;
                }

                let lock_clone = Arc::clone(&rwlock);
                let tracker_clone = tracker.clone();

                if is_acquire {
                    // Attempt acquisition
                    let acquire_result = lock_clone.try_write();
                    match acquire_result {
                        Ok(_guard) => {
                            tracker.record_operation(&format!("interleaved_acquire_{}", op_count));
                            tracker.record_acquisition_result(AcquisitionResult {
                                operation_id: op_count,
                                operation_type: AcquisitionType::TryWrite,
                                result: AcquisitionOutcome::Success,
                                lock_was_poisoned: rwlock.is_poisoned(),
                            });
                        }
                        Err(TryWriteError::Locked) => {
                            tracker.record_acquisition_result(AcquisitionResult {
                                operation_id: op_count,
                                operation_type: AcquisitionType::TryWrite,
                                result: AcquisitionOutcome::Locked,
                                lock_was_poisoned: rwlock.is_poisoned(),
                            });
                        }
                        Err(TryWriteError::Poisoned) => {
                            tracker.record_acquisition_result(AcquisitionResult {
                                operation_id: op_count,
                                operation_type: AcquisitionType::TryWrite,
                                result: AcquisitionOutcome::Poisoned,
                                lock_was_poisoned: rwlock.is_poisoned(),
                            });
                        }
                    }
                } else {
                    // Attempt panic during write
                    let panic_result = catch_unwind(AssertUnwindSafe(|| {
                        let _write_guard = lock_clone.try_write().ok();
                        tracker_clone.record_operation(&format!("interleaved_panic_{}", op_count));
                        panic!("Interleaved panic");
                    }));

                    if panic_result.is_err() {
                        tracker.record_poison_event(PoisonEvent {
                            writer_id: op_count,
                            panic_message: "Interleaved panic".to_string(),
                            lock_poisoned_after: rwlock.is_poisoned(),
                        });
                    }
                }

                op_count += 1;
            }
        }

        PoisonPattern::RapidPanicAcquire { iterations } => {
            let iterations = iterations.min(8) as usize;

            for i in 0..iterations {
                let lock_clone = Arc::clone(&rwlock);
                let tracker_clone = tracker.clone();

                let panic_result = catch_unwind(AssertUnwindSafe(|| {
                    let write_result = lock_clone.try_write();
                    match write_result {
                        Ok(_guard) => {
                            tracker_clone.record_operation(&format!("rapid_panic_{}", i));
                            panic!("Rapid panic {}", i);
                        }
                        Err(_) => {
                            tracker_clone.record_operation(&format!("rapid_blocked_{}", i));
                        }
                    }
                }));

                if panic_result.is_err() && rwlock.is_poisoned() {
                    tracker.record_poison_event(PoisonEvent {
                        writer_id: i,
                        panic_message: format!("Rapid panic {}", i),
                        lock_poisoned_after: rwlock.is_poisoned(),
                    });
                }
            }
        }

        PoisonPattern::PanicThenMultipleReads { reader_count } => {
            // First, poison the lock
            let lock_clone = Arc::clone(&rwlock);
            let tracker_clone = tracker.clone();

            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                let _write_guard = lock_clone.try_write().expect("Should acquire write lock");
                tracker_clone.record_operation("poison_before_reads");
                panic!("Poison before multiple reads");
            }));

            if panic_result.is_err() {
                tracker.record_poison_event(PoisonEvent {
                    writer_id: 0,
                    panic_message: "Poison before multiple reads".to_string(),
                    lock_poisoned_after: rwlock.is_poisoned(),
                });
            }

            // Then attempt multiple reads
            let read_count = reader_count.min(10) as usize;
            for i in 0..read_count {
                let read_result = rwlock.try_read();
                match read_result {
                    Ok(_guard) => {
                        tracker.record_acquisition_result(AcquisitionResult {
                            operation_id: i + 1000, // Offset to distinguish from writers
                            operation_type: AcquisitionType::TryRead,
                            result: AcquisitionOutcome::Success,
                            lock_was_poisoned: rwlock.is_poisoned(),
                        });
                    }
                    Err(TryReadError::Locked) => {
                        tracker.record_acquisition_result(AcquisitionResult {
                            operation_id: i + 1000,
                            operation_type: AcquisitionType::TryRead,
                            result: AcquisitionOutcome::Locked,
                            lock_was_poisoned: rwlock.is_poisoned(),
                        });
                    }
                    Err(TryReadError::Poisoned) => {
                        tracker.record_acquisition_result(AcquisitionResult {
                            operation_id: i + 1000,
                            operation_type: AcquisitionType::TryRead,
                            result: AcquisitionOutcome::Poisoned,
                            lock_was_poisoned: rwlock.is_poisoned(),
                        });
                    }
                }
            }
        }
    }

    // Final validation
    tracker.validate_poison_invariants(&rwlock);
});

fn test_post_poison_acquisitions(rwlock: &RwLock<u32>, tracker: &PoisonTracker, op_id: usize) {
    let was_poisoned = rwlock.is_poisoned();

    // Test try_read
    let try_read_result = rwlock.try_read();
    let read_outcome = match try_read_result {
        Ok(_) => AcquisitionOutcome::Success,
        Err(TryReadError::Locked) => AcquisitionOutcome::Locked,
        Err(TryReadError::Poisoned) => AcquisitionOutcome::Poisoned,
    };

    tracker.record_acquisition_result(AcquisitionResult {
        operation_id: op_id + 10000, // Offset for post-poison tests
        operation_type: AcquisitionType::TryRead,
        result: read_outcome,
        lock_was_poisoned: was_poisoned,
    });

    // Test try_write
    let try_write_result = rwlock.try_write();
    let write_outcome = match try_write_result {
        Ok(_) => AcquisitionOutcome::Success,
        Err(TryWriteError::Locked) => AcquisitionOutcome::Locked,
        Err(TryWriteError::Poisoned) => AcquisitionOutcome::Poisoned,
    };

    tracker.record_acquisition_result(AcquisitionResult {
        operation_id: op_id + 20000, // Offset for post-poison write tests
        operation_type: AcquisitionType::TryWrite,
        result: write_outcome,
        lock_was_poisoned: was_poisoned,
    });

    // Test async read
    let cx: Cx<cap::All> = Cx::new(
        RegionId::from_arena(ArenaIndex::new(999, 0)),
        TaskId::from_arena(ArenaIndex::new(999, 0)),
        Budget::unlimited(),
    );

    let read_future = rwlock.read(&cx);
    let mut pinned_read = Box::pin(read_future);
    let read_waker = TrackedWaker::new(op_id + 30000, tracker.clone()).create_waker();
    let mut read_context = Context::from_waker(&read_waker);

    let async_read_outcome = match pinned_read.as_mut().poll(&mut read_context) {
        Poll::Ready(Ok(_)) => AcquisitionOutcome::Success,
        Poll::Ready(Err(RwLockError::Cancelled)) => AcquisitionOutcome::Cancelled,
        Poll::Ready(Err(RwLockError::Poisoned)) => AcquisitionOutcome::Poisoned,
        Poll::Ready(Err(RwLockError::PolledAfterCompletion)) => {
            AcquisitionOutcome::Other("PolledAfterCompletion".to_string())
        }
        Poll::Pending => AcquisitionOutcome::Other("Pending".to_string()),
    };

    tracker.record_acquisition_result(AcquisitionResult {
        operation_id: op_id + 30000,
        operation_type: AcquisitionType::AsyncRead,
        result: async_read_outcome,
        lock_was_poisoned: was_poisoned,
    });

    // Test async write
    let write_future = rwlock.write(&cx);
    let mut pinned_write = Box::pin(write_future);
    let write_waker = TrackedWaker::new(op_id + 40000, tracker.clone()).create_waker();
    let mut write_context = Context::from_waker(&write_waker);

    let async_write_outcome = match pinned_write.as_mut().poll(&mut write_context) {
        Poll::Ready(Ok(_)) => AcquisitionOutcome::Success,
        Poll::Ready(Err(RwLockError::Cancelled)) => AcquisitionOutcome::Cancelled,
        Poll::Ready(Err(RwLockError::Poisoned)) => AcquisitionOutcome::Poisoned,
        Poll::Ready(Err(RwLockError::PolledAfterCompletion)) => {
            AcquisitionOutcome::Other("PolledAfterCompletion".to_string())
        }
        Poll::Pending => AcquisitionOutcome::Other("Pending".to_string()),
    };

    tracker.record_acquisition_result(AcquisitionResult {
        operation_id: op_id + 40000,
        operation_type: AcquisitionType::AsyncWrite,
        result: async_write_outcome,
        lock_was_poisoned: was_poisoned,
    });
}
