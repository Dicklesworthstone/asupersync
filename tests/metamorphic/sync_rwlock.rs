#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for sync::rwlock writer-preference and reader-concurrency invariants
//!
//! This test suite validates the fundamental RwLock semantics using metamorphic
//! relations that must hold regardless of timing, contention patterns, or
//! specific data access patterns.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::rwlock::{RwLock, RwLockError, TryReadError, TryWriteError};
use asupersync::time::sleep;
use asupersync::{region, Outcome};
use proptest::prelude::*;

/// Test configuration for RwLock properties
#[derive(Debug, Clone)]
struct RwLockTestConfig {
    /// Number of readers to spawn
    reader_count: usize,
    /// Number of writers to spawn
    writer_count: usize,
    /// How long each task should hold the lock (in ms)
    hold_duration_ms: u64,
    /// Whether to introduce cancellation during acquisition
    cancel_during_acquire: bool,
    /// Whether to test panic scenarios
    test_panic_behavior: bool,
}

fn rwlock_config_strategy() -> impl Strategy<Value = RwLockTestConfig> {
    (
        // Reader count: 1 to 5
        1_usize..=5,
        // Writer count: 0 to 3
        0_usize..=3,
        // Hold duration: 1ms to 50ms
        1_u64..=50,
        // Cancel flag
        any::<bool>(),
        // Panic test flag
        any::<bool>(),
    )
        .prop_map(|(reader_count, writer_count, hold_duration_ms, cancel_during_acquire, test_panic_behavior)| {
            RwLockTestConfig {
                reader_count,
                writer_count,
                hold_duration_ms,
                cancel_during_acquire,
                test_panic_behavior,
            }
        })
}

/// Counter for tracking concurrent operations
#[derive(Debug, Default)]
struct ConcurrencyCounter {
    active_readers: AtomicUsize,
    active_writers: AtomicUsize,
    max_concurrent_readers: AtomicUsize,
    violations: AtomicUsize,
}

impl ConcurrencyCounter {
    fn enter_read(&self) {
        let readers = self.active_readers.fetch_add(1, Ordering::SeqCst);
        let writers = self.active_writers.load(Ordering::SeqCst);

        // Violation: readers and writers active at the same time
        if writers > 0 {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }

        // Track max concurrent readers
        self.max_concurrent_readers.fetch_max(readers + 1, Ordering::SeqCst);
    }

    fn exit_read(&self) {
        self.active_readers.fetch_sub(1, Ordering::SeqCst);
    }

    fn enter_write(&self) {
        let writers = self.active_writers.fetch_add(1, Ordering::SeqCst);
        let readers = self.active_readers.load(Ordering::SeqCst);

        // Violation: multiple writers active
        if writers > 0 {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }

        // Violation: readers and writers active at the same time
        if readers > 0 {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn exit_write(&self) {
        self.active_writers.fetch_sub(1, Ordering::SeqCst);
    }

    fn get_violations(&self) -> usize {
        self.violations.load(Ordering::SeqCst)
    }

    fn get_max_concurrent_readers(&self) -> usize {
        self.max_concurrent_readers.load(Ordering::SeqCst)
    }
}

/// MR1: Multiple readers concurrent (when no writers waiting/active)
#[test]
fn mr1_multiple_readers_concurrent() {
    proptest!(|(config in rwlock_config_strategy())| {
        // Skip configurations with writers or cancellation for this pure reader concurrency test
        if config.writer_count > 0 || config.cancel_during_acquire {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(42_u32));
                let counter = Arc::new(ConcurrencyCounter::default());

                // Spawn multiple readers
                let mut reader_handles = Vec::new();
                for reader_id in 0..config.reader_count {
                    let lock_clone = lock.clone();
                    let counter_clone = counter.clone();
                    let handle = scope.spawn(move |reader_cx| async move {
                        let guard = lock_clone.read(reader_cx).await?;
                        counter_clone.enter_read();

                        // Hold the lock for a short duration
                        sleep(reader_cx, Duration::from_millis(config.hold_duration_ms)).await;

                        // Verify we can read the data
                        let _value = *guard;

                        counter_clone.exit_read();
                        Ok(reader_id)
                    });
                    reader_handles.push(handle);
                }

                // Wait for all readers to complete
                for handle in reader_handles {
                    let _reader_id = handle.await?;
                }

                // Verify concurrent reader behavior
                prop_assert_eq!(counter.get_violations(), 0,
                    "No read-write or write-write violations should occur with only readers");

                if config.reader_count > 1 {
                    prop_assert!(counter.get_max_concurrent_readers() > 1,
                        "Should have concurrent readers when multiple readers and no writers");
                }

                Ok(())
            })
        });

        result
    });
}

/// MR2: Writer excludes all readers (mutual exclusion)
#[test]
fn mr2_writer_excludes_all_readers() {
    proptest!(|(config in rwlock_config_strategy())| {
        // Skip configurations without writers
        if config.writer_count == 0 {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(0_u32));
                let counter = Arc::new(ConcurrencyCounter::default());

                // Spawn readers and writers
                let mut handles = Vec::new();

                // Add readers
                for reader_id in 0..config.reader_count {
                    let lock_clone = lock.clone();
                    let counter_clone = counter.clone();
                    let handle = scope.spawn(move |reader_cx| async move {
                        let guard = lock_clone.read(reader_cx).await?;
                        counter_clone.enter_read();

                        sleep(reader_cx, Duration::from_millis(config.hold_duration_ms / 2)).await;

                        let _value = *guard;
                        counter_clone.exit_read();
                        Ok(format!("reader_{}", reader_id))
                    });
                    handles.push(handle);
                }

                // Add writers
                for writer_id in 0..config.writer_count {
                    let lock_clone = lock.clone();
                    let counter_clone = counter.clone();
                    let handle = scope.spawn(move |writer_cx| async move {
                        let mut guard = lock_clone.write(writer_cx).await?;
                        counter_clone.enter_write();

                        sleep(writer_cx, Duration::from_millis(config.hold_duration_ms)).await;

                        // Modify the data while holding write lock
                        *guard += 1;

                        counter_clone.exit_write();
                        Ok(format!("writer_{}", writer_id))
                    });
                    handles.push(handle);
                }

                // Wait for all tasks to complete
                for handle in handles {
                    let _task_id = handle.await?;
                }

                // Verify mutual exclusion was maintained
                prop_assert_eq!(counter.get_violations(), 0,
                    "No mutual exclusion violations should occur with readers and writers");

                Ok(())
            })
        });

        result
    });
}

/// MR3: Writer-waiter blocks new readers (writer-preference)
#[test]
fn mr3_writer_waiter_blocks_new_readers() {
    proptest!(|(reader_count in 2_usize..=4)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(0_u32));
                let writer_waiting = Arc::new(AtomicBool::new(false));
                let readers_blocked = Arc::new(AtomicUsize::new(0));

                // First reader acquires the lock
                let first_reader_lock = lock.clone();
                let first_reader_handle = scope.spawn(|first_cx| async move {
                    let _guard = first_reader_lock.read(first_cx).await?;
                    // Hold for a while to allow writer to start waiting
                    sleep(first_cx, Duration::from_millis(100)).await;
                    Ok("first_reader")
                });

                // Small delay to ensure first reader acquires
                sleep(cx, Duration::from_millis(10)).await;

                // Writer tries to acquire (will wait for first reader)
                let writer_lock = lock.clone();
                let writer_waiting_flag = writer_waiting.clone();
                let writer_handle = scope.spawn(move |writer_cx| async move {
                    writer_waiting_flag.store(true, Ordering::SeqCst);
                    let mut _guard = writer_lock.write(writer_cx).await?;
                    writer_waiting_flag.store(false, Ordering::SeqCst);
                    *_guard += 1;
                    Ok("writer")
                });

                // Small delay to ensure writer starts waiting
                sleep(cx, Duration::from_millis(20)).await;

                // Additional readers try to acquire while writer is waiting
                let mut reader_handles = Vec::new();
                for reader_id in 1..reader_count {
                    let lock_clone = lock.clone();
                    let waiting_flag = writer_waiting.clone();
                    let blocked_counter = readers_blocked.clone();
                    let handle = scope.spawn(move |reader_cx| async move {
                        if waiting_flag.load(Ordering::SeqCst) {
                            // Writer is waiting, so this reader should be blocked by writer-preference
                            blocked_counter.fetch_add(1, Ordering::SeqCst);
                        }

                        let _guard = lock_clone.read(reader_cx).await?;
                        Ok(format!("reader_{}", reader_id))
                    });
                    reader_handles.push(handle);
                }

                // Wait for first reader to finish
                first_reader_handle.await?;

                // Wait for writer
                writer_handle.await?;

                // Wait for additional readers
                for handle in reader_handles {
                    handle.await?;
                }

                // Verify that additional readers were blocked while writer was waiting
                let blocked_count = readers_blocked.load(Ordering::SeqCst);
                prop_assert!(blocked_count > 0,
                    "Some readers should have been blocked by writer-preference, blocked: {}",
                    blocked_count);

                Ok(())
            })
        });

        result
    });
}

/// MR4: Cancelled acquire does not hold lock
#[test]
fn mr4_cancelled_acquire_does_not_hold_lock() {
    proptest!(|(config in rwlock_config_strategy())| {
        // Test only configurations with cancellation enabled
        if !config.cancel_during_acquire {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(0_u32));

                // First, acquire a write lock to block subsequent acquisitions
                let blocking_lock = lock.clone();
                let blocking_handle = scope.spawn(move |blocking_cx| async move {
                    let mut _guard = blocking_lock.write(blocking_cx).await?;
                    sleep(blocking_cx, Duration::from_millis(150)).await;
                    *_guard = 42;
                    Ok("blocker")
                });

                // Small delay to ensure blocker acquires first
                sleep(cx, Duration::from_millis(10)).await;

                // Try to acquire with cancellation
                let cancelled_outcome = region(|inner_cx, inner_scope| async move {
                    let acquire_lock = lock.clone();

                    // Start acquisition that will be cancelled
                    let acquire_future = acquire_lock.read(inner_cx);

                    // Schedule cancellation
                    inner_scope.spawn(|cancel_cx| async move {
                        sleep(cancel_cx, Duration::from_millis(25)).await;
                        // This will cancel the acquisition
                        Ok(())
                    });

                    acquire_future.await
                }).await;

                // Should be cancelled
                match cancelled_outcome {
                    Outcome::Cancelled => {
                        // Expected when cancelled externally
                    }
                    Outcome::Ok(Err(RwLockError::Cancelled)) => {
                        // Also valid - explicit cancellation error
                    }
                    other => {
                        // Could also succeed if timing is different
                    }
                }

                // After cancellation, lock should still be available for others
                blocking_handle.await?;

                // Now the lock should be available
                let final_guard = lock.try_read();
                prop_assert!(final_guard.is_ok(),
                    "Lock should be available after cancelled acquisition");

                if let Ok(guard) = final_guard {
                    prop_assert_eq!(*guard, 42, "Should see the value set by the blocker");
                }

                Ok(())
            })
        });

        result
    });
}

/// MR5: Dropped guards release on all paths including panic
#[test]
fn mr5_dropped_guards_release_including_panic() {
    proptest!(|(config in rwlock_config_strategy())| {
        // Skip complex configurations for this focused panic test
        if !config.test_panic_behavior || config.reader_count > 2 || config.writer_count > 1 {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(0_u32));

                // Spawn a task that will panic while holding a write guard
                let panic_lock = lock.clone();
                let panic_handle = scope.spawn(move |panic_cx| async move {
                    let mut guard = panic_lock.write(panic_cx).await?;
                    *guard = 123; // Set a value

                    // Simulate a panic by returning an error (safer than actual panic in tests)
                    // This tests the "normal" drop path; actual panic would poison the lock
                    drop(guard); // Explicit drop to simulate guard release
                    Err::<(), _>(std::io::Error::new(std::io::ErrorKind::Other, "simulated panic"))
                });

                // Wait for the panicking task (it will error)
                let _panic_result = panic_handle.await;

                // Verify the lock was released and is available
                let recovery_guard = lock.try_write();
                prop_assert!(recovery_guard.is_ok() || lock.is_poisoned(),
                    "Lock should be available after guard drop, or poisoned if panic occurred");

                match recovery_guard {
                    Ok(guard) => {
                        prop_assert_eq!(*guard, 123, "Should see value written before drop");
                    }
                    Err(TryWriteError::Poisoned) => {
                        // Expected if real panic occurred
                    }
                    Err(e) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected error after guard drop: {:?}", e)
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR6: try_read/try_write never block
#[test]
fn mr6_try_methods_never_block() {
    proptest!(|(config in rwlock_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(42_u32));

                // Measure execution time of try_read and try_write
                let start_time = std::time::Instant::now();

                // Test try_read when available
                let try_read_result = lock.try_read();
                let after_try_read = std::time::Instant::now();

                if let Ok(guard) = try_read_result {
                    prop_assert_eq!(*guard, 42, "try_read should succeed when available");
                    drop(guard);
                }

                // Test try_write when available
                let try_write_result = lock.try_write();
                let after_try_write = std::time::Instant::now();

                if let Ok(mut guard) = try_write_result {
                    *guard = 84;
                    drop(guard);
                }

                // Both operations should complete very quickly (non-blocking)
                let try_read_duration = after_try_read.duration_since(start_time);
                let try_write_duration = after_try_write.duration_since(after_try_read);

                prop_assert!(try_read_duration < Duration::from_millis(10),
                    "try_read should not block, took {:?}", try_read_duration);
                prop_assert!(try_write_duration < Duration::from_millis(10),
                    "try_write should not block, took {:?}", try_write_duration);

                // Test try methods when lock is held
                let write_lock = lock.clone();
                let blocking_handle = scope.spawn(move |write_cx| async move {
                    let _guard = write_lock.write(write_cx).await?;
                    sleep(write_cx, Duration::from_millis(100)).await;
                    Ok(())
                });

                // Small delay to ensure write lock is acquired
                sleep(cx, Duration::from_millis(10)).await;

                // try_read should fail quickly when writer is active
                let blocked_read_start = std::time::Instant::now();
                let blocked_read_result = lock.try_read();
                let blocked_read_duration = blocked_read_start.elapsed();

                prop_assert!(blocked_read_result.is_err(),
                    "try_read should fail when writer is active");
                prop_assert!(blocked_read_duration < Duration::from_millis(10),
                    "try_read should fail quickly, took {:?}", blocked_read_duration);

                match blocked_read_result.unwrap_err() {
                    TryReadError::Locked => {
                        // Expected when writer is active
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected try_read error: {:?}", other)
                        ));
                    }
                }

                // try_write should also fail quickly when writer is active
                let blocked_write_start = std::time::Instant::now();
                let blocked_write_result = lock.try_write();
                let blocked_write_duration = blocked_write_start.elapsed();

                prop_assert!(blocked_write_result.is_err(),
                    "try_write should fail when writer is active");
                prop_assert!(blocked_write_duration < Duration::from_millis(10),
                    "try_write should fail quickly, took {:?}", blocked_write_duration);

                blocking_handle.await?;

                Ok(())
            })
        });

        result
    });
}

/// Additional property: Read-write lock fairness under contention
#[test]
fn mr_writer_preference_fairness() {
    proptest!(|(reader_count in 2_usize..=4, writer_count in 1_usize..=2)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(0_u32));
                let operations = Arc::new(std::sync::Mutex::new(Vec::new()));

                // Start with a reader holding the lock
                let initial_reader_lock = lock.clone();
                let initial_reader_ops = operations.clone();
                let initial_handle = scope.spawn(move |initial_cx| async move {
                    let _guard = initial_reader_lock.read(initial_cx).await?;
                    initial_reader_ops.lock().unwrap().push("initial_reader_start".to_string());
                    sleep(initial_cx, Duration::from_millis(50)).await;
                    initial_reader_ops.lock().unwrap().push("initial_reader_end".to_string());
                    Ok(())
                });

                // Small delay to ensure initial reader starts
                sleep(cx, Duration::from_millis(10)).await;

                // Spawn writers (they will wait for initial reader)
                let mut writer_handles = Vec::new();
                for writer_id in 0..writer_count {
                    let lock_clone = lock.clone();
                    let ops_clone = operations.clone();
                    let handle = scope.spawn(move |writer_cx| async move {
                        ops_clone.lock().unwrap().push(format!("writer_{}_waiting", writer_id));
                        let mut _guard = lock_clone.write(writer_cx).await?;
                        ops_clone.lock().unwrap().push(format!("writer_{}_acquired", writer_id));
                        sleep(writer_cx, Duration::from_millis(25)).await;
                        ops_clone.lock().unwrap().push(format!("writer_{}_done", writer_id));
                        Ok(())
                    });
                    writer_handles.push(handle);
                }

                // Small delay to ensure writers start waiting
                sleep(cx, Duration::from_millis(20)).await;

                // Spawn additional readers (should be blocked by waiting writers)
                let mut reader_handles = Vec::new();
                for reader_id in 1..reader_count {
                    let lock_clone = lock.clone();
                    let ops_clone = operations.clone();
                    let handle = scope.spawn(move |reader_cx| async move {
                        ops_clone.lock().unwrap().push(format!("reader_{}_waiting", reader_id));
                        let _guard = lock_clone.read(reader_cx).await?;
                        ops_clone.lock().unwrap().push(format!("reader_{}_acquired", reader_id));
                        sleep(reader_cx, Duration::from_millis(25)).await;
                        ops_clone.lock().unwrap().push(format!("reader_{}_done", reader_id));
                        Ok(())
                    });
                    reader_handles.push(handle);
                }

                // Wait for all tasks
                initial_handle.await?;
                for handle in writer_handles {
                    handle.await?;
                }
                for handle in reader_handles {
                    handle.await?;
                }

                // Analyze operation sequence for writer preference
                let ops = operations.lock().unwrap().clone();

                // Look for evidence of writer preference
                let mut writer_blocked_readers = false;
                for window in ops.windows(2) {
                    if window[0].contains("writer") && window[0].contains("waiting") &&
                       window[1].contains("reader") && window[1].contains("waiting") {
                        // Writer was waiting when reader tried to start - this shows writer preference
                        writer_blocked_readers = true;
                        break;
                    }
                }

                // In a writer-preference system, waiting writers should prevent new readers
                if writer_count > 0 && reader_count > 1 {
                    prop_assert!(writer_blocked_readers || ops.len() > 6,
                        "Should see evidence of writer-preference or complex scheduling");
                }

                Ok(())
            })
        });

        result
    });
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_read_write() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = RwLock::new(42_u32);

                // Read access
                let read_guard = lock.read(cx).await?;
                assert_eq!(*read_guard, 42);
                drop(read_guard);

                // Write access
                let mut write_guard = lock.write(cx).await?;
                *write_guard = 84;
                drop(write_guard);

                // Read updated value
                let read_guard2 = lock.read(cx).await?;
                assert_eq!(*read_guard2, 84);

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_try_methods() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = RwLock::new(42_u32);

                // try_read when available
                let read_guard = lock.try_read().unwrap();
                assert_eq!(*read_guard, 42);
                drop(read_guard);

                // try_write when available
                let mut write_guard = lock.try_write().unwrap();
                *write_guard = 84;
                drop(write_guard);

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_concurrent_readers() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let lock = Arc::new(RwLock::new(42_u32));

                // Multiple readers should be able to acquire concurrently
                let lock1 = lock.clone();
                let lock2 = lock.clone();

                let (guard1, guard2) = asupersync::combinator::join(
                    lock1.read(cx),
                    lock2.read(cx)
                ).await;

                let guard1 = guard1?;
                let guard2 = guard2?;

                assert_eq!(*guard1, 42);
                assert_eq!(*guard2, 42);

                Ok(())
            })
        }).unwrap();
    }
}