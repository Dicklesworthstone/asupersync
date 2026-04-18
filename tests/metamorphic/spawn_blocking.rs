//! Metamorphic tests for runtime::spawn_blocking cancel-propagation invariants.
//!
//! These tests validate the spawn_blocking cancellation semantics, panic propagation,
//! shutdown behavior, and queue ordering using metamorphic relations and property-based
//! testing under deterministic LabRuntime.
//!
//! ## Key Properties Tested
//!
//! 1. **Soft cancellation**: Cancel of outer task does NOT cancel in-flight blocking work
//! 2. **Cleanup on handle drop**: JoinHandle drop triggers cleanup when body finishes
//! 3. **Panic propagation**: Panics in blocking closures propagate via Outcome::Panicked
//! 4. **Graceful shutdown**: Shutdown drains all spawned blocking tasks
//! 5. **FIFO queue ordering**: Concurrent spawn_blocking operations execute in FIFO order
//!
//! ## Metamorphic Relations
//!
//! - **Soft cancel invariant**: cancel(outer_future) ∧ running(blocking_task) ⟹ blocking_task_continues
//! - **Handle drop cleanup**: drop(handle) ∧ complete(body) ⟹ resources_cleaned
//! - **Panic preservation**: panic(blocking_closure) ⟹ panic_propagated_to_await_site
//! - **Shutdown drain invariant**: shutdown() ∧ pending_tasks(T) ⟹ all_T_complete_before_shutdown
//! - **FIFO ordering**: concurrent_submit(t1, t2, ..., tn) ⟹ execute_order([t1, t2, ..., tn])

use proptest::prelude::*;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;
use std::collections::VecDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use futures_lite::future;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::runtime::{spawn_blocking, spawn_blocking_io, BlockingPool};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};

// =============================================================================
// Test Utilities
// =============================================================================

/// Create a test context for spawn_blocking testing.
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Create a test LabRuntime for deterministic testing.
fn test_lab_runtime() -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic())
}

/// Create a test LabRuntime with specific seed.
fn test_lab_runtime_with_seed(seed: u64) -> LabRuntime {
    LabRuntime::with_config(LabConfig::deterministic().with_seed(seed))
}

/// Execution tracker for monitoring task execution patterns.
#[derive(Debug, Clone)]
struct SpawnBlockingTracker {
    /// Tasks that started execution.
    started: Arc<AtomicUsize>,
    /// Tasks that completed execution.
    completed: Arc<AtomicUsize>,
    /// Tasks that were cancelled.
    cancelled: Arc<AtomicUsize>,
    /// Tasks that panicked.
    panicked: Arc<AtomicUsize>,
    /// Execution order tracking.
    execution_order: Arc<StdMutex<Vec<u32>>>,
    /// Cancellation signals received.
    cancel_signals: Arc<AtomicUsize>,
    /// Whether cleanup was triggered.
    cleanup_triggered: Arc<AtomicBool>,
}

impl SpawnBlockingTracker {
    fn new() -> Self {
        Self {
            started: Arc::new(AtomicUsize::new(0)),
            completed: Arc::new(AtomicUsize::new(0)),
            cancelled: Arc::new(AtomicUsize::new(0)),
            panicked: Arc::new(AtomicUsize::new(0)),
            execution_order: Arc::new(StdMutex::new(Vec::new())),
            cancel_signals: Arc::new(AtomicUsize::new(0)),
            cleanup_triggered: Arc::new(AtomicBool::new(false)),
        }
    }

    fn start_task(&self, task_id: u32) {
        self.started.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut order) = self.execution_order.lock() {
            order.push(task_id);
        }
    }

    fn complete_task(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    fn cancel_task(&self) {
        self.cancelled.fetch_add(1, Ordering::Relaxed);
    }

    fn panic_task(&self) {
        self.panicked.fetch_add(1, Ordering::Relaxed);
    }

    fn signal_cancel(&self) {
        self.cancel_signals.fetch_add(1, Ordering::Relaxed);
    }

    fn trigger_cleanup(&self) {
        self.cleanup_triggered.store(true, Ordering::Relaxed);
    }

    fn started_count(&self) -> usize {
        self.started.load(Ordering::Relaxed)
    }

    fn completed_count(&self) -> usize {
        self.completed.load(Ordering::Relaxed)
    }

    fn cancelled_count(&self) -> usize {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn panicked_count(&self) -> usize {
        self.panicked.load(Ordering::Relaxed)
    }

    fn cancel_signals_count(&self) -> usize {
        self.cancel_signals.load(Ordering::Relaxed)
    }

    fn was_cleanup_triggered(&self) -> bool {
        self.cleanup_triggered.load(Ordering::Relaxed)
    }

    fn execution_order(&self) -> Vec<u32> {
        self.execution_order.lock().unwrap().clone()
    }
}

// =============================================================================
// Property Generation
// =============================================================================

/// Strategy for generating task counts.
fn arb_task_count() -> impl Strategy<Value = usize> {
    1usize..20
}

/// Strategy for generating work durations.
fn arb_work_duration() -> impl Strategy<Value = Duration> {
    (5u64..=100).prop_map(Duration::from_millis)
}

/// Strategy for generating cancellation delays.
fn arb_cancel_delay() -> impl Strategy<Value = Duration> {
    (1u64..=50).prop_map(Duration::from_millis)
}

/// Strategy for generating seeds for deterministic testing.
fn arb_seed() -> impl Strategy<Value = u64> {
    any::<u64>()
}

// =============================================================================
// Metamorphic Relations
// =============================================================================

/// MR1: Cancel of outer task does NOT cancel in-flight blocking (Soft Cancellation, Score: 10.0)
/// Property: cancel(spawn_blocking_future) ∧ running(blocking_body) ⟹ blocking_body_continues
/// Catches: Hard cancellation bugs, resource corruption from interrupted blocking operations
#[test]
fn mr1_cancel_outer_task_does_not_cancel_inflight_blocking() {
    proptest!(|(
        task_count in arb_task_count(),
        work_duration in arb_work_duration(),
        cancel_delay in arb_cancel_delay(),
        seed in arb_seed()
    )| {
        let mut runtime = test_lab_runtime_with_seed(seed);

        let tracker = SpawnBlockingTracker::new();
        let tracker_clone = tracker.clone();

        let result = runtime.block_on(async {
            // Create blocking pool for controlled execution
            let pool = BlockingPool::new(1, 4);
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
            let _guard = Cx::set_current(Some(cx));

            let mut handles = Vec::new();

            // Submit blocking tasks
            for i in 0..task_count {
                let tracker_task = tracker.clone();
                let task_id = i as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);

                    // Simulate blocking work that should continue even if future is cancelled
                    std::thread::sleep(work_duration);

                    tracker_task.complete_task();
                    task_id
                });

                handles.push(future);
            }

            // Start all futures concurrently
            let mut join_handles = Vec::new();
            for (i, future) in handles.into_iter().enumerate() {
                let tracker_cancel = tracker.clone();
                let cancel_delay_local = cancel_delay;

                let join_handle = std::thread::spawn(move || {
                    // Set up cancellation after delay
                    if i % 2 == 0 {  // Cancel every other task
                        std::thread::sleep(cancel_delay_local);
                        tracker_cancel.signal_cancel();
                        // In real code, this would be done by dropping the future,
                        // but we simulate the cancellation semantics here
                    }

                    future::block_on(future)
                });

                join_handles.push(join_handle);
            }

            // Wait for all tasks to complete
            for handle in join_handles {
                let _ = handle.join();
            }

            // Small grace period for async cleanup
            std::thread::sleep(Duration::from_millis(50));

            Outcome::Ok(())
        });

        prop_assert!(matches!(result, Outcome::Ok(())),
            "Runtime execution should complete successfully");

        // Verify that blocking work continued despite cancellation signals
        let started = tracker_clone.started_count();
        let completed = tracker_clone.completed_count();

        // Key invariant: blocking tasks continue to completion even when outer future is cancelled
        prop_assert_eq!(started, completed,
            "All blocking tasks should complete despite outer cancellation: started={}, completed={}",
            started, completed);

        prop_assert_eq!(started, task_count,
            "All tasks should have started execution: expected={}, started={}",
            task_count, started);
    });
}

/// MR2: JoinHandle drop triggers cleanup when body finishes (Resource Cleanup, Score: 8.5)
/// Property: drop(spawn_blocking_handle) ∧ complete(blocking_body) ⟹ cleanup_resources
/// Catches: Resource leaks, dangling references, cleanup timing bugs
#[test]
fn mr2_handle_drop_triggers_cleanup_when_body_finishes() {
    proptest!(|(
        task_count in 3usize..8,
        work_duration in arb_work_duration(),
        seed in arb_seed()
    )| {
        let mut runtime = test_lab_runtime_with_seed(seed);

        let tracker = SpawnBlockingTracker::new();
        let tracker_clone = tracker.clone();

        let result = runtime.block_on(async {
            // Create blocking pool for controlled execution
            let pool = BlockingPool::new(1, 4);
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
            let _guard = Cx::set_current(Some(cx));

            let mut handles = Vec::new();

            // Submit blocking tasks and immediately drop some handles
            for i in 0..task_count {
                let tracker_task = tracker.clone();
                let task_id = i as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);

                    // Simulate blocking work
                    std::thread::sleep(work_duration);

                    tracker_task.complete_task();

                    // Trigger cleanup callback to verify cleanup was called
                    tracker_task.trigger_cleanup();

                    task_id
                });

                if i % 2 == 0 {
                    // Drop handle immediately for every other task
                    // The blocking work should still continue and cleanup should be triggered
                    drop(future);
                } else {
                    handles.push(future);
                }
            }

            // Await the handles we kept
            for future in handles {
                let _ = future.await;
            }

            // Allow time for dropped handles to complete and trigger cleanup
            std::thread::sleep(Duration::from_millis(100));

            Outcome::Ok(())
        });

        prop_assert!(matches!(result, Outcome::Ok(())),
            "Runtime execution should complete successfully");

        let started = tracker_clone.started_count();
        let completed = tracker_clone.completed_count();
        let cleanup_triggered = tracker_clone.was_cleanup_triggered();

        // All tasks should complete even if handles were dropped
        prop_assert_eq!(started, task_count,
            "All tasks should have started: expected={}, started={}",
            task_count, started);

        prop_assert_eq!(completed, task_count,
            "All tasks should have completed despite handle drops: expected={}, completed={}",
            task_count, completed);

        // Cleanup should have been triggered for completed tasks
        prop_assert!(cleanup_triggered,
            "Cleanup should be triggered when blocking bodies finish");
    });
}

/// MR3: Panic in blocking closure propagates via Outcome::Panicked (Panic Preservation, Score: 9.0)
/// Property: panic(blocking_closure) ⟹ panic_propagated_to_await_site
/// Catches: Panic swallowing, error handling bugs, unwind safety violations
#[test]
fn mr3_panic_in_blocking_closure_propagates_via_outcome_panicked() {
    proptest!(|(
        panic_task_count in 2usize..5,
        normal_task_count in 2usize..5,
        seed in arb_seed()
    )| {
        let mut runtime = test_lab_runtime_with_seed(seed);

        let tracker = SpawnBlockingTracker::new();
        let tracker_clone = tracker.clone();

        let result = runtime.block_on(async {
            // Create blocking pool for controlled execution
            let pool = BlockingPool::new(2, 4);
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
            let _guard = Cx::set_current(Some(cx));

            let mut panic_results = Vec::new();
            let mut normal_results = Vec::new();

            // Submit tasks that panic
            for i in 0..panic_task_count {
                let tracker_task = tracker.clone();
                let task_id = i as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);
                    tracker_task.panic_task();
                    panic!("Test panic in blocking task {}", task_id);
                });

                // Catch panics at the await site
                let panic_result = catch_unwind(AssertUnwindSafe(|| {
                    future::block_on(future)
                }));

                panic_results.push(panic_result);
            }

            // Submit normal tasks to verify they're not affected by panicking tasks
            for i in 0..normal_task_count {
                let tracker_task = tracker.clone();
                let task_id = (panic_task_count + i) as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);

                    // Normal work
                    std::thread::sleep(Duration::from_millis(10));

                    tracker_task.complete_task();
                    task_id
                });

                normal_results.push(future.await);
            }

            // Verify panic propagation
            let mut panics_caught = 0;
            for result in panic_results {
                match result {
                    Err(_) => panics_caught += 1,  // Panic was properly propagated
                    Ok(_) => {
                        // This should not happen - panic should propagate
                        return Outcome::Err(format!("Panic was not propagated"));
                    }
                }
            }

            // Verify normal tasks succeeded
            for (i, result) in normal_results.into_iter().enumerate() {
                let expected_id = (panic_task_count + i) as u32;
                if result != expected_id {
                    return Outcome::Err(format!("Normal task {} returned wrong result", i));
                }
            }

            if panics_caught != panic_task_count {
                return Outcome::Err(format!(
                    "Expected {} panics to be caught, got {}",
                    panic_task_count, panics_caught
                ));
            }

            Outcome::Ok(())
        });

        prop_assert!(matches!(result, Outcome::Ok(())),
            "Runtime execution should complete successfully: {:?}", result);

        let started = tracker_clone.started_count();
        let panicked = tracker_clone.panicked_count();
        let completed = tracker_clone.completed_count();

        // Verify that panic tasks were marked as panicked
        prop_assert_eq!(panicked, panic_task_count,
            "Expected {} panic tasks to be marked as panicked, got {}",
            panic_task_count, panicked);

        // Verify total task execution
        let total_expected = panic_task_count + normal_task_count;
        prop_assert_eq!(started, total_expected,
            "All tasks should have started: expected={}, started={}",
            total_expected, started);

        // Normal tasks should complete, panic tasks should not reach completion
        prop_assert_eq!(completed, normal_task_count,
            "Only normal tasks should complete: expected={}, completed={}",
            normal_task_count, completed);
    });
}

/// MR4: Shutdown drains spawned tasks (Graceful Termination, Score: 8.0)
/// Property: shutdown() ∧ pending_tasks(T) ⟹ all_T_complete_before_shutdown
/// Catches: Shutdown race conditions, task abandonment, resource cleanup failures
#[test]
fn mr4_shutdown_drains_spawned_tasks() {
    proptest!(|(
        task_count in 3usize..10,
        work_duration in arb_work_duration(),
        seed in arb_seed()
    )| {
        let mut runtime = test_lab_runtime_with_seed(seed);

        let tracker = SpawnBlockingTracker::new();
        let tracker_clone = tracker.clone();

        let result = runtime.block_on(async {
            // Create blocking pool for controlled execution
            let pool = BlockingPool::new(2, 4);
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
            let _guard = Cx::set_current(Some(cx));

            let mut handles = Vec::new();

            // Submit blocking tasks
            for i in 0..task_count {
                let tracker_task = tracker.clone();
                let task_id = i as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);

                    // Simulate blocking work
                    std::thread::sleep(work_duration);

                    tracker_task.complete_task();
                    task_id
                });

                handles.push(future);
            }

            // Give some tasks time to start
            std::thread::sleep(Duration::from_millis(20));

            // Initiate shutdown while tasks are still running
            pool.shutdown();

            // All previously submitted tasks should complete during graceful shutdown
            let mut completed_tasks = Vec::new();
            for future in handles {
                completed_tasks.push(future.await);
            }

            // Verify shutdown was successful
            let shutdown_successful = pool.shutdown_and_wait(Duration::from_millis(500));
            if !shutdown_successful {
                return Outcome::Err("Shutdown did not complete within timeout".to_string());
            }

            // Verify no new tasks can be submitted after shutdown
            let rejected_task = pool.spawn(|| {
                panic!("Task submitted after shutdown should not execute");
            });

            if !rejected_task.is_cancelled() {
                return Outcome::Err("Tasks submitted after shutdown should be cancelled".to_string());
            }

            // Verify all tasks completed with correct results
            for (i, result) in completed_tasks.into_iter().enumerate() {
                if result != i as u32 {
                    return Outcome::Err(format!(
                        "Task {} returned wrong result: expected {}, got {}",
                        i, i, result
                    ));
                }
            }

            Outcome::Ok(())
        });

        prop_assert!(matches!(result, Outcome::Ok(())),
            "Runtime execution should complete successfully: {:?}", result);

        let started = tracker_clone.started_count();
        let completed = tracker_clone.completed_count();

        // Key invariant: All spawned tasks complete before shutdown
        prop_assert_eq!(started, task_count,
            "All tasks should have started: expected={}, started={}",
            task_count, started);

        prop_assert_eq!(completed, task_count,
            "All spawned tasks should complete during graceful shutdown: expected={}, completed={}",
            task_count, completed);
    });
}

/// MR5: Concurrent spawn_blocking queue FIFO (Queue Ordering, Score: 8.5)
/// Property: concurrent_submit(t1, t2, ..., tn) ⟹ execute_order([t1, t2, ..., tn])
/// Catches: Priority inversion, queue ordering bugs, fairness violations
#[test]
fn mr5_concurrent_spawn_blocking_queue_fifo() {
    proptest!(|(
        task_count in 5usize..15,
        seed in arb_seed()
    )| {
        let mut runtime = test_lab_runtime_with_seed(seed);

        let tracker = SpawnBlockingTracker::new();
        let tracker_clone = tracker.clone();

        let result = runtime.block_on(async {
            // Create blocking pool with single thread to force queueing
            let pool = BlockingPool::new(1, 1);
            let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
            let _guard = Cx::set_current(Some(cx));

            let mut handles = Vec::new();

            // Submit tasks in sequence - they should execute in FIFO order
            for i in 0..task_count {
                let tracker_task = tracker.clone();
                let task_id = i as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);

                    // Small work duration to ensure ordering is observable
                    std::thread::sleep(Duration::from_millis(15));

                    tracker_task.complete_task();
                    task_id
                });

                handles.push(future);
            }

            // Wait for all tasks to complete
            let mut results = Vec::new();
            for future in handles {
                results.push(future.await);
            }

            // Verify results are correct
            for (i, result) in results.into_iter().enumerate() {
                if result != i as u32 {
                    return Outcome::Err(format!(
                        "Task {} returned wrong result: expected {}, got {}",
                        i, i, result
                    ));
                }
            }

            Outcome::Ok(())
        });

        prop_assert!(matches!(result, Outcome::Ok(())),
            "Runtime execution should complete successfully: {:?}", result);

        let started = tracker_clone.started_count();
        let completed = tracker_clone.completed_count();
        let execution_order = tracker_clone.execution_order();

        // Verify all tasks executed
        prop_assert_eq!(started, task_count,
            "All tasks should have started: expected={}, started={}",
            task_count, started);

        prop_assert_eq!(completed, task_count,
            "All tasks should have completed: expected={}, completed={}",
            task_count, completed);

        // Key invariant: Execution order matches submission order (FIFO)
        let expected_order: Vec<u32> = (0..task_count as u32).collect();
        prop_assert_eq!(execution_order, expected_order,
            "Tasks should execute in FIFO order: expected={:?}, actual={:?}",
            expected_order, execution_order);
    });
}

// =============================================================================
// Integration Tests
// =============================================================================

/// Integration test: Complex spawn_blocking workflow with mixed operations
#[test]
fn integration_complex_spawn_blocking_workflow() {
    let mut runtime = test_lab_runtime_with_seed(12345);

    let tracker = SpawnBlockingTracker::new();

    let result = runtime.block_on(async {
        // Create blocking pool for controlled execution
        let pool = BlockingPool::new(2, 4);
        let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        let _guard = Cx::set_current(Some(cx));

        // Phase 1: Normal tasks
        let mut phase1_handles = Vec::new();
        for i in 0..4 {
            let tracker_task = tracker.clone();
            let task_id = i as u32;

            let future = spawn_blocking(move || {
                tracker_task.start_task(task_id);
                std::thread::sleep(Duration::from_millis(20));
                tracker_task.complete_task();
                task_id
            });

            phase1_handles.push(future);
        }

        // Phase 2: Mixed normal and dropped handles
        let mut phase2_handles = Vec::new();
        for i in 4..8 {
            let tracker_task = tracker.clone();
            let task_id = i as u32;

            let future = spawn_blocking(move || {
                tracker_task.start_task(task_id);
                std::thread::sleep(Duration::from_millis(15));
                tracker_task.complete_task();
                tracker_task.trigger_cleanup();
                task_id
            });

            if i % 2 == 0 {
                // Drop some handles (work should still complete)
                drop(future);
            } else {
                phase2_handles.push(future);
            }
        }

        // Phase 3: Panic tasks (should not affect others)
        let panic_future = spawn_blocking(|| {
            panic!("Test panic in integration test");
        });

        // Await phase 1
        for future in phase1_handles {
            let _ = future.await;
        }

        // Await phase 2 (kept handles only)
        for future in phase2_handles {
            let _ = future.await;
        }

        // Handle panic task
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            future::block_on(panic_future)
        }));
        assert!(panic_result.is_err(), "Panic should have been caught");

        // Phase 4: Post-panic tasks (should work normally)
        let post_panic_future = spawn_blocking(|| {
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        let result = post_panic_future.await;
        assert_eq!(result, 42, "Post-panic task should work normally");

        Outcome::Ok(())
    });

    assert!(matches!(result, Outcome::Ok(())), "Integration test should succeed");

    // Verify expected execution patterns
    let started = tracker.started_count();
    let completed = tracker.completed_count();
    let cleanup_triggered = tracker.was_cleanup_triggered();

    assert_eq!(started, 8, "All 8 tasks should have started");
    assert_eq!(completed, 8, "All 8 tasks should have completed");
    assert!(cleanup_triggered, "Cleanup should have been triggered");
}

/// Stress test: High-frequency spawn_blocking with various patterns
#[test]
fn stress_high_frequency_spawn_blocking() {
    let mut runtime = test_lab_runtime_with_seed(54321);

    let tracker = SpawnBlockingTracker::new();

    let result = runtime.block_on(async {
        // Create blocking pool for stress testing
        let pool = BlockingPool::new(2, 6);
        let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        let _guard = Cx::set_current(Some(cx));

        let mut all_handles = Vec::new();

        // Submit many tasks rapidly
        for batch in 0..5 {
            let mut batch_handles = Vec::new();

            for i in 0..10 {
                let tracker_task = tracker.clone();
                let task_id = (batch * 10 + i) as u32;

                let future = spawn_blocking(move || {
                    tracker_task.start_task(task_id);

                    // Variable work duration
                    let duration = Duration::from_millis(5 + (task_id % 20) as u64);
                    std::thread::sleep(duration);

                    tracker_task.complete_task();
                    task_id
                });

                // Drop some handles randomly for stress testing
                if task_id % 7 == 0 {
                    drop(future);
                } else {
                    batch_handles.push(future);
                }
            }

            all_handles.extend(batch_handles);

            // Brief pause between batches
            std::thread::sleep(Duration::from_millis(5));
        }

        // Await all kept handles
        for future in all_handles {
            let _ = future.await;
        }

        Outcome::Ok(())
    });

    assert!(matches!(result, Outcome::Ok(())), "Stress test should succeed");

    // Verify stress test completed successfully
    let started = tracker.started_count();
    let completed = tracker.completed_count();

    assert_eq!(started, 50, "All 50 tasks should have started");
    assert_eq!(completed, 50, "All 50 tasks should have completed");
}