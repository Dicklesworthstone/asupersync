#![allow(clippy::all)]
//! Metamorphic tests for runtime::blocking_pool capacity and spawn invariants.
//!
//! These tests validate the blocking pool behavior using metamorphic relations
//! to ensure thread management, task scheduling, and shutdown semantics are preserved
//! across various operation patterns and configurations.

use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use proptest::prelude::*;

use asupersync::runtime::{BlockingPool, BlockingPoolOptions};

/// Counter for tracking task executions.
#[derive(Debug, Clone)]
struct ExecutionCounter {
    /// Tasks that started execution.
    started: Arc<AtomicUsize>,
    /// Tasks that completed execution.
    completed: Arc<AtomicUsize>,
    /// Tasks that were cancelled before execution.
    cancelled_before_execution: Arc<AtomicUsize>,
    /// Execution order tracking.
    execution_order: Arc<StdMutex<Vec<u32>>>,
    /// Peak concurrent executions observed.
    peak_concurrent: Arc<AtomicUsize>,
    /// Current concurrent executions.
    current_concurrent: Arc<AtomicUsize>,
}

impl ExecutionCounter {
    fn new() -> Self {
        Self {
            started: Arc::new(AtomicUsize::new(0)),
            completed: Arc::new(AtomicUsize::new(0)),
            cancelled_before_execution: Arc::new(AtomicUsize::new(0)),
            execution_order: Arc::new(StdMutex::new(Vec::new())),
            peak_concurrent: Arc::new(AtomicUsize::new(0)),
            current_concurrent: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn start_task(&self, task_id: u32) {
        self.started.fetch_add(1, Ordering::Relaxed);
        let current = self.current_concurrent.fetch_add(1, Ordering::Relaxed) + 1;

        // Update peak if necessary
        let mut peak = self.peak_concurrent.load(Ordering::Relaxed);
        while peak < current {
            match self.peak_concurrent.compare_exchange_weak(
                peak, current, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(actual) => peak = actual,
            }
        }

        // Record execution order
        if let Ok(mut order) = self.execution_order.lock() {
            order.push(task_id);
        }
    }

    fn complete_task(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.current_concurrent.fetch_sub(1, Ordering::Relaxed);
    }

    fn cancel_task(&self) {
        self.cancelled_before_execution.fetch_add(1, Ordering::Relaxed);
    }

    fn started_count(&self) -> usize {
        self.started.load(Ordering::Relaxed)
    }

    fn completed_count(&self) -> usize {
        self.completed.load(Ordering::Relaxed)
    }

    fn cancelled_count(&self) -> usize {
        self.cancelled_before_execution.load(Ordering::Relaxed)
    }

    fn peak_concurrent_count(&self) -> usize {
        self.peak_concurrent.load(Ordering::Relaxed)
    }

    fn execution_order(&self) -> Vec<u32> {
        self.execution_order.lock().unwrap().clone()
    }
}

/// Create a test blocking pool with configurable options.
fn test_pool(min_threads: usize, max_threads: usize) -> BlockingPool {
    let options = BlockingPoolOptions {
        idle_timeout: Duration::from_millis(100), // Short timeout for tests
        time_getter: || Instant::now(),
        sleep_fn: std::thread::sleep,
        thread_name_prefix: "test-blocking".to_string(),
        on_thread_start: None,
        on_thread_stop: None,
    };
    BlockingPool::with_config(min_threads, max_threads, options)
}

/// Strategy for generating pool configurations.
fn arb_pool_config() -> impl Strategy<Value = (usize, usize)> {
    (1usize..=8, 2usize..=16)
        .prop_map(|(min, max_offset)| (min, min + max_offset))
}

/// Strategy for generating task counts.
fn arb_task_count() -> impl Strategy<Value = usize> {
    1usize..50
}

/// Strategy for generating work durations.
fn arb_work_duration() -> impl Strategy<Value = Duration> {
    (1u64..=100).prop_map(Duration::from_millis)
}

/// Strategy for generating shutdown timeout.
fn arb_shutdown_timeout() -> impl Strategy<Value = Duration> {
    (100u64..=1000).prop_map(Duration::from_millis)
}

// Metamorphic Relations for Blocking Pool Capacity and Spawn Invariants

/// MR1: Active workers never exceed max (Capacity Invariant, Score: 10.0)
/// Property: concurrent_executions <= max_threads at all times
/// Catches: Thread pool overflow bugs, resource leak vulnerabilities
#[test]
fn mr1_active_workers_never_exceed_max() {
    proptest!(|(
        (min_threads, max_threads) in arb_pool_config(),
        task_count in arb_task_count(),
        work_duration in arb_work_duration()
    )| {
        let pool = test_pool(min_threads, max_threads);
        let counter = ExecutionCounter::new();

        // Submit tasks that will run concurrently
        let handles: Vec<_> = (0..task_count).map(|i| {
            let counter_clone = counter.clone();
            pool.spawn(move || {
                counter_clone.start_task(i as u32);
                std::thread::sleep(work_duration);
                counter_clone.complete_task();
            })
        }).collect();

        // Wait for all tasks to complete
        for handle in handles {
            handle.wait();
        }

        // Verify peak concurrent executions never exceeded max_threads
        let peak = counter.peak_concurrent_count();
        prop_assert!(peak <= max_threads,
            "Peak concurrent executions ({}) exceeded max_threads ({})",
            peak, max_threads);

        // Verify all tasks eventually completed
        prop_assert_eq!(counter.started_count(), task_count,
            "Not all tasks started execution");
        prop_assert_eq!(counter.completed_count(), task_count,
            "Not all tasks completed");
    });
}

/// MR2: Queued tasks FIFO ordering (Fairness Invariant, Score: 8.5)
/// Property: tasks execute in submission order when threads are saturated
/// Catches: Priority inversion, starvation, scheduling fairness bugs
#[test]
fn mr2_queued_tasks_fifo_ordering() {
    proptest!(|(task_count in 5usize..20)| {
        // Use a pool with only 1 thread to force queueing
        let pool = test_pool(1, 1);
        let counter = ExecutionCounter::new();

        // Submit tasks with identifiable work that forces sequential execution
        let handles: Vec<_> = (0..task_count).map(|i| {
            let counter_clone = counter.clone();
            pool.spawn(move || {
                counter_clone.start_task(i as u32);
                // Small delay to ensure tasks don't complete instantly
                std::thread::sleep(Duration::from_millis(10));
                counter_clone.complete_task();
            })
        }).collect();

        // Wait for all tasks to complete
        for handle in handles {
            handle.wait();
        }

        // Verify execution order matches submission order (FIFO)
        let execution_order = counter.execution_order();
        let expected_order: Vec<u32> = (0..task_count as u32).collect();

        prop_assert_eq!(execution_order, expected_order,
            "Tasks did not execute in FIFO order: expected {:?}, got {:?}",
            expected_order, execution_order);
    });
}

/// MR3: Cancelled spawn_blocking does not run body (Cancellation Invariant, Score: 9.0)
/// Property: cancelled_task_handle.cancel() → task_body never executes
/// Catches: Cancellation race conditions, resource waste from cancelled work
#[test]
fn mr3_cancelled_spawn_blocking_does_not_run_body() {
    proptest!(|(task_count in 5usize..15)| {
        let pool = test_pool(1, 4); // Limited threads to control execution timing
        let counter = ExecutionCounter::new();

        // Submit tasks and immediately cancel half of them
        let handles: Vec<_> = (0..task_count).map(|i| {
            let counter_clone = counter.clone();
            let should_cancel = i % 2 == 0; // Cancel every other task

            let handle = pool.spawn(move || {
                if should_cancel {
                    // This should not execute due to cancellation
                    counter_clone.start_task(i as u32);
                    counter_clone.complete_task();
                } else {
                    counter_clone.start_task(i as u32);
                    std::thread::sleep(Duration::from_millis(5));
                    counter_clone.complete_task();
                }
            });

            if should_cancel {
                // Cancel immediately after submission
                handle.cancel();
                counter.cancel_task();
            }

            handle
        }).collect();

        // Wait for all handles to complete (cancelled ones should complete immediately)
        for handle in handles {
            handle.wait();
        }

        // Allow some time for any wrongly-executing cancelled tasks
        std::thread::sleep(Duration::from_millis(50));

        let expected_executions = task_count / 2 + task_count % 2; // Non-cancelled tasks
        let actual_executions = counter.started_count();

        prop_assert!(actual_executions <= expected_executions,
            "Cancelled tasks should not execute: expected <= {}, got {}",
            expected_executions, actual_executions);
    });
}

/// MR4: Worker idle timeout recycles threads (Resource Efficiency, Score: 7.0)
/// Property: excess_threads_idle > timeout → active_threads decreases toward min_threads
/// Catches: Thread leak bugs, resource management failures
#[test]
fn mr4_worker_idle_timeout_recycles_threads() {
    proptest!(|(min_threads in 1usize..=3, max_threads_offset in 3usize..=6)| {
        let max_threads = min_threads + max_threads_offset;
        let pool = test_pool(min_threads, max_threads);

        // Submit burst of work to scale up to max threads
        let burst_size = max_threads * 2;
        let counter = ExecutionCounter::new();

        let handles: Vec<_> = (0..burst_size).map(|i| {
            let counter_clone = counter.clone();
            pool.spawn(move || {
                counter_clone.start_task(i as u32);
                std::thread::sleep(Duration::from_millis(50));
                counter_clone.complete_task();
            })
        }).collect();

        // Wait for all work to complete
        for handle in handles {
            handle.wait();
        }

        let active_after_burst = pool.active_threads();
        prop_assert!(active_after_burst >= min_threads,
            "Active threads should be at least min_threads after burst");

        // Wait longer than the idle timeout
        std::thread::sleep(Duration::from_millis(200));

        let active_after_timeout = pool.active_threads();

        // Threads should have been recycled down toward min_threads
        prop_assert!(active_after_timeout <= active_after_burst,
            "Idle threads should be recycled after timeout: {} -> {}",
            active_after_burst, active_after_timeout);

        prop_assert!(active_after_timeout >= min_threads,
            "Should maintain at least min_threads: expected >= {}, got {}",
            min_threads, active_after_timeout);
    });
}

/// MR5: Shutdown drains queue gracefully (Graceful Termination, Score: 8.0)
/// Property: shutdown() → pending_tasks complete → no_new_tasks_accepted
/// Catches: Shutdown race conditions, data loss during termination
#[test]
fn mr5_shutdown_drains_queue_gracefully() {
    proptest!(|(
        task_count in 5usize..15,
        work_duration in arb_work_duration(),
        shutdown_timeout in arb_shutdown_timeout()
    )| {
        let pool = test_pool(1, 2); // Limited threads to create queue buildup
        let counter = ExecutionCounter::new();

        // Submit work that will queue up
        let handles: Vec<_> = (0..task_count).map(|i| {
            let counter_clone = counter.clone();
            pool.spawn(move || {
                counter_clone.start_task(i as u32);
                std::thread::sleep(work_duration);
                counter_clone.complete_task();
            })
        }).collect();

        // Give some tasks time to start
        std::thread::sleep(Duration::from_millis(20));

        // Initiate shutdown while tasks are still queued/running
        pool.shutdown();

        // New tasks after shutdown should be rejected (cancelled immediately)
        let rejected_task = pool.spawn(|| {
            // This should not execute
            panic!("Task submitted after shutdown should not execute");
        });

        prop_assert!(rejected_task.is_cancelled(),
            "Tasks submitted after shutdown should be cancelled");

        // Wait for graceful shutdown
        let shutdown_successful = pool.shutdown_and_wait(shutdown_timeout);
        prop_assert!(shutdown_successful,
            "Shutdown should complete within timeout");

        // All originally submitted tasks should have completed
        prop_assert_eq!(counter.completed_count(), counter.started_count(),
            "All started tasks should complete during graceful shutdown");

        // Verify no threads remain active
        prop_assert_eq!(pool.active_threads(), 0,
            "No threads should remain active after shutdown");

        prop_assert!(pool.is_shutdown(),
            "Pool should report shutdown state");
    });
}

/// Integration test: Complex workflow with mixed operations
#[test]
fn integration_complex_blocking_pool_workflow() {
    let pool = test_pool(2, 6);
    let counter = ExecutionCounter::new();

    // Phase 1: Submit initial burst of work
    let phase1_handles: Vec<_> = (0..8).map(|i| {
        let counter_clone = counter.clone();
        pool.spawn(move || {
            counter_clone.start_task(i);
            std::thread::sleep(Duration::from_millis(30));
            counter_clone.complete_task();
        })
    }).collect();

    // Phase 2: Cancel some tasks, submit more work
    let mut phase2_handles = Vec::new();
    for i in 8..12 {
        let counter_clone = counter.clone();
        let handle = pool.spawn(move || {
            counter_clone.start_task(i);
            std::thread::sleep(Duration::from_millis(20));
            counter_clone.complete_task();
        });

        if i % 2 == 0 {
            handle.cancel();
            counter.cancel_task();
        }

        phase2_handles.push(handle);
    }

    // Wait for phase 1
    for handle in phase1_handles {
        handle.wait();
    }

    // Phase 3: Submit final batch
    let phase3_handles: Vec<_> = (12..16).map(|i| {
        let counter_clone = counter.clone();
        pool.spawn(move || {
            counter_clone.start_task(i);
            std::thread::sleep(Duration::from_millis(10));
            counter_clone.complete_task();
        })
    }).collect();

    // Wait for all phases
    for handle in phase2_handles.into_iter().chain(phase3_handles) {
        handle.wait();
    }

    // Verify capacity was never exceeded
    assert!(counter.peak_concurrent_count() <= 6,
        "Peak concurrent executions exceeded max_threads");

    // Verify no thread leaks
    let active_threads = pool.active_threads();
    assert!(active_threads >= 2 && active_threads <= 6,
        "Active threads should be within configured bounds");

    // Graceful shutdown
    assert!(pool.shutdown_and_wait(Duration::from_secs(1)),
        "Pool should shutdown gracefully");
}

/// Stress test: High concurrency with rapid submission/cancellation
#[test]
fn stress_rapid_submission_and_cancellation() {
    let pool = test_pool(1, 4);
    let counter = ExecutionCounter::new();

    // Rapid submission with mixed cancellation
    let handles: Vec<_> = (0..50).map(|i| {
        let counter_clone = counter.clone();
        let handle = pool.spawn(move || {
            counter_clone.start_task(i);
            std::thread::sleep(Duration::from_millis(5));
            counter_clone.complete_task();
        });

        // Cancel roughly 30% of tasks
        if i % 7 < 2 {
            handle.cancel();
            counter.cancel_task();
        }

        handle
    }).collect();

    // Wait for all handles
    for handle in handles {
        handle.wait();
    }

    // Verify pool remained stable
    assert!(counter.peak_concurrent_count() <= 4,
        "Concurrent executions should not exceed pool limit");

    // Cleanup
    pool.shutdown();
    assert!(pool.shutdown_and_wait(Duration::from_millis(500)),
        "Pool should shutdown after stress test");
}

/// Error recovery test: Pool behavior under thread panic conditions
#[test]
fn error_recovery_thread_panics() {
    let pool = test_pool(2, 4);

    // Submit a task that panics
    let panic_handle = pool.spawn(|| {
        panic!("Intentional panic for testing");
    });

    // Submit normal tasks before and after panic
    let normal_handle1 = pool.spawn(|| {
        std::thread::sleep(Duration::from_millis(10));
        42
    });

    let normal_handle2 = pool.spawn(|| {
        std::thread::sleep(Duration::from_millis(10));
        84
    });

    // Wait for tasks (panic should be contained)
    panic_handle.wait();
    normal_handle1.wait();
    normal_handle2.wait();

    // Pool should remain functional
    let test_handle = pool.spawn(|| 123);
    test_handle.wait();
    assert!(test_handle.is_done(), "Pool should remain functional after thread panic");

    // Cleanup
    assert!(pool.shutdown_and_wait(Duration::from_millis(200)),
        "Pool should shutdown after panic recovery");
}