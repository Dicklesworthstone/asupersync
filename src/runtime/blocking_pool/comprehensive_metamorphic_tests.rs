//! Comprehensive metamorphic tests for BlockingPool runtime component.
//!
//! These tests verify invariant relationships for the blocking thread pool,
//! addressing the oracle problem for complex concurrent state management.
//! Each test focuses on a specific metamorphic relation derived from
//! thread pool domain properties.
//!
//! This module complements the existing metamorphic.rs fairness tests with
//! broader coverage of thread pool invariants, resource management, and
//! concurrent state properties.

#![allow(dead_code, clippy::pedantic, clippy::nursery, clippy::unwrap_used)]

use proptest::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use super::super::*;

/// Test-specific blocking pool configuration.
#[derive(Debug, Clone)]
struct TestPoolConfig {
    min_threads: usize,
    max_threads: usize,
    idle_timeout_ms: u64,
    affinity_enabled: bool,
    cohort_count: Option<usize>,
}

impl TestPoolConfig {
    fn to_options(&self) -> BlockingPoolOptions {
        use crate::runtime::config::BlockingPoolAffinityProfile;

        let affinity_profile = if self.affinity_enabled && self.cohort_count.is_some() {
            BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 10,
                spill_check_interval: 5,
            }
        } else {
            BlockingPoolAffinityProfile::Disabled
        };

        BlockingPoolOptions {
            idle_timeout: Duration::from_millis(self.idle_timeout_ms),
            affinity_profile,
            cohort_count: self.cohort_count,
            ..Default::default()
        }
    }

    fn create_pool(&self) -> BlockingPool {
        BlockingPool::with_config(self.min_threads, self.max_threads, self.to_options())
    }
}

/// Generate arbitrary valid pool configurations for testing.
fn arb_pool_config() -> impl Strategy<Value = TestPoolConfig> {
    (
        1usize..=4,
        4usize..=8,
        50u64..500,
        any::<bool>(),
        prop::option::of(1usize..4),
    )
        .prop_map(|(min, max, timeout_ms, affinity, cohorts)| {
            let max = max.max(min); // Ensure max >= min
            TestPoolConfig {
                min_threads: min,
                max_threads: max,
                idle_timeout_ms: timeout_ms,
                affinity_enabled: affinity,
                cohort_count: if affinity { cohorts } else { None },
            }
        })
}

/// Test task that can be tracked for completion.
#[derive(Debug, Clone)]
struct TestTask {
    id: u32,
    work_duration_ms: u64,
    should_fail: bool,
    preferred_cohort: Option<usize>,
}

/// Generate arbitrary test tasks.
fn arb_test_task() -> impl Strategy<Value = TestTask> {
    (
        any::<u32>(),
        1u64..100,
        any::<bool>(),
        prop::option::of(0usize..4),
    )
        .prop_map(|(id, duration_ms, should_fail, cohort)| TestTask {
            id,
            work_duration_ms: duration_ms,
            should_fail,
            preferred_cohort: cohort,
        })
}

/// Pool operations for metamorphic testing.
#[derive(Debug, Clone)]
enum PoolOperation {
    SpawnTask { task: TestTask },
    CancelTask { task_index: usize },
    WaitForCompletion { task_index: usize, timeout_ms: u64 },
    DrainAndShutdown,
    CheckMetrics,
}

/// Generate arbitrary pool operations.
fn arb_pool_operation() -> impl Strategy<Value = PoolOperation> {
    prop_oneof![
        arb_test_task().prop_map(|task| PoolOperation::SpawnTask { task }),
        any::<usize>().prop_map(|idx| PoolOperation::CancelTask { task_index: idx }),
        (any::<usize>(), 100u64..1000).prop_map(|(idx, timeout)| {
            PoolOperation::WaitForCompletion {
                task_index: idx,
                timeout_ms: timeout,
            }
        }),
        Just(PoolOperation::DrainAndShutdown),
        Just(PoolOperation::CheckMetrics),
    ]
}

/// Tracked state for a spawned task.
struct TrackedTask {
    id: u32,
    handle: BlockingTaskHandle,
    spawn_time: std::time::Instant,
    expected_duration_ms: u64,
    cancelled: bool,
    completed: bool,
    preferred_cohort: Option<usize>,
}

/// State snapshot for invariant verification.
#[derive(Debug, Clone)]
struct PoolSnapshot {
    active_threads: usize,
    pending_tasks: usize,
    busy_threads: usize,
    total_spawned: usize,
    total_completed: usize,
    total_cancelled: usize,
    total_outstanding: usize,
    is_shutdown: bool,
    min_threads: usize,
    max_threads: usize,
    affinity_enabled: bool,
}

impl PoolSnapshot {
    fn capture(
        pool: &BlockingPool,
        config: &TestPoolConfig,
        tracked_tasks: &[TrackedTask],
    ) -> Self {
        let total_spawned = tracked_tasks.len();
        let total_completed = tracked_tasks
            .iter()
            .filter(|t| t.completed || t.handle.is_done())
            .count();
        let total_cancelled = tracked_tasks
            .iter()
            .filter(|t| t.handle.is_cancelled())
            .count();
        let total_outstanding = total_spawned.saturating_sub(total_completed);

        Self {
            active_threads: pool.active_threads(),
            pending_tasks: pool.pending_count(),
            busy_threads: pool.busy_threads(),
            total_spawned,
            total_completed,
            total_cancelled,
            total_outstanding,
            is_shutdown: pool.is_shutdown(),
            min_threads: config.min_threads,
            max_threads: config.max_threads,
            affinity_enabled: pool.affinity_metrics().enabled,
        }
    }
}

/// Execute a pool operation and update tracked state.
fn apply_operation(
    pool: &BlockingPool,
    operation: &PoolOperation,
    tracked_tasks: &mut Vec<TrackedTask>,
    completion_counter: Arc<AtomicUsize>,
) {
    match operation {
        PoolOperation::SpawnTask { task } => {
            let counter = completion_counter.clone();
            let task_id = task.id;
            let work_duration = Duration::from_millis(task.work_duration_ms);
            let should_fail = task.should_fail;

            let handle = if let Some(cohort) = task.preferred_cohort {
                pool.spawn_on_cohort(cohort, move || {
                    thread::sleep(work_duration);
                    if should_fail {
                        panic!("Simulated task failure");
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                })
            } else {
                pool.spawn(move || {
                    thread::sleep(work_duration);
                    if should_fail {
                        panic!("Simulated task failure");
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                })
            };

            tracked_tasks.push(TrackedTask {
                id: task_id,
                handle,
                spawn_time: std::time::Instant::now(),
                expected_duration_ms: task.work_duration_ms,
                cancelled: false,
                completed: false,
                preferred_cohort: task.preferred_cohort,
            });
        }
        PoolOperation::CancelTask { task_index } => {
            let len = tracked_tasks.len().max(1);
            if let Some(task) = tracked_tasks.get_mut(*task_index % len) {
                if !task.completed && !task.cancelled {
                    task.handle.cancel();
                    task.cancelled = true;
                }
            }
        }
        PoolOperation::WaitForCompletion {
            task_index,
            timeout_ms,
        } => {
            let len = tracked_tasks.len().max(1);
            if let Some(task) = tracked_tasks.get_mut(*task_index % len) {
                if !task.completed {
                    let timeout = Duration::from_millis(*timeout_ms);
                    let _ = task.handle.wait_timeout(timeout);
                    task.completed = task.handle.is_done();
                }
            }
        }
        PoolOperation::DrainAndShutdown => {
            pool.shutdown_and_wait(Duration::from_secs(5));
            // Mark all remaining tasks as completed
            for task in tracked_tasks.iter_mut() {
                if !task.completed {
                    task.completed = true;
                }
            }
        }
        PoolOperation::CheckMetrics => {
            // Just trigger metrics collection - used for state observation
            let _ = (
                pool.active_threads(),
                pool.pending_count(),
                pool.busy_threads(),
            );
        }
    }
}

//
// METAMORPHIC RELATIONS - Core invariants for blocking pool
//

/// MR1: INCLUSIVE - Thread Count Bounds
/// Active thread count must always respect min/max bounds: min ≤ active ≤ max.
#[test]
fn mr_thread_count_bounds() {
    proptest!(|(config in arb_pool_config(), operations in prop::collection::vec(arb_pool_operation(), 0..=30))| {
        let pool = config.create_pool();
        let mut tracked_tasks = Vec::new();
        let completion_counter = Arc::new(AtomicUsize::new(0));

        for op in operations.iter().take(15) {
            apply_operation(&pool, op, &mut tracked_tasks, completion_counter.clone());

            let snapshot = PoolSnapshot::capture(&pool, &config, &tracked_tasks);

            if snapshot.is_shutdown {
                prop_assert_eq!(snapshot.active_threads, 0,
                    "Shutdown pool should retire all threads after operation {:?}", op);
            } else {
                prop_assert!(snapshot.active_threads >= snapshot.min_threads,
                    "Active threads {} below minimum {} after operation {:?}",
                    snapshot.active_threads, snapshot.min_threads, op);

                prop_assert!(snapshot.active_threads <= snapshot.max_threads,
                    "Active threads {} exceeds maximum {} after operation {:?}",
                    snapshot.active_threads, snapshot.max_threads, op);
            }
        }

        // Cleanup
        pool.shutdown_and_wait(Duration::from_secs(5));
    });
}

/// MR2: EQUIVALENCE - Task Conservation
/// Total spawned tasks = completed + outstanding (accounting identity).
#[test]
fn mr_task_conservation() {
    proptest!(|(config in arb_pool_config(), operations in prop::collection::vec(arb_pool_operation(), 0..=30))| {
        let pool = config.create_pool();
        let mut tracked_tasks = Vec::new();
        let completion_counter = Arc::new(AtomicUsize::new(0));

        for op in operations.iter().take(12) {
            apply_operation(&pool, op, &mut tracked_tasks, completion_counter.clone());

            let snapshot = PoolSnapshot::capture(&pool, &config, &tracked_tasks);
            let accounted_tasks = snapshot.total_completed + snapshot.total_outstanding;

            prop_assert_eq!(snapshot.total_spawned, accounted_tasks,
                "Task conservation violated after operation {:?}: spawned={}, completed={}, outstanding={}, cancelled={}",
                op, snapshot.total_spawned, snapshot.total_completed, snapshot.total_outstanding, snapshot.total_cancelled);

            prop_assert!(snapshot.pending_tasks <= snapshot.total_outstanding,
                "Pending queue depth {} exceeded outstanding tasks {} after operation {:?}",
                snapshot.pending_tasks, snapshot.total_outstanding, op);
            prop_assert!(snapshot.busy_threads <= snapshot.total_outstanding,
                "Busy thread count {} exceeded outstanding tasks {} after operation {:?}",
                snapshot.busy_threads, snapshot.total_outstanding, op);
        }

        pool.shutdown_and_wait(Duration::from_secs(5));
    });
}

/// MR3: INCLUSIVE - Busy Threads Constraint
/// Number of busy threads cannot exceed active threads: busy ≤ active.
#[test]
fn mr_busy_threads_constraint() {
    proptest!(|(config in arb_pool_config(), operations in prop::collection::vec(arb_pool_operation(), 0..=30))| {
        let pool = config.create_pool();
        let mut tracked_tasks = Vec::new();
        let completion_counter = Arc::new(AtomicUsize::new(0));

        for op in operations.iter().take(10) {
            apply_operation(&pool, op, &mut tracked_tasks, completion_counter.clone());

            let snapshot = PoolSnapshot::capture(&pool, &config, &tracked_tasks);

            prop_assert!(snapshot.busy_threads <= snapshot.active_threads,
                "Busy threads {} exceeds active threads {} after operation {:?}",
                snapshot.busy_threads, snapshot.active_threads, op);
        }

        pool.shutdown_and_wait(Duration::from_secs(5));
    });
}

/// MR4: MULTIPLICATIVE - Scaling Linearity
/// When doubling task submission rate, pending count should scale proportionally
/// (under saturation conditions).
#[test]
fn mr_scaling_linearity() {
    proptest!(|(base_task_count in 1usize..=50)| {
        let base_task_count = (base_task_count % 8) + 2; // 2-9 tasks
        let config = TestPoolConfig {
            min_threads: 1,
            max_threads: 2, // Keep small to force saturation
            idle_timeout_ms: 1000,
            affinity_enabled: false,
            cohort_count: None,
        };

        let pool1 = config.create_pool();
        let pool2 = config.create_pool();

        // Submit base_task_count tasks to pool1
        for _i in 0..base_task_count {
            pool1.spawn(move || {
                thread::sleep(Duration::from_millis(200)); // Long enough to create backlog
            });
        }

        // Submit 2×base_task_count tasks to pool2
        for _i in 0..(base_task_count * 2) {
            pool2.spawn(move || {
                thread::sleep(Duration::from_millis(200));
            });
        }

        // Allow some time for queue buildup
        thread::sleep(Duration::from_millis(50));

        let queued_or_running1 = pool1.pending_count() + pool1.busy_threads();
        let queued_or_running2 = pool2.pending_count() + pool2.busy_threads();

        // Under saturation, queued-or-running work should scale approximately linearly.
        if queued_or_running1 > 0 && queued_or_running2 > 0 {
            let ratio = queued_or_running2 as f64 / queued_or_running1 as f64;
            prop_assert!((1.5..=2.5).contains(&ratio),
                "Scaling linearity violated: base_in_flight={}, doubled_in_flight={}, ratio={}",
                queued_or_running1, queued_or_running2, ratio);
        }

        pool1.shutdown_and_wait(Duration::from_secs(5));
        pool2.shutdown_and_wait(Duration::from_secs(5));
    });
}

/// MR5: EQUIVALENCE - Cancellation Commutativity
/// Cancel(A) then Cancel(B) should produce same result as Cancel(B) then Cancel(A)
/// for independent tasks.
#[test]
fn mr_cancellation_commutativity() {
    proptest!(|(task_duration_ms in 1u64..=100)| {
        let task_duration_ms = (task_duration_ms % 300) + 100; // 100-399ms
        let config = TestPoolConfig {
            min_threads: 1,
            max_threads: 2,
            idle_timeout_ms: 500,
            affinity_enabled: false,
            cohort_count: None,
        };

        let pool1 = config.create_pool();
        let pool2 = config.create_pool();

        // Pool1: Submit A, B, then Cancel A, Cancel B
        let handle1a = pool1.spawn(move || thread::sleep(Duration::from_millis(task_duration_ms)));
        let handle1b = pool1.spawn(move || thread::sleep(Duration::from_millis(task_duration_ms)));
        handle1a.cancel();
        handle1b.cancel();

        // Pool2: Submit A, B, then Cancel B, Cancel A (reversed order)
        let handle2a = pool2.spawn(move || thread::sleep(Duration::from_millis(task_duration_ms)));
        let handle2b = pool2.spawn(move || thread::sleep(Duration::from_millis(task_duration_ms)));
        handle2b.cancel();
        handle2a.cancel();

        prop_assert!(handle1a.is_cancelled(), "A should be cancelled in pool1");
        prop_assert!(handle1b.is_cancelled(), "B should be cancelled in pool1");
        prop_assert!(handle2a.is_cancelled(), "A should be cancelled in pool2");
        prop_assert!(handle2b.is_cancelled(), "B should be cancelled in pool2");

        prop_assert!(pool1.pending_count() + pool1.busy_threads() <= 2,
            "Pool1 should never report more in-flight work than submitted");
        prop_assert!(pool2.pending_count() + pool2.busy_threads() <= 2,
            "Pool2 should never report more in-flight work than submitted");

        prop_assert!(pool1.shutdown_and_wait(Duration::from_secs(5)),
            "Pool1 should shut down cleanly after cancellation");
        prop_assert!(pool2.shutdown_and_wait(Duration::from_secs(5)),
            "Pool2 should shut down cleanly after cancellation");

        prop_assert_eq!(pool1.pending_count(), 0, "Pool1 should drain queued work");
        prop_assert_eq!(pool2.pending_count(), 0, "Pool2 should drain queued work");
        prop_assert_eq!(pool1.busy_threads(), 0, "Pool1 should have no busy workers");
        prop_assert_eq!(pool2.busy_threads(), 0, "Pool2 should have no busy workers");
        prop_assert!(handle1a.is_done(), "Pool1 task A should reach a terminal state");
        prop_assert!(handle1b.is_done(), "Pool1 task B should reach a terminal state");
        prop_assert!(handle2a.is_done(), "Pool2 task A should reach a terminal state");
        prop_assert!(handle2b.is_done(), "Pool2 task B should reach a terminal state");
    });
}

/// MR6: INVERTIVE - Spawn-Shutdown Round Trip
/// spawn_tasks(N) → drain_and_shutdown() should restore initial state.
#[test]
fn mr_spawn_shutdown_round_trip() {
    proptest!(|(task_count in 1usize..=50)| {
        let task_count = (task_count % 6) + 1; // 1-6 tasks
        let config = TestPoolConfig {
            min_threads: 1,
            max_threads: 3,
            idle_timeout_ms: 200,
            affinity_enabled: false,
            cohort_count: None,
        };

        let pool = config.create_pool();

        // Capture initial state
        let initial_active_threads = pool.active_threads();

        // Spawn tasks
        let handles: Vec<_> = (0..task_count)
            .map(|_i| pool.spawn(move || {
                thread::sleep(Duration::from_millis(50));
            }))
            .collect();

        // Verify tasks were spawned
        prop_assert!(pool.pending_count() > 0 || pool.busy_threads() > 0,
            "No evidence of spawned tasks in metrics");

        // Shutdown and drain
        pool.shutdown_and_wait(Duration::from_secs(5));

        // Verify all tasks completed
        for handle in handles {
            prop_assert!(handle.is_done(), "Task should be completed after shutdown");
        }

        // Final state should show no pending work
        prop_assert_eq!(pool.pending_count(), 0,
            "Pending tasks should be 0 after drain_and_shutdown");
        prop_assert_eq!(pool.busy_threads(), 0,
            "Busy threads should be 0 after drain_and_shutdown");
        prop_assert!(pool.active_threads() <= initial_active_threads,
            "Active threads should not grow after shutdown");
    });
}

/// MR7: EQUIVALENCE - Configuration Invariance
/// Pool behavior should be deterministic given the same configuration parameters.
#[test]
fn mr_configuration_invariance() {
    proptest!(|(config in arb_pool_config(), task_count in 1usize..=50)| {
        let task_count = (task_count % 4) + 1; // 1-4 tasks

        // Create two identical pools
        let pool1 = config.create_pool();
        let pool2 = config.create_pool();

        // Submit identical workloads
        for _i in 0..task_count {
            pool1.spawn(move || thread::sleep(Duration::from_millis(100)));
            pool2.spawn(move || thread::sleep(Duration::from_millis(100)));
        }

        // Allow some processing time. Instantaneous queue/busy distribution is
        // scheduler-dependent, so this test only checks stable configuration
        // invariants before comparing final quiescence below.
        thread::sleep(Duration::from_millis(50));

        let active1 = pool1.active_threads();
        let active2 = pool2.active_threads();

        prop_assert!(active1 <= config.max_threads,
            "Pool1 active threads {} exceeded max {}",
            active1, config.max_threads);
        prop_assert!(active2 <= config.max_threads,
            "Pool2 active threads {} exceeded max {}",
            active2, config.max_threads);

        let total_work1 = pool1.pending_count() + pool1.busy_threads();
        let total_work2 = pool2.pending_count() + pool2.busy_threads();
        prop_assert!(total_work1 <= task_count,
            "Pool1 reported more in-flight work than submitted: {} > {}",
            total_work1, task_count);
        prop_assert!(total_work2 <= task_count,
            "Pool2 reported more in-flight work than submitted: {} > {}",
            total_work2, task_count);

        prop_assert!(pool1.shutdown_and_wait(Duration::from_secs(5)),
            "Pool1 should shut down cleanly");
        prop_assert!(pool2.shutdown_and_wait(Duration::from_secs(5)),
            "Pool2 should shut down cleanly");
        prop_assert_eq!(pool1.pending_count(), pool2.pending_count(),
            "Identical pools should converge to the same drained queue depth");
        prop_assert_eq!(pool1.busy_threads(), pool2.busy_threads(),
            "Identical pools should converge to the same drained busy count");
        prop_assert_eq!(pool1.active_threads(), pool2.active_threads(),
            "Identical pools should converge to the same retired worker count");
    });
}

/// MR8: ADDITIVE - Affinity Conservation
/// Total tasks across all cohorts should equal global task count when affinity is enabled.
#[test]
fn mr_affinity_conservation() {
    proptest!(|(task_count in 1usize..=50, cohort_preferences in prop::collection::vec(0usize..4, 0..=50))| {
        let task_count = (task_count % 6) + 2; // 2-7 tasks
        let config = TestPoolConfig {
            min_threads: 1,
            max_threads: 3,
            idle_timeout_ms: 300,
            affinity_enabled: true,
            cohort_count: Some(3),
        };

        let pool = config.create_pool();

        // Submit tasks with cohort preferences
        for i in 0..task_count {
            let cohort = cohort_preferences.get(i).unwrap_or(&0) % 3;
            pool.spawn_on_cohort(cohort, move || {
                thread::sleep(Duration::from_millis(100));
            });
        }

        thread::sleep(Duration::from_millis(50));

        let affinity_metrics = pool.affinity_metrics();
        if affinity_metrics.enabled {
            let cohort_total: usize = affinity_metrics.cohort_pending_counts.iter().sum();
            let total_tracked = cohort_total + affinity_metrics.global_pending_count;
            let global_pending = pool.pending_count();

            prop_assert_eq!(total_tracked, global_pending,
                "Affinity conservation violated: cohort_total={}, global_spill={}, tracked_total={}, global_pending={}",
                cohort_total, affinity_metrics.global_pending_count, total_tracked, global_pending);
        }

        pool.shutdown_and_wait(Duration::from_secs(5));
    });
}

/// MR9: PERMUTATIVE - Task Ordering Under FIFO
/// For same-priority tasks, execution order should respect submission order (FIFO property).
#[test]
fn mr_task_ordering_fifo() {
    proptest!(|(task_count in 1usize..=50)| {
        let task_count = (task_count % 4) + 2; // 2-5 tasks
        let config = TestPoolConfig {
            min_threads: 1,
            max_threads: 1, // Single thread to ensure serialization
            idle_timeout_ms: 500,
            affinity_enabled: false,
            cohort_count: None,
        };

        let pool = config.create_pool();

        let execution_order = Arc::new(parking_lot::Mutex::new(Vec::new()));

        // Submit tasks that record their execution order
        for i in 0..task_count {
            let order = execution_order.clone();
            pool.spawn(move || {
                thread::sleep(Duration::from_millis(50));
                order.lock().push(i);
            });
        }

        // Wait for all tasks to complete
        thread::sleep(Duration::from_millis((task_count as u64) * 100 + 200));

        let final_order = execution_order.lock().clone();

        // Verify FIFO ordering (should be 0, 1, 2, ...)
        let expected_order: Vec<_> = (0..task_count).collect();
        prop_assert_eq!(&final_order, &expected_order,
            "FIFO ordering violated: expected {:?}, got {:?}",
            expected_order, final_order);

        pool.shutdown_and_wait(Duration::from_secs(5));
    });
}

/// MR10: EQUIVALENCE - Completion Consistency
/// A task marked as completed should remain completed (monotonic property).
#[test]
fn mr_completion_consistency() {
    proptest!(|(task_duration_ms in 1u64..=100)| {
        let task_duration_ms = (task_duration_ms % 100) + 50; // 50-149ms
        let config = TestPoolConfig {
            min_threads: 1,
            max_threads: 2,
            idle_timeout_ms: 300,
            affinity_enabled: false,
            cohort_count: None,
        };

        let pool = config.create_pool();

        let handle = pool.spawn(move || {
            thread::sleep(Duration::from_millis(task_duration_ms));
        });

        // Poll completion status over time
        let mut was_completed = false;
        for _ in 0..10 {
            let is_completed = handle.is_done();

            if was_completed {
                prop_assert!(is_completed,
                    "Completion consistency violated: task became incomplete after being complete");
            }

            was_completed = was_completed || is_completed;
            thread::sleep(Duration::from_millis(20));
        }

        pool.shutdown_and_wait(Duration::from_secs(5));
    });
}

#[cfg(test)]
mod composition_tests {
    use super::*;

    /// Composite MR: Thread Bounds + Task Conservation + Completion
    /// Tests that all three properties hold simultaneously under complex operations.
    #[test]
    fn mr_composite_pool_invariants() {
        proptest!(|(config in arb_pool_config(), operations in prop::collection::vec(arb_pool_operation(), 0..=30))| {
            let pool = config.create_pool();
            let mut tracked_tasks = Vec::new();
            let completion_counter = Arc::new(AtomicUsize::new(0));

            for op in operations.iter().take(8) {
                apply_operation(&pool, op, &mut tracked_tasks, completion_counter.clone());

                let snapshot = PoolSnapshot::capture(&pool, &config, &tracked_tasks);

                // MR1: Thread bounds
                if snapshot.is_shutdown {
                    prop_assert_eq!(snapshot.active_threads, 0, "Shutdown pool should retire all threads");
                } else {
                    prop_assert!(snapshot.active_threads >= snapshot.min_threads &&
                               snapshot.active_threads <= snapshot.max_threads,
                        "Thread bounds violated");
                }

                // MR2: Task conservation
                let accounted = snapshot.total_completed + snapshot.total_outstanding;
                prop_assert_eq!(snapshot.total_spawned, accounted, "Task conservation violated");
                prop_assert!(snapshot.pending_tasks <= snapshot.total_outstanding,
                    "Pending queue depth exceeded outstanding tasks");
                prop_assert!(snapshot.busy_threads <= snapshot.total_outstanding,
                    "Busy thread count exceeded outstanding tasks");

                // MR3: Busy constraint
                prop_assert!(snapshot.busy_threads <= snapshot.active_threads,
                    "Busy threads constraint violated");

                // Composite property: No thread leaks under load
                if snapshot.pending_tasks > 0 {
                    prop_assert!(snapshot.active_threads > 0,
                        "Pool should have active threads when work is pending");
                }
            }

            pool.shutdown_and_wait(Duration::from_secs(5));
        });
    }
}
