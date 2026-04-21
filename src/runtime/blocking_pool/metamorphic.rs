#![allow(clippy::all)]
//! Metamorphic tests for blocking pool task fairness.
//!
//! Tests fairness properties using metamorphic relations to verify that the blocking
//! pool maintains task ordering guarantees, fair thread utilization, and correct
//! priority handling under various transformations.

#[cfg(test)]
mod tests {
    use super::super::BlockingPool;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Condvar, Mutex};
    use std::time::{Duration, Instant};

    fn run_queued_cancellation_scenario(cancel_repeats: usize) -> (Vec<u8>, bool, bool) {
        let pool = BlockingPool::new(1, 1);
        let start_barrier = Arc::new(Barrier::new(2));
        let finish_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let execution_order = Arc::new(Mutex::new(Vec::new()));
        let cancelled_executed = Arc::new(AtomicBool::new(false));
        let follower_executed = Arc::new(AtomicBool::new(false));

        let start_barrier_clone = Arc::clone(&start_barrier);
        let finish_gate_clone = Arc::clone(&finish_gate);
        let execution_order_clone = Arc::clone(&execution_order);
        let handle1 = pool.spawn(move || {
            start_barrier_clone.wait();
            let (lock, cvar) = &*finish_gate_clone;
            let mut finish = lock.lock().unwrap();
            while !*finish {
                finish = cvar.wait(finish).unwrap();
            }
            execution_order_clone.lock().unwrap().push(1);
        });

        start_barrier.wait();

        let cancelled_executed_clone = Arc::clone(&cancelled_executed);
        let execution_order_clone = Arc::clone(&execution_order);
        let handle2 = pool.spawn(move || {
            cancelled_executed_clone.store(true, Ordering::SeqCst);
            execution_order_clone.lock().unwrap().push(2);
        });

        let follower_executed_clone = Arc::clone(&follower_executed);
        let execution_order_clone = Arc::clone(&execution_order);
        let handle3 = pool.spawn(move || {
            follower_executed_clone.store(true, Ordering::SeqCst);
            execution_order_clone.lock().unwrap().push(3);
        });

        let queue_deadline = Instant::now() + Duration::from_secs(1);
        while pool.pending_count() < 2 && Instant::now() < queue_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            pool.pending_count() >= 2,
            "blocked worker should leave the cancelled task and follower queued"
        );

        for _ in 0..cancel_repeats {
            handle2.cancel();
        }
        assert!(
            handle2.is_cancelled(),
            "queued task should report cancelled"
        );

        {
            let (lock, cvar) = &*finish_gate;
            let mut finish = lock.lock().unwrap();
            *finish = true;
            cvar.notify_all();
        }

        assert!(handle1.wait_timeout(Duration::from_secs(5)));
        assert!(handle2.wait_timeout(Duration::from_secs(5)));
        assert!(handle3.wait_timeout(Duration::from_secs(5)));
        assert!(pool.shutdown_and_wait(Duration::from_secs(5)));

        (
            execution_order.lock().unwrap().clone(),
            cancelled_executed.load(Ordering::SeqCst),
            follower_executed.load(Ordering::SeqCst),
        )
    }

    /// Metamorphic Relation 1: FIFO Ordering Preservation
    ///
    /// Property: If tasks T1, T2, ..., Tn are submitted in order, they should
    /// complete in the same relative order when there's only one worker thread.
    ///
    /// MR: order(execute(sequential_tasks)) = order(submit(sequential_tasks))
    #[test]
    fn mr_fifo_ordering_preservation() {
        let pool = BlockingPool::new(1, 1); // Single thread to ensure serialization

        const TASK_COUNT: usize = 10;
        let completion_order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut handles = Vec::new();

        // Submit tasks in order 0, 1, 2, ..., TASK_COUNT-1
        for task_id in 0..TASK_COUNT {
            let completion_order = Arc::clone(&completion_order);
            let handle = pool.spawn(move || {
                // Small delay to prevent tasks from completing too quickly
                std::thread::sleep(Duration::from_millis(10));
                completion_order.lock().unwrap().push(task_id);
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.wait();
        }

        let final_order = completion_order.lock().unwrap().clone();
        let expected_order: Vec<usize> = (0..TASK_COUNT).collect();

        assert_eq!(
            final_order, expected_order,
            "Tasks should complete in FIFO order with single thread. Expected: {:?}, Got: {:?}",
            expected_order, final_order
        );
    }

    /// Metamorphic Relation 2: Permutation Invariance for Multiple Threads
    ///
    /// Property: With multiple threads, while individual execution order may vary,
    /// the total set of completed tasks should be identical regardless of submission
    /// order when tasks have equal priority.
    ///
    /// MR: set(complete(permute(tasks))) = set(complete(tasks))
    #[test]
    fn mr_permutation_invariance_multiple_threads() {
        let pool = BlockingPool::new(2, 4); // Multiple threads

        let task_ids = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Test original order
        let original_completed = {
            let completed = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            for &task_id in &task_ids {
                let completed = Arc::clone(&completed);
                let handle = pool.spawn(move || {
                    std::thread::sleep(Duration::from_millis(50)); // Simulate work
                    completed.lock().unwrap().push(task_id);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            let mut result = completed.lock().unwrap().clone();
            result.sort_unstable();
            result
        };

        // Test reversed order
        let reversed_completed = {
            let completed = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut handles = Vec::new();
            let mut reversed_ids = task_ids.clone();
            reversed_ids.reverse();

            for &task_id in &reversed_ids {
                let completed = Arc::clone(&completed);
                let handle = pool.spawn(move || {
                    std::thread::sleep(Duration::from_millis(50)); // Simulate work
                    completed.lock().unwrap().push(task_id);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            let mut result = completed.lock().unwrap().clone();
            result.sort_unstable();
            result
        };

        assert_eq!(
            original_completed, reversed_completed,
            "Same set of tasks should complete regardless of submission order"
        );
        assert_eq!(
            original_completed, task_ids,
            "All submitted tasks should complete exactly once"
        );
    }

    /// Metamorphic Relation 3: Thread Scaling Consistency
    ///
    /// Property: Increasing the number of available threads should not change
    /// the set of completed tasks, only potentially the completion timing.
    ///
    /// MR: set(complete(tasks, min_threads)) = set(complete(tasks, max_threads))
    #[test]
    fn mr_thread_scaling_consistency() {
        let tasks = vec![10, 20, 30, 40, 50];

        // Test with minimal threads
        let minimal_results = {
            let pool = BlockingPool::new(1, 1);
            let results = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            for &task_id in &tasks {
                let results = Arc::clone(&results);
                let handle = pool.spawn(move || {
                    std::thread::sleep(Duration::from_millis(30));
                    results.lock().unwrap().push(task_id);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            let mut result = results.lock().unwrap().clone();
            result.sort_unstable();
            result
        };

        // Test with many threads
        let maximal_results = {
            let pool = BlockingPool::new(tasks.len(), tasks.len());
            let results = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            for &task_id in &tasks {
                let results = Arc::clone(&results);
                let handle = pool.spawn(move || {
                    std::thread::sleep(Duration::from_millis(30));
                    results.lock().unwrap().push(task_id);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            let mut result = results.lock().unwrap().clone();
            result.sort_unstable();
            result
        };

        assert_eq!(
            minimal_results, maximal_results,
            "Thread count should not affect which tasks complete"
        );
        assert_eq!(
            minimal_results, tasks,
            "All tasks should complete regardless of thread count"
        );
    }

    /// Metamorphic Relation 4: Task Cancellation Monotonicity
    ///
    /// Property: Cancelling a subset of tasks should result in at least as many
    /// completed tasks in the non-cancelled set as when all tasks run.
    ///
    /// MR: |complete(tasks \ cancelled)| ≤ |complete(tasks)|
    #[test]
    fn mr_cancellation_monotonicity() {
        let pool = BlockingPool::new(2, 2);

        let task_count = 6;

        // Run all tasks without cancellation
        let all_completed = {
            let completed = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for _task_id in 0..task_count {
                let completed = Arc::clone(&completed);
                let handle = pool.spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    completed.fetch_add(1, Ordering::Relaxed);
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            completed.load(Ordering::Relaxed)
        };

        // Run with some tasks cancelled
        let partial_completed = {
            let completed = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();

            for task_id in 0..task_count {
                let completed = Arc::clone(&completed);
                let handle = pool.spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    completed.fetch_add(1, Ordering::Relaxed);
                });

                // Cancel every other task
                if task_id % 2 == 0 {
                    handle.cancel();
                }

                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            completed.load(Ordering::Relaxed)
        };

        // The relationship might be complex due to timing, but cancelled tasks
        // should generally result in fewer completions
        assert!(
            partial_completed <= all_completed,
            "Cancelling tasks should not increase completion count. All: {}, Partial: {}",
            all_completed,
            partial_completed
        );
    }

    /// Metamorphic Relation 5: Load Distribution Fairness
    ///
    /// Property: With multiple identical tasks, work should be distributed roughly
    /// evenly across threads. No single thread should handle all tasks when
    /// multiple threads are available.
    ///
    /// MR: max(thread_task_count) ≤ ⌈total_tasks / active_threads⌉ + threshold
    #[test]
    fn mr_load_distribution_fairness() {
        let pool = BlockingPool::new(3, 3);
        let task_count = 12; // Evenly divisible by 3 threads

        // Track which thread handles each task using thread IDs
        let thread_assignments = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut handles = Vec::new();

        for _i in 0..task_count {
            let thread_assignments = Arc::clone(&thread_assignments);
            let handle = pool.spawn(move || {
                let thread_id = std::thread::current().id();
                std::thread::sleep(Duration::from_millis(50));

                let mut assignments = thread_assignments.lock().unwrap();
                let count = assignments.entry(thread_id).or_insert(0);
                *count += 1;
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.wait();
        }

        let assignments = thread_assignments.lock().unwrap();
        let task_counts: Vec<usize> = assignments.values().copied().collect();

        assert!(
            !task_counts.is_empty(),
            "At least one thread should have processed tasks"
        );

        let max_tasks_per_thread = *task_counts.iter().max().unwrap();
        let min_tasks_per_thread = *task_counts.iter().min().unwrap();
        let expected_tasks_per_thread = task_count / 3; // 3 threads
        let fairness_threshold = 2; // Allow some variance due to timing

        assert!(
            max_tasks_per_thread <= expected_tasks_per_thread + fairness_threshold,
            "Load distribution too uneven. Max: {}, Expected: {}, Threshold: {}",
            max_tasks_per_thread,
            expected_tasks_per_thread,
            fairness_threshold
        );

        assert!(
            max_tasks_per_thread - min_tasks_per_thread <= fairness_threshold,
            "Thread load variance too high. Max: {}, Min: {}, Threshold: {}",
            max_tasks_per_thread,
            min_tasks_per_thread,
            fairness_threshold
        );
    }

    /// Metamorphic Relation 6: Priority Invariance (Current Implementation)
    ///
    /// Property: Since the current implementation ignores priority, tasks with
    /// different priorities should behave identically to tasks with same priority.
    ///
    /// MR: complete(tasks_with_mixed_priorities) ≈ complete(tasks_with_same_priority)
    #[test]
    fn mr_priority_invariance() {
        let pool = BlockingPool::new(2, 2);

        // Test with mixed priorities
        let mixed_priority_results = {
            let completed = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            let priorities = vec![1, 255, 128, 50, 200]; // Various priorities
            for (i, &priority) in priorities.iter().enumerate() {
                let completed = Arc::clone(&completed);
                let handle = pool.spawn_with_priority(
                    move || {
                        std::thread::sleep(Duration::from_millis(50));
                        completed.lock().unwrap().push(i);
                    },
                    priority,
                );
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            let mut result = completed.lock().unwrap().clone();
            result.sort_unstable();
            result
        };

        // Test with same priority
        let same_priority_results = {
            let completed = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut handles = Vec::new();

            for i in 0..5 {
                let completed = Arc::clone(&completed);
                let handle = pool.spawn_with_priority(
                    move || {
                        std::thread::sleep(Duration::from_millis(50));
                        completed.lock().unwrap().push(i);
                    },
                    128,
                ); // Same priority for all
                handles.push(handle);
            }

            for handle in handles {
                handle.wait();
            }

            let mut result = completed.lock().unwrap().clone();
            result.sort_unstable();
            result
        };

        assert_eq!(
            mixed_priority_results, same_priority_results,
            "Priority should not affect completion in current implementation"
        );
        assert_eq!(
            mixed_priority_results,
            vec![0, 1, 2, 3, 4],
            "All tasks should complete regardless of priority"
        );
    }

    /// Metamorphic Relation 7: Repeated cancellation preserves follower progress.
    ///
    /// Property: Repeating `cancel()` on the same queued task must not change
    /// whether a later queued follower runs once the blocked worker is released.
    ///
    /// MR: execute(blocker, cancel(x), follower) = execute(blocker, cancel(x)^n, follower)
    #[test]
    fn mr_repeated_cancellation_preserves_follower_progress() {
        let (single_cancel_order, single_cancelled_executed, single_follower_executed) =
            run_queued_cancellation_scenario(1);
        let (repeated_cancel_order, repeated_cancelled_executed, repeated_follower_executed) =
            run_queued_cancellation_scenario(4);

        assert!(
            !single_cancelled_executed && !repeated_cancelled_executed,
            "queued cancelled task must stay skipped regardless of repeated cancel calls"
        );
        assert!(
            single_follower_executed && repeated_follower_executed,
            "follower task must still execute after the blocked worker is released"
        );
        assert_eq!(
            single_cancel_order,
            vec![1, 3],
            "single cancellation should preserve blocker-then-follower execution order"
        );
        assert_eq!(
            repeated_cancel_order,
            vec![1, 3],
            "repeated cancellation should preserve blocker-then-follower execution order"
        );
        assert_eq!(
            repeated_cancel_order, single_cancel_order,
            "repeating cancellation must not perturb survivor execution order"
        );
    }
}
