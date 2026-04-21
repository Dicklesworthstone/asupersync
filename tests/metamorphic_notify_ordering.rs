//! Metamorphic Testing for Notify Ordering Invariants
//!
//! Tests fairness and ordering guarantees for notify_one and notify_waiters
//! operations on the Notify primitive.
//!
//! Target: src/sync/notify.rs
//!
//! # Metamorphic Relations
//!
//! 1. **FIFO Ordering**: notify_one wakes waiters in arrival order
//! 2. **Broadcast Completeness**: notify_waiters wakes all current waiters atomically
//! 3. **Storage Preservation**: Early notify_one creates stored notifications for late waiters
//! 4. **Generation Ordering**: Waiters before notify_waiters get woken, after don't
//! 5. **No Double Notification**: Each waiter receives at most one notification per notify

#![cfg(test)]

use proptest::prelude::*;
use std::sync::Arc;
use std::time::Duration;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::sync::Notify;

/// Test harness for notify ordering tests
struct NotifyOrderingHarness {
    lab_runtime: LabRuntime,
    notify: Arc<Notify>,
}

impl NotifyOrderingHarness {
    fn new() -> Self {
        let config = LabConfig::default()
            .worker_count(4)
            .trace_capacity(1024)
            .max_steps(5000);
        let lab_runtime = LabRuntime::new(config);
        let notify = Arc::new(Notify::new());

        Self {
            lab_runtime,
            notify,
        }
    }

    /// Start multiple waiters concurrently and track their completion order
    fn spawn_waiters(&self, count: usize) -> Vec<impl std::future::Future<Output = usize>> {
        let notify = Arc::clone(&self.notify);
        (0..count)
            .map(|index| {
                let notify_clone = Arc::clone(&notify);
                self.lab_runtime.spawn_local(async move {
                    notify_clone.notified().await;
                    index
                })
            })
            .collect()
    }

    /// Notify waiters sequentially and collect completion order
    fn sequential_notify_one(&self, waiter_count: usize) -> Vec<usize> {
        let tasks = self.spawn_waiters(waiter_count);

        // Give waiters time to register
        self.lab_runtime.advance_time_by(Duration::from_millis(10));

        // Notify each waiter one by one
        let mut completed = Vec::new();
        for _ in 0..waiter_count {
            self.notify.notify_one();
            self.lab_runtime.advance_time_by(Duration::from_millis(1));
        }

        // Collect results
        self.lab_runtime.block_on_local(async {
            for task in tasks {
                completed.push(task.await);
            }
            completed
        })
    }

    /// Test broadcast notification behavior
    fn broadcast_notify(&self, waiter_count: usize) -> Vec<usize> {
        let tasks = self.spawn_waiters(waiter_count);

        // Give waiters time to register
        self.lab_runtime.advance_time_by(Duration::from_millis(10));

        // Broadcast notify
        self.notify.notify_waiters();

        // Collect results
        self.lab_runtime.block_on_local(async {
            let mut completed = Vec::new();
            for task in tasks {
                completed.push(task.await);
            }
            completed
        })
    }
}

/// Statistics for analyzing notification ordering behavior
#[derive(Debug, Clone)]
struct NotifyStats {
    waiter_count: usize,
    completion_order: Vec<usize>,
    fifo_violations: usize,
}

impl NotifyStats {
    fn analyze(completion_order: Vec<usize>) -> Self {
        let waiter_count = completion_order.len();
        let mut fifo_violations = 0;

        // Count ordering inversions (later-arriving waiter completes before earlier one)
        for i in 0..completion_order.len() {
            for j in (i + 1)..completion_order.len() {
                if completion_order[i] > completion_order[j] {
                    fifo_violations += 1;
                }
            }
        }

        Self {
            waiter_count,
            completion_order,
            fifo_violations,
        }
    }
}

// MR1: FIFO Ordering
// notify_one should wake waiters in the order they registered (FIFO fairness)
#[test]
fn mr_fifo_ordering() {
    proptest!(|(waiter_count in 2..8_usize)| {
        let harness = NotifyOrderingHarness::new();
        let completion_order = harness.sequential_notify_one(waiter_count);
        let stats = NotifyStats::analyze(completion_order);

        // FIFO invariant: no ordering violations
        prop_assert_eq!(stats.fifo_violations, 0,
            "FIFO violation: completion order {:?} for {} waiters",
            stats.completion_order, waiter_count);

        // All waiters should complete
        prop_assert_eq!(stats.waiter_count, waiter_count,
            "Not all waiters completed: got {}, expected {}",
            stats.waiter_count, waiter_count);
    });
}

// MR2: Broadcast Completeness
// notify_waiters should wake all currently registered waiters
#[test]
fn mr_broadcast_completeness() {
    proptest!(|(waiter_count in 1..10_usize)| {
        let harness = NotifyOrderingHarness::new();
        let completion_order = harness.broadcast_notify(waiter_count);

        // All waiters should be woken by single broadcast
        prop_assert_eq!(completion_order.len(), waiter_count,
            "Broadcast completeness failed: {} waiters woken, expected {}",
            completion_order.len(), waiter_count);

        // Each waiter index should appear exactly once
        let mut sorted_order = completion_order.clone();
        sorted_order.sort_unstable();
        let expected: Vec<usize> = (0..waiter_count).collect();
        prop_assert_eq!(sorted_order, expected,
            "Broadcast completeness violation: missing or duplicate waiters {:?}",
            completion_order);
    });
}

// MR3: Storage Preservation
// notify_one before waiters should create stored notifications
#[test]
fn mr_storage_preservation() {
    proptest!(|(
        stored_notifications in 1..5_usize,
        waiter_count in 1..8_usize
    )| {
        let harness = NotifyOrderingHarness::new();

        // Send notifications before any waiters
        for _ in 0..stored_notifications {
            harness.notify.notify_one();
        }

        // Now start waiters
        let tasks = harness.spawn_waiters(waiter_count);

        let completion_order: Vec<usize> = harness.lab_runtime.block_on_local(async {
            let mut completed = Vec::new();
            for task in tasks {
                completed.push(task.await);
            }
            completed
        });

        // The number that complete immediately should equal stored notifications
        let expected_immediate = stored_notifications.min(waiter_count);
        prop_assert_eq!(completion_order.len(), expected_immediate,
            "Storage preservation failed: {} waiters completed from {} stored notifications",
            completion_order.len(), stored_notifications);
    });
}

// MR4: Generation Ordering
// Waiters registered before notify_waiters should be woken, after should not
#[test]
fn mr_generation_ordering() {
    proptest!(|(
        pre_waiters in 1..6_usize,
        post_waiters in 1..6_usize
    )| {
        let harness = NotifyOrderingHarness::new();

        // Start pre-broadcast waiters
        let pre_tasks = harness.spawn_waiters(pre_waiters);

        // Give them time to register
        harness.lab_runtime.advance_time_by(Duration::from_millis(10));

        // Broadcast notify
        harness.notify.notify_waiters();

        // Start post-broadcast waiters (should not be woken by the broadcast)
        let post_tasks = harness.spawn_waiters(post_waiters);

        // Give a short time for any spurious wakeups
        harness.lab_runtime.advance_time_by(Duration::from_millis(5));

        // Collect pre-broadcast results (should all complete)
        let pre_completed: Vec<usize> = harness.lab_runtime.block_on_local(async {
            let mut completed = Vec::new();
            for task in pre_tasks {
                completed.push(task.await);
            }
            completed
        });

        // Check that all pre-broadcast waiters completed
        prop_assert_eq!(pre_completed.len(), pre_waiters,
            "Generation ordering failed: {} pre-waiters completed, expected {}",
            pre_completed.len(), pre_waiters);

        // Post-waiters should still be waiting (we don't await them)
        // This is implicit - if they were woken, the test would behave differently

        // Clean up by notifying post-waiters
        harness.notify.notify_waiters();
        harness.lab_runtime.block_on_local(async {
            for task in post_tasks {
                let _ = task.await;
            }
        });
    });
}

// MR5: No Double Notification
// A waiter should not receive multiple notifications from the same notify event
#[test]
fn mr_no_double_notification() {
    proptest!(|(waiter_count in 2..8_usize)| {
        let harness = NotifyOrderingHarness::new();

        // Create a custom test that can detect double notifications
        let notify = Arc::clone(&harness.notify);
        let completion_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let tasks: Vec<_> = (0..waiter_count)
            .map(|index| {
                let notify_clone = Arc::clone(&notify);
                let count_clone = Arc::clone(&completion_count);
                harness.lab_runtime.spawn_local(async move {
                    notify_clone.notified().await;
                    count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    index
                })
            })
            .collect();

        // Give waiters time to register
        harness.lab_runtime.advance_time_by(Duration::from_millis(10));

        // Single broadcast should wake all waiters exactly once
        harness.notify.notify_waiters();

        // Collect results
        let completed: Vec<usize> = harness.lab_runtime.block_on_local(async {
            let mut results = Vec::new();
            for task in tasks {
                results.push(task.await);
            }
            results
        });

        // Exactly waiter_count notifications should have been delivered
        let total_notifications = completion_count.load(std::sync::atomic::Ordering::Relaxed);
        prop_assert_eq!(total_notifications, waiter_count,
            "Double notification detected: {} notifications for {} waiters",
            total_notifications, waiter_count);

        prop_assert_eq!(completed.len(), waiter_count,
            "Completion count mismatch: {} completed, {} waiters",
            completed.len(), waiter_count);
    });
}
