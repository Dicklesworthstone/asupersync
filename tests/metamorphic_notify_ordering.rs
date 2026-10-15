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
#![allow(warnings)]
#![allow(clippy::all)]

use proptest::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use asupersync::sync::Notify;

type WaiterFuture = Pin<Box<dyn Future<Output = usize>>>;

/// Test harness for notify ordering tests
struct NotifyOrderingHarness {
    notify: Arc<Notify>,
}

impl NotifyOrderingHarness {
    fn new() -> Self {
        let notify = Arc::new(Notify::new());

        Self { notify }
    }

    /// Start multiple waiters concurrently and return their task handles.
    fn spawn_waiters(&self, count: usize) -> Vec<WaiterFuture> {
        let mut handles = Vec::with_capacity(count);
        for index in 0..count {
            let notify_clone = Arc::clone(&self.notify);
            handles.push(Box::pin(async move {
                notify_clone.notified().await;
                index
            }) as WaiterFuture);
        }
        handles
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn register_waiters(&self, waiters: &mut [WaiterFuture]) {
        let waker = Self::noop_waker();
        let mut cx = Context::from_waker(&waker);
        for waiter in &mut *waiters {
            assert!(
                matches!(waiter.as_mut().poll(&mut cx), Poll::Pending),
                "waiter should register before notification"
            );
        }
        assert_eq!(
            self.notify.waiter_count(),
            waiters.len(),
            "all waiters should be registered"
        );
    }

    /// Poll all waiters once and collect those that are currently ready.
    /// Pending waiters stay registered and are returned to `waiters`.
    fn drain_ready(&self, waiters: &mut Vec<WaiterFuture>) -> Vec<usize> {
        let waker = Self::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut completed = Vec::new();
        let mut pending = Vec::new();

        for mut waiter in std::mem::take(waiters) {
            match waiter.as_mut().poll(&mut cx) {
                Poll::Ready(value) => completed.push(value),
                Poll::Pending => pending.push(waiter),
            }
        }

        *waiters = pending;
        completed
    }

    /// Notify waiters sequentially and collect completion order
    fn sequential_notify_one(&mut self, waiter_count: usize) -> Vec<usize> {
        let mut handles = self.spawn_waiters(waiter_count);
        self.register_waiters(&mut handles);

        // Notify each waiter one by one
        let mut completed = Vec::with_capacity(waiter_count);
        for _ in 0..waiter_count {
            self.notify.notify_one();
            completed.extend(self.drain_ready(&mut handles));
        }

        completed
    }

    /// Test broadcast notification behavior
    fn broadcast_notify(&mut self, waiter_count: usize) -> Vec<usize> {
        let mut handles = self.spawn_waiters(waiter_count);
        self.register_waiters(&mut handles);

        // Broadcast notify
        self.notify.notify_waiters();

        self.drain_ready(&mut handles)
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

fn notify_ordering_proptest_config() -> ProptestConfig {
    ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// MR1: FIFO Ordering
// notify_one should wake waiters in the order they registered (FIFO fairness)
#[test]
fn mr_fifo_ordering() {
    proptest!(notify_ordering_proptest_config(), |(waiter_count in 2..8_usize)| {
        let mut harness = NotifyOrderingHarness::new();
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
    proptest!(notify_ordering_proptest_config(), |(waiter_count in 1..10_usize)| {
        let mut harness = NotifyOrderingHarness::new();
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
    proptest!(notify_ordering_proptest_config(), |(
        stored_notifications in 1..5_usize,
        waiter_count in 1..8_usize
    )| {
        let mut harness = NotifyOrderingHarness::new();

        // Send notifications before any waiters
        for _ in 0..stored_notifications {
            harness.notify.notify_one();
        }

        // Now start waiters
        let mut handles = harness.spawn_waiters(waiter_count);

        let completion_order = harness.drain_ready(&mut handles);

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
    proptest!(notify_ordering_proptest_config(), |(
        pre_waiters in 1..6_usize,
        post_waiters in 1..6_usize
    )| {
        let mut harness = NotifyOrderingHarness::new();

        // Start pre-broadcast waiters
        let mut pre_handles = harness.spawn_waiters(pre_waiters);
        harness.register_waiters(&mut pre_handles);

        // Broadcast notify
        harness.notify.notify_waiters();

        // Start post-broadcast waiters (should not be woken by the broadcast)
        let mut post_handles = harness.spawn_waiters(post_waiters);

        // Collect pre-broadcast results (should all complete)
        let pre_completed = harness.drain_ready(&mut pre_handles);

        let post_completed = harness.drain_ready(&mut post_handles);
        prop_assert!(
            post_completed.is_empty(),
            "post-broadcast waiters should not be completed by the earlier broadcast: {:?}",
            post_completed
        );

        // Check that all pre-broadcast waiters completed
        prop_assert_eq!(pre_completed.len(), pre_waiters,
            "Generation ordering failed: {} pre-waiters completed, expected {}",
            pre_completed.len(), pre_waiters);

        // Clean up by notifying post-waiters
        harness.register_waiters(&mut post_handles);
        harness.notify.notify_waiters();
        let _ = harness.drain_ready(&mut post_handles);
    });
}

// MR5: No Double Notification
// A waiter should not receive multiple notifications from the same notify event
#[test]
fn mr_no_double_notification() {
    proptest!(notify_ordering_proptest_config(), |(waiter_count in 2..8_usize)| {
        let mut harness = NotifyOrderingHarness::new();

        // Create a custom test that can detect double notifications
        let completion_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles: Vec<WaiterFuture> = Vec::with_capacity(waiter_count);
        for index in 0..waiter_count {
            let notify_clone = Arc::clone(&harness.notify);
            let count_clone = Arc::clone(&completion_count);
            handles.push(Box::pin(async move {
                notify_clone.notified().await;
                count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                index
            }) as WaiterFuture);
        }

        harness.register_waiters(&mut handles);

        // Single broadcast should wake all waiters exactly once
        harness.notify.notify_waiters();

        // Collect results
        let completed = harness.drain_ready(&mut handles);

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
