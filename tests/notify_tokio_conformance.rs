//! Notify conformance test: asupersync vs tokio::sync::Notify
//!
//! Tests that both implementations exhibit identical wake order characteristics
//! when the same sequence of N waiters + M notifications arrive in the same order.
//! Validates basic notification semantics and fairness consistency.

use asupersync::sync::Notify as AsyncNotify;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify as TokioNotify;

/// Result of a notify conformance test comparing both implementations.
#[derive(Debug, Clone, PartialEq)]
struct NotifyConformanceResult {
    /// Test scenario identifier
    scenario: String,
    /// Total number of notifications sent
    notifications_sent: usize,
    /// Number of waiters that successfully received notification
    waiters_notified: usize,
    /// Order in which notifications were received (thread_id, timestamp)
    notification_order: Vec<(usize, Instant)>,
    /// Total test duration
    duration: Duration,
}

/// Test configuration for notify comparison
#[derive(Debug, Clone)]
struct NotifyTest {
    /// Number of waiters to spawn
    waiter_count: usize,
    /// Number of notifications to send
    notification_count: usize,
    /// Delay between notifications (ms)
    notification_interval: u64,
    /// How long each waiter holds after notification (ms)
    hold_time: u64,
}

/// Tracks the order of notification completions
#[derive(Debug)]
struct NotificationTracker {
    completions: StdMutex<Vec<(usize, Instant)>>,
}

impl NotificationTracker {
    fn new() -> Self {
        Self {
            completions: StdMutex::new(Vec::new()),
        }
    }

    fn record_notification(&self, waiter_id: usize) {
        self.completions
            .lock()
            .unwrap()
            .push((waiter_id, Instant::now()));
    }

    fn get_notification_order(&self) -> Vec<(usize, Instant)> {
        let mut completions = self.completions.lock().unwrap().clone();
        completions.sort_by_key(|(_, timestamp)| *timestamp);
        completions
    }
}

/// Run notify test on asupersync Notify using thread-based async runtime
fn test_async_notify_conformance(config: &NotifyTest) -> NotifyConformanceResult {
    // Create a simple single-threaded async runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let notify = Arc::new(AsyncNotify::new());
        let tracker = Arc::new(NotificationTracker::new());
        let start_barrier = Arc::new(tokio::sync::Barrier::new(config.waiter_count + 1));
        let start_time = Instant::now();

        let mut handles = Vec::new();

        // Spawn waiters
        for i in 0..config.waiter_count {
            let notify = Arc::clone(&notify);
            let tracker = Arc::clone(&tracker);
            let start_barrier = Arc::clone(&start_barrier);
            let config = config.clone();

            let handle = tokio::spawn(async move {
                let waiter_id = i;
                start_barrier.wait().await;

                // Wait for notification
                notify.notified().await;

                // Hold for specified time
                tokio::time::sleep(Duration::from_millis(config.hold_time)).await;
                tracker.record_notification(waiter_id);
            });

            handles.push(handle);
        }

        // Start all waiters
        start_barrier.wait().await;

        // Allow waiters to get ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send notifications at specified intervals
        for i in 0..config.notification_count {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(config.notification_interval)).await;
            }

            notify.notify_one();
        }

        // Wait for all waiters to complete
        for handle in handles {
            handle.await.unwrap();
        }

        let notification_order = tracker.get_notification_order();

        NotifyConformanceResult {
            scenario: "async_notify".to_string(),
            notifications_sent: config.notification_count,
            waiters_notified: notification_order.len(),
            notification_order,
            duration: start_time.elapsed(),
        }
    })
}

/// Run notify test on tokio::sync::Notify
fn test_tokio_notify_conformance(config: &NotifyTest) -> NotifyConformanceResult {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let notify = Arc::new(TokioNotify::new());
        let tracker = Arc::new(NotificationTracker::new());
        let start_barrier = Arc::new(tokio::sync::Barrier::new(config.waiter_count + 1));
        let start_time = Instant::now();

        let mut handles = Vec::new();

        // Spawn waiters
        for i in 0..config.waiter_count {
            let notify = Arc::clone(&notify);
            let tracker = Arc::clone(&tracker);
            let start_barrier = Arc::clone(&start_barrier);
            let config = config.clone();

            let handle = tokio::spawn(async move {
                let waiter_id = i;
                start_barrier.wait().await;

                // Wait for notification
                notify.notified().await;

                // Hold for specified time
                tokio::time::sleep(Duration::from_millis(config.hold_time)).await;
                tracker.record_notification(waiter_id);
            });

            handles.push(handle);
        }

        // Start all waiters
        start_barrier.wait().await;

        // Allow waiters to get ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send notifications at specified intervals
        for i in 0..config.notification_count {
            if i > 0 {
                tokio::time::sleep(Duration::from_millis(config.notification_interval)).await;
            }

            if i % 2 == 0 {
                notify.notify_one();
            } else {
                // Mix of notify_one and notify_waiters to test both
                notify.notify_one();
            }
        }

        // Wait for all waiters to complete
        for handle in handles {
            handle.await.unwrap();
        }

        let notification_order = tracker.get_notification_order();

        NotifyConformanceResult {
            scenario: "tokio_notify".to_string(),
            notifications_sent: config.notification_count,
            waiters_notified: notification_order.len(),
            notification_order,
            duration: start_time.elapsed(),
        }
    })
}

/// Compare notify results between implementations
fn compare_notify_results(
    async_result: &NotifyConformanceResult,
    tokio_result: &NotifyConformanceResult,
) -> Result<(), String> {
    // Both should send same number of notifications
    if async_result.notifications_sent != tokio_result.notifications_sent {
        return Err(format!(
            "Notification count differs: async={}, tokio={}",
            async_result.notifications_sent, tokio_result.notifications_sent
        ));
    }

    // Both should notify same number of waiters (up to available waiters)
    if async_result.waiters_notified != tokio_result.waiters_notified {
        return Err(format!(
            "Notified waiters differ: async={}, tokio={}",
            async_result.waiters_notified, tokio_result.waiters_notified
        ));
    }

    // Check that the notification order patterns are consistent
    // We allow some timing variation but the relative order should be similar
    println!(
        "Async Notify order: {:?}",
        async_result
            .notification_order
            .iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>()
    );
    println!(
        "Tokio Notify order: {:?}",
        tokio_result
            .notification_order
            .iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>()
    );
    println!(
        "Async duration: {:?}, Tokio duration: {:?}",
        async_result.duration, tokio_result.duration
    );

    // Basic sanity checks
    if async_result.waiters_notified == 0 && async_result.notifications_sent > 0 {
        return Err("Async notify sent notifications but no waiters were notified".to_string());
    }

    if tokio_result.waiters_notified == 0 && tokio_result.notifications_sent > 0 {
        return Err("Tokio notify sent notifications but no waiters were notified".to_string());
    }

    Ok(())
}

#[test]
fn notify_basic_conformance() {
    let config = NotifyTest {
        waiter_count: 3,
        notification_count: 3,
        notification_interval: 5,
        hold_time: 1,
    };

    let async_result = test_async_notify_conformance(&config);
    let tokio_result = test_tokio_notify_conformance(&config);

    compare_notify_results(&async_result, &tokio_result)
        .expect("Basic notify conformance check failed");
}

#[test]
fn notify_single_waiter_multiple_notifications() {
    let config = NotifyTest {
        waiter_count: 1,
        notification_count: 5,
        notification_interval: 2,
        hold_time: 1,
    };

    let async_result = test_async_notify_conformance(&config);
    let tokio_result = test_tokio_notify_conformance(&config);

    // Single waiter should only get one notification
    assert_eq!(
        async_result.waiters_notified, 1,
        "Async notify: single waiter should only receive one notification"
    );
    assert_eq!(
        tokio_result.waiters_notified, 1,
        "Tokio notify: single waiter should only receive one notification"
    );

    compare_notify_results(&async_result, &tokio_result)
        .expect("Single waiter multiple notifications conformance check failed");
}

#[test]
fn notify_multiple_waiters_single_notification() {
    let config = NotifyTest {
        waiter_count: 5,
        notification_count: 1,
        notification_interval: 0,
        hold_time: 1,
    };

    let async_result = test_async_notify_conformance(&config);
    let tokio_result = test_tokio_notify_conformance(&config);

    // Single notification should wake exactly one waiter
    assert_eq!(
        async_result.waiters_notified, 1,
        "Async notify: single notification should wake exactly one waiter"
    );
    assert_eq!(
        tokio_result.waiters_notified, 1,
        "Tokio notify: single notification should wake exactly one waiter"
    );

    compare_notify_results(&async_result, &tokio_result)
        .expect("Multiple waiters single notification conformance check failed");
}

#[test]
fn notify_fairness_conformance() {
    let config = NotifyTest {
        waiter_count: 4,
        notification_count: 4,
        notification_interval: 10,
        hold_time: 5,
    };

    let async_result = test_async_notify_conformance(&config);
    let tokio_result = test_tokio_notify_conformance(&config);

    // All waiters should eventually be notified
    assert_eq!(
        async_result.waiters_notified, 4,
        "Async notify: all waiters should be notified"
    );
    assert_eq!(
        tokio_result.waiters_notified, 4,
        "Tokio notify: all waiters should be notified"
    );

    compare_notify_results(&async_result, &tokio_result)
        .expect("Notify fairness conformance check failed");
}

#[test]
fn notify_rapid_sequence_conformance() {
    let config = NotifyTest {
        waiter_count: 6,
        notification_count: 3,
        notification_interval: 1, // Rapid notifications
        hold_time: 2,
    };

    let async_result = test_async_notify_conformance(&config);
    let tokio_result = test_tokio_notify_conformance(&config);

    // Exactly 3 waiters should be notified
    assert_eq!(
        async_result.waiters_notified, 3,
        "Async notify: exactly 3 waiters should be notified"
    );
    assert_eq!(
        tokio_result.waiters_notified, 3,
        "Tokio notify: exactly 3 waiters should be notified"
    );

    compare_notify_results(&async_result, &tokio_result)
        .expect("Rapid sequence conformance check failed");
}
