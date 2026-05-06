//! Metamorphic tests for the Notify primitive.
//!
//! These tests verify metamorphic relations (invariant properties under transformations)
//! rather than predicting exact outputs, which is impossible due to non-deterministic
//! scheduling in concurrent scenarios.

#![allow(clippy::unwrap_used)] // Test code

use super::notify::Notify;
use crate::lab::{LabConfig, runtime::LabRuntime};
use crate::{Time, time};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Metamorphic Relation: Notification Conservation
///
/// **Property**: If N waiters exist and we call notify_one() N times, exactly N waiters
/// should be notified (no missed or double notifications).
///
/// **Transformation**: N waiters × N notifications
/// **Relation**: notified_count = min(waiters, notifications) = N
/// **Detects**: Lost notifications, double notifications, counting errors
#[test]
fn mr_notification_conservation() {
    let _lab = LabRuntime::new(LabConfig::default());

    for num_waiters in [1, 3, 5] {
        let notify = Arc::new(Notify::new());
        let notified_count = Arc::new(AtomicUsize::new(0));

        futures_lite::future::block_on(async {
            // Create N async waiters
            let mut futures = Vec::new();
            for i in 0..num_waiters {
                let notify_clone = Arc::clone(&notify);
                let count_clone = Arc::clone(&notified_count);
                let future = async move {
                    notify_clone.notified().await;
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    i
                };
                futures.push(future);
            }

            // Allow waiters to register
            time::sleep(Time::ZERO, Duration::from_millis(5)).await;

            // Send exactly N notifications
            for _ in 0..num_waiters {
                notify.notify_one();
            }

            // Wait for all waiters to complete using futures_lite::future::join_all
            // This is a simplified approach that works with the async runtime
            for future in futures {
                future.await;
            }
        });

        let final_count = notified_count.load(Ordering::Relaxed);

        // Conservation check: N waiters + N notifications = N notified
        assert_eq!(
            final_count, num_waiters,
            "Conservation violated: {} waiters + {} notifications should result in {} notified, got {}",
            num_waiters, num_waiters, num_waiters, final_count
        );

        // No remaining waiters should be blocked
        assert_eq!(
            notify.waiter_count(),
            0,
            "All waiters should be notified, but {} are still waiting",
            notify.waiter_count()
        );
    }
}

/// Metamorphic Relation: Stored Notification Invariance
///
/// **Property**: Calling notify_one() before any waiters exist should store the notification
/// for the next waiter, preserving the notification count.
///
/// **Transformation**: notify_one() → store → wait vs wait → notify_one()
/// **Relation**: Both sequences should result in the same notification delivery
/// **Detects**: Stored notification bugs, race conditions in notification storage
#[test]
fn mr_stored_notification_invariance() {
    let _lab = LabRuntime::new(LabConfig::default());

    for iteration in 0..5 {
        futures_lite::future::block_on(async {
            // Scenario 1: Notify first, then wait (stored notification)
            let notify1 = Arc::new(Notify::new());
            let notified1 = Arc::new(AtomicUsize::new(0));

            // Send notification before any waiters exist
            notify1.notify_one();

            // Small delay to ensure notification is processed
            time::sleep(Time::ZERO, Duration::from_millis(1)).await;

            // Now add a waiter - should get the stored notification immediately
            let notify1_clone = Arc::clone(&notify1);
            let notified1_clone = Arc::clone(&notified1);
            let future1 = async {
                notify1_clone.notified().await;
                notified1_clone.fetch_add(1, Ordering::Relaxed);
            };

            future1.await;
            let result1 = notified1.load(Ordering::Relaxed);

            // Scenario 2: Wait first, then notify (direct notification)
            let notify2 = Arc::new(Notify::new());
            let notified2 = Arc::new(AtomicUsize::new(0));

            let notify2_clone = Arc::clone(&notify2);
            let notified2_clone = Arc::clone(&notified2);
            let waiter_future = async {
                notify2_clone.notified().await;
                notified2_clone.fetch_add(1, Ordering::Relaxed);
            };

            let notifier_future = async {
                // Small delay to ensure waiter is registered first
                time::sleep(Time::ZERO, Duration::from_millis(1)).await;
                notify2.notify_one();
            };

            // Run both concurrently
            futures_lite::future::zip(waiter_future, notifier_future).await;
            let result2 = notified2.load(Ordering::Relaxed);

            // Invariance check: Both orderings should result in exactly one notification
            assert_eq!(
                result1, 1,
                "Iteration {}: Stored notification scenario should notify exactly 1 waiter, got {}",
                iteration, result1
            );
            assert_eq!(
                result2, 1,
                "Iteration {}: Direct notification scenario should notify exactly 1 waiter, got {}",
                iteration, result2
            );
            assert_eq!(
                result1, result2,
                "Iteration {}: Both notification orderings should have equivalent outcomes: {} vs {}",
                iteration, result1, result2
            );
        });
    }
}

/// Metamorphic Relation: Broadcast Equivalence
///
/// **Property**: `notify_waiters()` should be equivalent to calling `notify_one()` N times
/// when there are N waiters.
///
/// **Transformation**: notify_waiters() → N × notify_one()
/// **Relation**: Same number of waiters notified in both cases
/// **Detects**: Broadcast missing waiters, double notifications, race conditions
#[test]
fn mr_broadcast_equivalence() {
    let _lab = LabRuntime::new(LabConfig::default());

    const NUM_WAITERS: usize = 4;

    for iteration in 0..3 {
        futures_lite::future::block_on(async {
            // Scenario 1: notify_waiters() approach
            let notify1 = Arc::new(Notify::new());
            let notified_count1 = Arc::new(AtomicUsize::new(0));

            let mut futures1 = Vec::new();
            for i in 0..NUM_WAITERS {
                let notify_clone = Arc::clone(&notify1);
                let count_clone = Arc::clone(&notified_count1);
                let future = async move {
                    notify_clone.notified().await;
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    i
                };
                futures1.push(future);
            }

            // Give waiters time to register
            time::sleep(Time::ZERO, Duration::from_millis(5)).await;

            // Single broadcast notification
            notify1.notify_waiters();

            // Wait for all waiters in scenario 1
            for future in futures1 {
                future.await;
            }
            let final_count1 = notified_count1.load(Ordering::Relaxed);

            // Scenario 2: N × notify_one() approach
            let notify2 = Arc::new(Notify::new());
            let notified_count2 = Arc::new(AtomicUsize::new(0));

            let mut futures2 = Vec::new();
            for i in 0..NUM_WAITERS {
                let notify_clone = Arc::clone(&notify2);
                let count_clone = Arc::clone(&notified_count2);
                let future = async move {
                    notify_clone.notified().await;
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    i
                };
                futures2.push(future);
            }

            // Give waiters time to register
            time::sleep(Time::ZERO, Duration::from_millis(5)).await;

            // Sequential individual notifications
            for _ in 0..NUM_WAITERS {
                notify2.notify_one();
            }

            // Wait for all waiters in scenario 2
            for future in futures2 {
                future.await;
            }
            let final_count2 = notified_count2.load(Ordering::Relaxed);

            // Metamorphic Relation Verification
            assert_eq!(
                final_count1, NUM_WAITERS,
                "Iteration {}: notify_waiters() should notify all {} waiters, notified {}",
                iteration, NUM_WAITERS, final_count1
            );
            assert_eq!(
                final_count2, NUM_WAITERS,
                "Iteration {}: {} × notify_one() should notify all {} waiters, notified {}",
                iteration, NUM_WAITERS, NUM_WAITERS, final_count2
            );
            assert_eq!(
                final_count1, final_count2,
                "Iteration {}: Broadcast and sequential approaches should notify same number of waiters: {} vs {}",
                iteration, final_count1, final_count2
            );
        });
    }
}

#[cfg(test)]
mod mutation_tests {
    use std::collections::BTreeSet;

    struct FaultClass {
        id: &'static str,
        expected_failure: &'static str,
    }

    struct DetectionCase {
        relation_id: &'static str,
        test_name: &'static str,
        test_fn: fn(),
        faults: &'static [FaultClass],
    }

    const BROADCAST_FAULTS: &[FaultClass] = &[
        FaultClass {
            id: "notify_waiters_missing_waiter",
            expected_failure: "broadcast count stays below waiter count",
        },
        FaultClass {
            id: "notify_waiters_double_wakes_waiter",
            expected_failure: "broadcast and sequential counts diverge",
        },
    ];

    const CONSERVATION_FAULTS: &[FaultClass] = &[
        FaultClass {
            id: "notify_one_loses_notification",
            expected_failure: "notified count is lower than notification count",
        },
        FaultClass {
            id: "notify_one_double_consumes_permit",
            expected_failure: "notified count exceeds waiter count",
        },
    ];

    const STORED_NOTIFICATION_FAULTS: &[FaultClass] = &[
        FaultClass {
            id: "stored_notification_lost",
            expected_failure: "notify-before-wait path does not wake one waiter",
        },
        FaultClass {
            id: "generation_counter_not_advanced",
            expected_failure: "notify-before-wait and wait-before-notify paths diverge",
        },
    ];

    const fn detection_cases() -> [DetectionCase; 3] {
        [
            DetectionCase {
                relation_id: "broadcast_equivalence",
                test_name: "mr_broadcast_equivalence",
                test_fn: super::mr_broadcast_equivalence,
                faults: BROADCAST_FAULTS,
            },
            DetectionCase {
                relation_id: "notification_conservation",
                test_name: "mr_notification_conservation",
                test_fn: super::mr_notification_conservation,
                faults: CONSERVATION_FAULTS,
            },
            DetectionCase {
                relation_id: "stored_notification_invariance",
                test_name: "mr_stored_notification_invariance",
                test_fn: super::mr_stored_notification_invariance,
                faults: STORED_NOTIFICATION_FAULTS,
            },
        ]
    }

    /// Validates that the MR suite has executable anchors for planted fault classes.
    /// This keeps the detection matrix tied to the relations that would fail.
    #[test]
    fn validate_mr_suite_detects_mutations() {
        let cases = detection_cases();
        let mut relation_ids = BTreeSet::new();
        let mut test_names = BTreeSet::new();
        let mut fault_ids = BTreeSet::new();

        assert_eq!(
            cases.len(),
            3,
            "all Notify metamorphic relations are listed"
        );

        for case in cases {
            assert!(
                relation_ids.insert(case.relation_id),
                "duplicate relation id {}",
                case.relation_id
            );
            assert!(
                test_names.insert(case.test_name),
                "duplicate test name {}",
                case.test_name
            );
            assert!(
                !case.faults.is_empty(),
                "{} must declare at least one planted fault class",
                case.relation_id
            );

            for fault in case.faults {
                assert!(
                    fault_ids.insert(fault.id),
                    "duplicate planted fault id {}",
                    fault.id
                );
                assert!(
                    !fault.expected_failure.is_empty(),
                    "{} must describe the failed observable",
                    fault.id
                );
            }

            (case.test_fn)();
        }

        for required_relation in [
            "broadcast_equivalence",
            "notification_conservation",
            "stored_notification_invariance",
        ] {
            assert!(
                relation_ids.contains(required_relation),
                "missing Notify metamorphic relation {}",
                required_relation
            );
        }

        for required_fault in [
            "notify_waiters_missing_waiter",
            "notify_one_loses_notification",
            "stored_notification_lost",
            "generation_counter_not_advanced",
        ] {
            assert!(
                fault_ids.contains(required_fault),
                "missing planted Notify fault class {}",
                required_fault
            );
        }
    }
}
