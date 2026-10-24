    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::cx::Cx;
    use crate::runtime::yield_now;
    use crate::types::Budget;
    use proptest::prelude::*;
    use serde_json::Value;
    use std::sync::Mutex;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // =========================================================================
    // Basic Permit Acquisition
    // =========================================================================

    #[test]
    fn new_bulkhead_has_full_capacity() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
        assert_eq!(bh.metrics().active_permits, 0);
        assert!((bh.metrics().utilization - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn try_acquire_reduces_available() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        let permit = bh.try_acquire(1, now).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 9);
        assert_eq!(bh.metrics().active_permits, 1);

        permit.release();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
        assert_eq!(bh.metrics().active_permits, 0);
    }

    #[test]
    fn try_acquire_fails_when_exhausted() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 2,
            ..Default::default()
        });

        let p1 = bh.try_acquire(1, now).unwrap();
        let p2 = bh.try_acquire(1, now).unwrap();
        let p3 = bh.try_acquire(1, now);

        assert!(p3.is_none());
        assert_eq!(bh.metrics().active_permits, 2);

        p1.release();
        p2.release();
    }

    // =========================================================================
    // Weighted Permits
    // =========================================================================

    #[test]
    fn weighted_permit_consumes_multiple() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        let permit = bh.try_acquire(5, now).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 5);
        assert_eq!(permit.weight(), 5);

        // Cannot acquire 6 more
        assert!(bh.try_acquire(6, now).is_none());

        // Can acquire 5
        let p2 = bh.try_acquire(5, now).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 0);

        permit.release();
        p2.release();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn weighted_permit_zero_weight_allowed() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        // Zero weight permits can be useful for "observer" patterns
        let permit = bh.try_acquire(0, now).unwrap();
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
        permit.release();
    }

    // =========================================================================
    // Queue Tests
    // =========================================================================

    #[test]
    fn enqueue_adds_to_queue() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1, now).unwrap();

        // Enqueue should succeed
        let entry_id = bh.enqueue(1, now).unwrap();
        assert!(entry_id < 1000); // Sanity check

        assert_eq!(bh.metrics().total_queued, 1);
    }

    #[test]
    fn try_acquire_yields_to_queued_entry() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        let permit = bh.try_acquire(1, now).unwrap();
        let entry_id = bh.enqueue(1, now).unwrap();

        permit.release();

        assert!(
            bh.try_acquire(1, now).is_none(),
            "queued entry should block barging try_acquire"
        );

        let granted_id = bh.process_queue(now);
        assert_eq!(granted_id, Some(entry_id));
        assert_eq!(
            bh.available(),
            0,
            "queued entry should consume the released permit"
        );

        let claimed = bh.check_entry(entry_id, now).unwrap();
        assert!(
            claimed.is_some(),
            "queued entry should be claimable after process_queue"
        );
    }

    #[test]
    fn try_acquire_recovers_after_abandoned_enqueue_times_out() {
        // A bare enqueue() that is never resolved via check_entry/cancel_entry
        // must NOT starve try_acquire forever: once the entry's deadline passes,
        // try_acquire drains it (process_queue-first) and succeeds with permits
        // free (br-asupersync-bulkhead-tryacquire-starve-kodql2).
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        // Hold the only permit, enqueue a waiter, then release the permit. The
        // waiter is now "abandoned" — nobody will ever call check_entry/cancel.
        let permit = bh.try_acquire(1, now).unwrap();
        let _abandoned = bh.enqueue(1, now).unwrap();
        permit.release();

        // Before the deadline, the pending waiter correctly blocks the fast path.
        assert!(
            bh.try_acquire(1, now).is_none(),
            "pending waiter blocks try_acquire before its deadline"
        );

        // Past the entry deadline (queue_timeout 60s), try_acquire must drain the
        // stale entry and succeed instead of starving forever.
        let later = Time::from_millis(60_001);
        let recovered = bh.try_acquire(1, later);
        assert!(
            recovered.is_some(),
            "try_acquire must recover once the abandoned entry times out"
        );
    }

    #[test]
    fn dropping_unclaimed_queued_acquire_releases_granted_permit() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let now = Time::from_millis(0);

        let permit = bh.try_acquire(1, now).unwrap();
        let guard = bh.acquire_queued(1, now).expect("queued acquire");
        let entry_id = guard.entry_id();
        permit.release();

        // Grant the queued entry; it now holds a granted-but-unclaimed permit.
        assert_eq!(
            bh.process_queue(now),
            Some(entry_id),
            "queued entry granted"
        );
        assert_eq!(bh.available(), 0, "grant consumed the released permit");

        // Drop the guard WITHOUT claiming: the granted permit must be released,
        // not leaked (5vzqse).
        drop(guard);
        assert_eq!(
            bh.available(),
            1,
            "granted-but-unclaimed permit must be released on guard drop, not leaked",
        );
        assert!(
            bh.try_acquire(1, now).is_some(),
            "permit is reusable after the guard releases it",
        );
    }

    #[test]
    fn try_acquire_observes_waiter_before_counter_publish() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);
        {
            let mut queue = bh.queue.write();
            queue.push_back(QueueEntry {
                id: 42,
                weight: 1,
                enqueued_at_millis: now.as_millis(),
                deadline_millis: now.as_millis().saturating_add(60_000),
                result: None,
            });
        }

        assert!(
            bh.try_acquire(1, now).is_none(),
            "direct acquisition must not barge ahead of a waiter that is already in the queue"
        );
        assert_eq!(
            bh.available(),
            1,
            "failed barging attempt must not consume a permit"
        );
    }

    #[test]
    fn enqueue_rejects_when_queue_full() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 2,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1, now).unwrap();

        // Fill queue
        bh.enqueue(1, now).unwrap();
        bh.enqueue(1, now).unwrap();

        // Third should fail
        let result = bh.enqueue(1, now);
        assert!(matches!(result, Err(BulkheadError::QueueFull)));
        assert_eq!(bh.metrics().total_rejected, 1);
    }

    #[test]
    fn process_queue_grants_when_permits_available() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let p = bh.try_acquire(1, now).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Release permit
        p.release();

        // Process queue - should grant
        let granted = bh.process_queue(now);
        assert_eq!(granted, Some(entry_id));
    }

    #[test]
    fn check_entry_returns_permit_when_granted() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 2,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let p1 = bh.try_acquire(1, now).unwrap();
        let _p2 = bh.try_acquire(1, now).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Still waiting
        let result = bh.check_entry(entry_id, now);
        assert!(matches!(result, Ok(None)));

        // Release one permit
        p1.release();

        // Now should be granted
        let result = bh.check_entry(entry_id, now);
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn queue_timeout_triggers_error() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_millis(100),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1, now).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Check after timeout
        let later = Time::from_millis(200);
        let result = bh.check_entry(entry_id, later);

        assert!(matches!(result, Err(BulkheadError::QueueTimeout { .. })));
        assert_eq!(bh.metrics().total_timeout, 1);
    }

    #[test]
    fn cancel_entry_triggers_cancellation() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // Exhaust permits
        let _p = bh.try_acquire(1, now).unwrap();

        // Enqueue
        let entry_id = bh.enqueue(1, now).unwrap();

        // Cancel
        bh.cancel_entry(entry_id, now);

        assert_eq!(bh.metrics().total_cancelled, 1);
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn metrics_track_active_permits() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        assert_eq!(bh.metrics().active_permits, 0);

        let p1 = bh.try_acquire(1, now).unwrap();
        assert_eq!(bh.metrics().active_permits, 1);

        let p2 = bh.try_acquire(3, now).unwrap();
        assert_eq!(bh.metrics().active_permits, 4);

        p1.release();
        assert_eq!(bh.metrics().active_permits, 3);

        p2.release();
        assert_eq!(bh.metrics().active_permits, 0);
    }

    #[test]
    fn metrics_calculate_utilization() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        assert!((bh.metrics().utilization - 0.0).abs() < f64::EPSILON);

        let p1 = bh.try_acquire(5, now).unwrap();
        assert!((bh.metrics().utilization - 0.5).abs() < f64::EPSILON);

        let p2 = bh.try_acquire(5, now).unwrap();
        assert!((bh.metrics().utilization - 1.0).abs() < f64::EPSILON);

        p1.release();
        p2.release();
    }

    #[test]
    fn metrics_initial_values() {
        let bh = Bulkhead::new(BulkheadPolicy {
            name: "test".into(),
            max_concurrent: 5,
            ..Default::default()
        });

        let m = bh.metrics();
        assert_eq!(m.active_permits, 0);
        assert_eq!(m.queue_depth, 0);
        assert_eq!(m.total_executed, 0);
        assert_eq!(m.total_queued, 0);
        assert_eq!(m.total_rejected, 0);
        assert_eq!(m.total_timeout, 0);
        assert_eq!(m.total_cancelled, 0);
        assert!((m.avg_queue_wait_ms - 0.0).abs() < f64::EPSILON);
        assert_eq!(m.max_queue_wait_ms, 0);
    }

    // =========================================================================
    // Registry Tests
    // =========================================================================

    #[test]
    fn registry_creates_named_bulkheads() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh1 = registry.get_or_create("service-a");
        let bh2 = registry.get_or_create("service-b");
        let bh3 = registry.get_or_create("service-a");

        // Same name returns same instance
        assert!(Arc::ptr_eq(&bh1, &bh3));

        // Different names return different instances
        assert!(!Arc::ptr_eq(&bh1, &bh2));
    }

    #[test]
    fn registry_uses_provided_name() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh = registry.get_or_create("my-service");
        assert_eq!(bh.name(), "my-service");
    }

    #[test]
    fn registry_custom_policy() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh = registry.get_or_create_with(
            "custom",
            BulkheadPolicy {
                max_concurrent: 100,
                max_queue: 500,
                ..Default::default()
            },
        );

        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn registry_all_metrics() {
        let now = Time::from_millis(0);
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh1 = registry.get_or_create("db");
        let bh2 = registry.get_or_create("api");

        let _p1 = bh1.try_acquire(1, now);
        let _p2 = bh2.try_acquire(3, now);

        let all = registry.all_metrics();
        assert_eq!(all.len(), 2);
        assert_eq!(all.get("db").unwrap().active_permits, 1);
        assert_eq!(all.get("api").unwrap().active_permits, 3);
    }

    #[test]
    fn registry_remove() {
        let registry = BulkheadRegistry::new(BulkheadPolicy::default());

        let bh1 = registry.get_or_create("temp");
        assert_eq!(registry.all_metrics().len(), 1);

        let removed = registry.remove("temp");
        assert!(removed.is_some());
        assert!(Arc::ptr_eq(&bh1, &removed.unwrap()));
        assert_eq!(registry.all_metrics().len(), 0);

        // Remove non-existent returns None
        assert!(registry.remove("nonexistent").is_none());
    }

    // =========================================================================
    // Concurrent Access Tests
    // =========================================================================

    #[test]
    fn concurrent_acquire_release_safe() {
        use std::thread;

        let now = Time::from_millis(0);
        let bh = Arc::new(Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        }));

        let handles: Vec<_> = (0..100)
            .map(|_| {
                let bh = bh.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        if let Some(permit) = bh.try_acquire(1, now) {
                            // Simulate work
                            std::thread::yield_now();
                            permit.release();
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All permits should be returned
        assert_eq!(bh.available_permits.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn concurrent_never_exceeds_max() {
        use std::sync::atomic::AtomicU32;
        use std::thread;

        let now = Time::from_millis(0);
        let bh = Arc::new(Bulkhead::new(BulkheadPolicy {
            max_concurrent: 5,
            ..Default::default()
        }));

        let current = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));

        let handles: Vec<_> = (0..50)
            .map(|_| {
                let bh = bh.clone();
                let current = current.clone();
                let peak = peak.clone();

                thread::spawn(move || {
                    for _ in 0..20 {
                        if let Some(permit) = bh.try_acquire(1, now) {
                            let c = current.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(c, Ordering::SeqCst);

                            std::thread::yield_now();

                            current.fetch_sub(1, Ordering::SeqCst);
                            permit.release();
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert!(peak.load(Ordering::SeqCst) <= 5);
    }

    // =========================================================================
    // Call Helper Tests
    // =========================================================================

    #[test]
    fn call_executes_and_records() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy::default());

        let result = bh.call(now, || Ok::<_, &str>(42));

        assert_eq!(result.unwrap(), 42);
        assert_eq!(bh.metrics().total_executed, 1);
    }

    #[test]
    fn call_handles_inner_error() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy::default());

        let result: Result<i32, BulkheadError<&str>> = bh.call(now, || Err("error"));

        assert!(matches!(result, Err(BulkheadError::Inner("error"))));
        assert_eq!(
            bh.metrics().total_executed,
            1,
            "inner-error calls still executed and should be counted"
        );
    }

    #[test]
    fn enqueue_with_huge_timeout_does_not_wrap_deadline() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 2,
            queue_timeout: Duration::MAX,
            ..Default::default()
        });

        let now = Time::MAX;
        let _p = bh.try_acquire(1, now).unwrap();
        let entry_id = bh.enqueue(1, now).unwrap();

        // If deadline arithmetic wraps, this may spuriously timeout immediately.
        let state = bh.check_entry(entry_id, now);
        assert!(
            matches!(state, Ok(None)),
            "entry should remain pending at enqueue time even with huge timeout"
        );
    }

    #[test]
    fn call_rejects_when_full() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        });

        let _p = bh.try_acquire(1, now).unwrap();

        let result: Result<i32, BulkheadError<&str>> = bh.call(now, || Ok(42));

        assert!(matches!(result, Err(BulkheadError::Full)));
    }

    #[test]
    fn call_releases_permit_on_panic() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            ..Default::default()
        });

        // Verify starting capacity
        assert_eq!(bh.available(), 1);

        // Call that panics
        let result = catch_unwind(AssertUnwindSafe(|| {
            bh.call(now, || -> Result<(), &str> {
                panic!("intentional test panic")
            })
        }));

        // Should have panicked
        assert!(result.is_err());

        // Permit should be released despite panic
        assert_eq!(bh.available(), 1, "permit should be released after panic");

        // Should be able to acquire again
        let permit = bh.try_acquire(1, now);
        assert!(permit.is_some(), "should be able to acquire after panic");
    }

    // =========================================================================
    // Builder Tests
    // =========================================================================

    #[test]
    fn builder_creates_policy() {
        let policy = BulkheadPolicyBuilder::new()
            .name("test")
            .max_concurrent(20)
            .max_queue(50)
            .queue_timeout(Duration::from_secs(30))
            .weighted(true)
            .build();

        assert_eq!(policy.name, "test");
        assert_eq!(policy.max_concurrent, 20);
        assert_eq!(policy.max_queue, 50);
        assert_eq!(policy.queue_timeout, Duration::from_secs(30));
        assert!(policy.weighted);
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn error_display() {
        let full: BulkheadError<&str> = BulkheadError::Full;
        assert!(full.to_string().contains("full"));

        let queue_full: BulkheadError<&str> = BulkheadError::QueueFull;
        assert!(queue_full.to_string().contains("queue full"));

        let timeout: BulkheadError<&str> = BulkheadError::QueueTimeout {
            waited: Duration::from_millis(500),
        };
        assert!(timeout.to_string().contains("timeout"));

        let cancelled: BulkheadError<&str> = BulkheadError::Cancelled;
        assert!(cancelled.to_string().contains("cancelled"));

        let inner: BulkheadError<&str> = BulkheadError::Inner("inner error");
        assert_eq!(inner.to_string(), "inner error");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_restores_capacity() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        let _p1 = bh.try_acquire(5, now).unwrap();
        let _p2 = bh.try_acquire(3, now).unwrap();

        assert_eq!(bh.available(), 2);

        bh.reset();

        assert_eq!(bh.available(), 10);
    }

    #[test]
    fn release_after_reset_does_not_exceed_max_concurrent() {
        let now = Time::from_millis(0);
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 10,
            ..Default::default()
        });

        // Acquire permits
        let p1 = bh.try_acquire(5, now).unwrap();
        let p2 = bh.try_acquire(3, now).unwrap();
        assert_eq!(bh.available(), 2);

        // Reset while permits outstanding
        bh.reset();
        assert_eq!(bh.available(), 10);

        // Release pre-reset permits — must NOT exceed max_concurrent
        p1.release();
        assert_eq!(
            bh.available(),
            10,
            "available_permits must be capped at max_concurrent after reset + release"
        );

        p2.release();
        assert_eq!(
            bh.available(),
            10,
            "available_permits must still be capped after second release"
        );

        // Core invariant: must not grant more than max_concurrent permits
        let mut permits: Vec<BulkheadPermit> = Vec::new();
        for _ in 0..10 {
            permits.push(bh.try_acquire(1, now).unwrap());
        }
        assert!(
            bh.try_acquire(1, now).is_none(),
            "must reject 11th permit even after reset + release"
        );

        for p in permits {
            p.release();
        }
    }

    #[test]
    fn reset_racing_cancel_never_wraps_the_pending_count() {
        // br-asupersync-r0x5ho: cancel_entry decremented the pending count after
        // releasing the queue lock, so a reset() zeroing it in between wrapped
        // it to u32::MAX and every later try_acquire failed. The window is a
        // few instructions wide, so this loops; a wrapped count is never a
        // legitimate value, whatever reset runs afterwards.
        let now = Time::from_millis(0);
        let bh = Arc::new(Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            ..Default::default()
        }));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resetter = {
            let bh = Arc::clone(&bh);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    bh.reset();
                }
            })
        };
        for _ in 0..50_000 {
            if let Ok(entry_id) = bh.enqueue(1, now) {
                bh.cancel_entry(entry_id, now);
            }
            let pending = bh.pending_queue_count.load(Ordering::Relaxed);
            assert!(pending < 1 << 16, "pending count wrapped to {pending}");
        }
        stop.store(true, Ordering::Relaxed);
        resetter.join().expect("resetter thread");
        bh.reset();
        assert!(bh.try_acquire(1, now).is_some(), "the fast path stays open");
    }

    #[test]
    fn cancel_entry_releases_permit_if_already_granted() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 1. Exhaust permits
        let p1 = bh.try_acquire(1, now).unwrap();

        // 2. Enqueue waiter
        let entry_id = bh.enqueue(1, now).unwrap();

        // 3. Release permit (making it available for the waiter)
        p1.release();

        // 4. Process queue (grants the permit to the waiter)
        let granted_id = bh.process_queue(now);
        assert_eq!(granted_id, Some(entry_id));

        // At this point, the waiter has the permit reserved (available = 0)
        // but hasn't claimed it via check_entry.
        assert_eq!(bh.available(), 0);

        // 5. Cancel the entry (simulate user dropping the future)
        bh.cancel_entry(entry_id, now);

        // 6. Verify permit is returned
        // REGRESSION TEST: Without the fix, this assertion fails because the permit is leaked.
        assert_eq!(
            bh.available(),
            1,
            "permit should be released upon cancellation of granted entry"
        );
    }

    #[test]
    fn cancel_removes_entry_from_queue() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 1. Exhaust permits
        let _p1 = bh.try_acquire(1, now).unwrap();

        // 2. Enqueue waiter
        let entry_id = bh.enqueue(1, now).unwrap();

        // 3. Cancel the entry
        bh.cancel_entry(entry_id, now);

        // 4. Verify queue is empty
        let metrics = bh.metrics();
        assert_eq!(
            metrics.queue_depth, 0,
            "queue should be empty after cancellation"
        );

        // Internal check to ensure vector is actually cleared
        // We can't access private fields, but we can check if we can fill the queue again
        // If the zombie is still there, we might hit the limit earlier than expected
        for _ in 0..10 {
            assert!(bh.enqueue(1, now).is_ok());
        }
    }

    #[test]
    fn cancel_removes_timed_out_entry_from_queue() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 10,
            queue_timeout: Duration::from_millis(1),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 1. Exhaust permits
        let _p1 = bh.try_acquire(1, now).unwrap();

        // 2. Enqueue waiter
        let entry_id = bh.enqueue(1, now).unwrap();

        // 3. Timeout the entry
        let later = Time::from_millis(100);
        bh.process_queue(later);

        // 4. Cancel the entry
        bh.cancel_entry(entry_id, now);

        // 5. Verify queue is empty
        let metrics = bh.metrics();
        assert_eq!(
            metrics.queue_depth, 0,
            "queue should be empty after cancellation of timed-out entry"
        );

        for _ in 0..10 {
            assert!(bh.enqueue(1, now).is_ok());
        }
    }

    #[test]
    fn cancelled_entry_behind_granted_zombie_frees_queue_slot() {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 2,
            ..Default::default()
        });

        let now = Time::from_millis(0);

        let p1 = bh.try_acquire(1, now).unwrap();
        let id1 = bh.enqueue(1, now).unwrap();
        let id2 = bh.enqueue(1, now).unwrap();

        p1.release();
        assert_eq!(bh.process_queue(now), Some(id1));

        bh.cancel_entry(id2, now);

        assert!(
            bh.enqueue(1, now).is_ok(),
            "actively cancelled entry must stop occupying queue capacity behind a granted zombie"
        );
    }

    #[test]
    fn zombies_fill_queue() {
        // Regression test for unbounded queue growth due to abandoned entries.
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 2,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });

        let now = Time::from_millis(0);

        // 1. Exhaust permits
        let p1 = bh.try_acquire(1, now).unwrap();

        // 2. Fill queue
        let id1 = bh.enqueue(1, now).unwrap();
        let _id2 = bh.enqueue(1, now).unwrap();

        // 3. Release permit - grants id1
        p1.release();
        let granted = bh.process_queue(now);
        assert_eq!(granted, Some(id1));

        // 4. Don't claim id1. It sits in queue as "Granted".
        // Queue len is still 2.

        // 5. Try to enqueue - should be rejected because queue is full of zombies/waiting
        let result = bh.enqueue(1, now);
        assert!(
            matches!(result, Err(BulkheadError::QueueFull)),
            "Zombies should count towards queue limit"
        );

        // 6. Claim id1 (removes it)
        let permit = bh.check_entry(id1, now).unwrap().unwrap();
        permit.release();

        // 7. Queue len now 1. Can enqueue.
        bh.enqueue(1, now).expect("enqueue should succeed");
    }

    #[derive(Debug, PartialEq, Eq)]
    struct QueueAdmissionRun {
        granted_positions: Vec<usize>,
        queue_depth: u32,
        available: u32,
        queued_executed: u64,
        total_cancelled: u64,
    }

    fn run_queue_admission(cancelled: &[bool], filter_cancelled: bool) -> QueueAdmissionRun {
        let bh = Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: cancelled.len() as u32 + 1,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        let now = Time::from_millis(0);
        let held = bh.try_acquire(1, now).expect("seed permit must exist");
        let mut entries = Vec::new();

        for (position, &is_cancelled) in cancelled.iter().enumerate() {
            if filter_cancelled && is_cancelled {
                continue;
            }
            let entry_id = bh.enqueue(1, now).expect("queue should have capacity");
            entries.push((position, entry_id, is_cancelled));
        }

        if !filter_cancelled {
            for &(_, entry_id, is_cancelled) in &entries {
                if is_cancelled {
                    bh.cancel_entry(entry_id, now);
                }
            }
        }

        held.release();

        let mut granted_positions = Vec::new();
        for &(position, entry_id, is_cancelled) in &entries {
            if !filter_cancelled && is_cancelled {
                assert!(
                    matches!(bh.check_entry(entry_id, now), Err(BulkheadError::Cancelled)),
                    "cancelled entry should not remain claimable"
                );
                continue;
            }

            let permit = bh
                .check_entry(entry_id, now)
                .expect("survivor should not reject")
                .expect("survivor should be granted in FIFO order");
            granted_positions.push(position);
            permit.release();
        }

        let metrics = bh.metrics();
        QueueAdmissionRun {
            granted_positions,
            queue_depth: metrics.queue_depth,
            available: bh.available(),
            queued_executed: metrics.total_executed.saturating_sub(1),
            total_cancelled: metrics.total_cancelled,
        }
    }

    proptest! {
        #[test]
        fn metamorphic_queue_cancellation_matches_filtered_admission(cancelled in prop::collection::vec(any::<bool>(), 1..12)) {
            let cancelled_run = run_queue_admission(&cancelled, false);
            let filtered_run = run_queue_admission(&cancelled, true);
            let expected_positions = cancelled
                .iter()
                .enumerate()
                .filter_map(|(position, &is_cancelled)| (!is_cancelled).then_some(position))
                .collect::<Vec<_>>();
            let survivor_count = expected_positions.len() as u64;
            let cancelled_count = cancelled.iter().filter(|&&is_cancelled| is_cancelled).count() as u64;

            prop_assert_eq!(&cancelled_run.granted_positions, &expected_positions);
            prop_assert_eq!(&filtered_run.granted_positions, &expected_positions);
            prop_assert_eq!(
                &cancelled_run.granted_positions,
                &filtered_run.granted_positions
            );

            prop_assert_eq!(cancelled_run.queue_depth, 0);
            prop_assert_eq!(filtered_run.queue_depth, 0);
            prop_assert_eq!(cancelled_run.available, 1);
            prop_assert_eq!(filtered_run.available, 1);

            prop_assert_eq!(cancelled_run.queued_executed, survivor_count);
            prop_assert_eq!(filtered_run.queued_executed, survivor_count);
            prop_assert_eq!(cancelled_run.total_cancelled, cancelled_count);
            prop_assert_eq!(filtered_run.total_cancelled, 0);
        }
    }

    // =========================================================================
    // Conformance: Isolation under concurrent overflow
    // =========================================================================

    #[test]
    fn conf_isolation_independent_bulkheads_isolated_overflow() {
        // CONF-BULKHEAD-001: Overflow in one bulkhead must not affect other bulkheads
        let bh_critical = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "critical-service".into(),
            max_concurrent: 2,
            max_queue: 1,
            ..Default::default()
        }));

        let bh_batch = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "batch-service".into(),
            max_concurrent: 1,
            max_queue: 1,
            ..Default::default()
        }));

        let now = Time::from_millis(0);

        // 1. Overflow the batch service
        let _batch_p1 = bh_batch.try_acquire(1, now).unwrap();
        let _batch_queue_id = bh_batch.enqueue(1, now).unwrap();
        let batch_overflow = bh_batch.enqueue(1, now);
        assert!(matches!(batch_overflow, Err(BulkheadError::QueueFull)));

        // 2. Verify critical service unaffected by batch overflow
        assert_eq!(bh_critical.available(), 2);
        let crit_p1 = bh_critical.try_acquire(1, now);
        assert!(
            crit_p1.is_some(),
            "critical service should be unaffected by batch overflow"
        );

        let crit_p2 = bh_critical.try_acquire(1, now);
        assert!(
            crit_p2.is_some(),
            "critical service should maintain full capacity"
        );

        // 3. Verify overflow metrics isolated
        let batch_metrics = bh_batch.metrics();
        let critical_metrics = bh_critical.metrics();

        assert_eq!(batch_metrics.total_rejected, 1);
        assert_eq!(critical_metrics.total_rejected, 0);
        assert_eq!(critical_metrics.active_permits, 2);
        assert_eq!(batch_metrics.active_permits, 1);
    }

    #[test]
    fn conf_isolation_concurrent_overflows_independent() {
        // CONF-BULKHEAD-002: Multiple bulkheads can overflow simultaneously without interference
        let bh_db = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "database".into(),
            max_concurrent: 1,
            max_queue: 2,
            ..Default::default()
        }));

        let bh_api = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "external-api".into(),
            max_concurrent: 1,
            max_queue: 1,
            ..Default::default()
        }));

        let now = Time::from_millis(0);

        // 1. Overflow both bulkheads simultaneously
        let _db_p = bh_db.try_acquire(1, now).unwrap();
        let _api_p = bh_api.try_acquire(1, now).unwrap();

        // Fill queues
        let _db_q1 = bh_db.enqueue(1, now).unwrap();
        let _db_q2 = bh_db.enqueue(1, now).unwrap();
        let _api_q1 = bh_api.enqueue(1, now).unwrap();

        // Overflow both
        let db_overflow = bh_db.enqueue(1, now);
        let api_overflow = bh_api.enqueue(1, now);

        assert!(matches!(db_overflow, Err(BulkheadError::QueueFull)));
        assert!(matches!(api_overflow, Err(BulkheadError::QueueFull)));

        // 2. Verify independent rejection tracking
        assert_eq!(bh_db.metrics().total_rejected, 1);
        assert_eq!(bh_api.metrics().total_rejected, 1);
        assert_eq!(bh_db.metrics().queue_depth, 2);
        assert_eq!(bh_api.metrics().queue_depth, 1);

        // 3. Verify independent recovery capability
        let third_service = Bulkhead::new(BulkheadPolicy {
            name: "unaffected".into(),
            max_concurrent: 5,
            ..Default::default()
        });

        // Should work normally despite other overflows
        let p1 = third_service.try_acquire(3, now);
        assert!(
            p1.is_some(),
            "unaffected service should work during other overflows"
        );
        assert_eq!(third_service.available(), 2);
    }

    #[test]
    fn conf_isolation_overflow_recovery_isolated() {
        // CONF-BULKHEAD-003: Recovery from overflow in one bulkhead doesn't affect others
        let bh_overloaded = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "overloaded".into(),
            max_concurrent: 1,
            max_queue: 2,
            ..Default::default()
        }));

        let bh_stable = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "stable".into(),
            max_concurrent: 2,
            max_queue: 5,
            ..Default::default()
        }));

        let now = Time::from_millis(0);

        // 1. Create overflow condition
        let overloaded_permit = bh_overloaded.try_acquire(1, now).unwrap();
        let _q1 = bh_overloaded.enqueue(1, now).unwrap();
        let _q2 = bh_overloaded.enqueue(1, now).unwrap();
        let overflow = bh_overloaded.enqueue(1, now);
        assert!(matches!(overflow, Err(BulkheadError::QueueFull)));

        // 2. Stable service operating normally
        let _stable_p1 = bh_stable.try_acquire(1, now).unwrap();
        let _stable_q1 = bh_stable.enqueue(1, now).unwrap();
        assert_eq!(bh_stable.available(), 1);

        // 3. Recovery in overloaded service
        overloaded_permit.release();
        let _granted = bh_overloaded.process_queue(now);

        // 4. Verify stable service unaffected by recovery
        assert_eq!(
            bh_stable.available(),
            1,
            "stable service should be unaffected by recovery"
        );
        assert_eq!(bh_stable.metrics().active_permits, 1);
        assert_eq!(bh_stable.metrics().queue_depth, 1);

        // 5. Both services should work independently after recovery.
        // Grant the stable bulkhead's queued entry first so that the FIFO
        // waiter does not block a subsequent `try_acquire` fast-path.
        let _granted_stable = bh_stable.process_queue(now);
        let new_stable = bh_stable.try_acquire(1, now);
        // After granting the queued entry, the stable bulkhead is back to
        // zero-available (1 stable_p1 + 1 granted queued entry). The new
        // try_acquire should therefore fail, confirming the service is
        // still functional and honours capacity bounds independently of
        // the overloaded bulkhead's recovery.
        assert!(
            new_stable.is_none(),
            "stable service should enforce its own capacity bounds"
        );
        assert_eq!(bh_stable.available(), 0);

        let overloaded_available = bh_overloaded.available();
        assert_eq!(
            overloaded_available, 0,
            "overloaded service should have granted queued request"
        );
    }

    #[test]
    fn conf_isolation_weighted_permits_overflow_isolation() {
        // CONF-BULKHEAD-004: Weighted permit overflow isolation
        let bh_heavy = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "heavy-ops".into(),
            max_concurrent: 10,
            max_queue: 3,
            weighted: true,
            ..Default::default()
        }));

        let bh_light = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "light-ops".into(),
            max_concurrent: 5,
            max_queue: 3,
            weighted: true,
            ..Default::default()
        }));

        let now = Time::from_millis(0);

        // 1. Overflow heavy service with weighted permits. Queue capacity
        //    is measured in entry count (max_queue=3), independent of the
        //    weighted permits held by each entry.
        let _heavy_p1 = bh_heavy.try_acquire(8, now).unwrap(); // 2 remaining
        let _heavy_q1 = bh_heavy.enqueue(2, now).unwrap();
        let _heavy_q2 = bh_heavy.enqueue(1, now).unwrap();
        let _heavy_q3 = bh_heavy.enqueue(2, now).unwrap();

        // Fourth enqueue overflows the queue (max_queue=3).
        let heavy_overflow = bh_heavy.enqueue(3, now);
        assert!(matches!(heavy_overflow, Err(BulkheadError::QueueFull)));

        // 2. Light service should work normally with weighted permits
        let light_p1 = bh_light.try_acquire(3, now);
        assert!(
            light_p1.is_some(),
            "light service should work despite heavy overflow"
        );
        assert_eq!(bh_light.available(), 2);

        let _light_q1 = bh_light.enqueue(2, now).unwrap();
        assert_eq!(bh_light.metrics().queue_depth, 1);

        // 3. Verify isolation in metrics
        assert_eq!(bh_heavy.metrics().total_rejected, 1);
        assert_eq!(bh_light.metrics().total_rejected, 0);
        assert!(bh_heavy.metrics().utilization >= 0.8); // 8/10 = 0.8
        assert!(bh_light.metrics().utilization > 0.5); // 3/5 = 0.6
    }

    #[test]
    fn conf_isolation_timeout_overflow_isolation() {
        // CONF-BULKHEAD-005: Timeout-based overflow doesn't affect other bulkheads
        let bh_fast = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "fast-timeout".into(),
            max_concurrent: 1,
            max_queue: 2,
            queue_timeout: Duration::from_millis(10),
            ..Default::default()
        }));

        let bh_slow = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "slow-timeout".into(),
            max_concurrent: 1,
            max_queue: 2,
            queue_timeout: Duration::from_secs(60),
            ..Default::default()
        }));

        let now = Time::from_millis(0);

        // 1. Create timeout condition in fast bulkhead
        let _fast_p = bh_fast.try_acquire(1, now).unwrap();
        let fast_q1 = bh_fast.enqueue(1, now).unwrap();

        // Create similar condition in slow bulkhead
        let _slow_p = bh_slow.try_acquire(1, now).unwrap();
        let slow_q1 = bh_slow.enqueue(1, now).unwrap();

        // 2. Advance time to trigger timeout in fast bulkhead only
        let later = Time::from_millis(50);
        bh_fast.process_queue(later);

        // 3. Verify fast bulkhead timed out
        let fast_result = bh_fast.check_entry(fast_q1, later);
        assert!(matches!(
            fast_result,
            Err(BulkheadError::QueueTimeout { .. })
        ));
        assert_eq!(bh_fast.metrics().total_timeout, 1);

        // 4. Verify slow bulkhead unaffected by fast timeout
        let slow_result = bh_slow.check_entry(slow_q1, later);
        assert!(
            matches!(slow_result, Ok(None)),
            "slow bulkhead should still be waiting"
        );
        assert_eq!(bh_slow.metrics().total_timeout, 0);
        assert_eq!(bh_slow.metrics().queue_depth, 1);

        // 5. Verify independent queue recovery
        let fast_can_enqueue = bh_fast.enqueue(1, later);
        assert!(
            fast_can_enqueue.is_ok(),
            "fast bulkhead should recover queue capacity after timeout"
        );

        let slow_metrics = bh_slow.metrics();
        assert_eq!(
            slow_metrics.queue_depth, 1,
            "slow bulkhead queue unchanged by fast timeout"
        );
    }

    #[test]
    fn bulkhead_saturation_queues_and_recovers_under_lab_runtime() {
        init_test("bulkhead_saturation_queues_and_recovers_under_lab_runtime");

        let config = TestConfig::new()
            .with_seed(0xB011_CE11)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);
        let bulkhead = Arc::new(Bulkhead::new(BulkheadPolicy {
            name: "lab-bulkhead".into(),
            max_concurrent: 1,
            max_queue: 1,
            queue_timeout: Duration::from_secs(1),
            ..Default::default()
        }));
        let checkpoints = Arc::new(Mutex::new(Vec::<Value>::new()));

        let (queue_entry_id, checkpoints, final_metrics, final_available) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");
                let holder_spawn_cx = cx.clone();
                let waiter_spawn_cx = cx.clone();

                let holder_bulkhead = Arc::clone(&bulkhead);
                let holder_checkpoints = Arc::clone(&checkpoints);
                let holder_task_cx = holder_spawn_cx.clone();
                let holder =
                    LabRuntimeTarget::spawn(&holder_spawn_cx, Budget::INFINITE, async move {
                        let permit = holder_bulkhead
                            .try_acquire(1, holder_task_cx.now())
                            .expect("holder should acquire the only permit");
                        let acquired = serde_json::json!({
                            "phase": "holder_acquired",
                            "available": holder_bulkhead.available(),
                        });
                        tracing::info!(event = %acquired, "bulkhead_lab_checkpoint");
                        holder_checkpoints.lock().unwrap().push(acquired);

                        yield_now().await;
                        yield_now().await;
                        permit.release();

                        let released = serde_json::json!({
                            "phase": "holder_released",
                            "available": holder_bulkhead.available(),
                            "time_ns": holder_task_cx.now().as_nanos(),
                        });
                        tracing::info!(event = %released, "bulkhead_lab_checkpoint");
                        holder_checkpoints.lock().unwrap().push(released);
                    });

                yield_now().await;

                let waiter_bulkhead = Arc::clone(&bulkhead);
                let waiter_checkpoints = Arc::clone(&checkpoints);
                let waiter_task_cx = waiter_spawn_cx.clone();
                let waiter =
                    LabRuntimeTarget::spawn(&waiter_spawn_cx, Budget::INFINITE, async move {
                        let entry_id = waiter_bulkhead
                            .enqueue(1, waiter_task_cx.now())
                            .expect("waiter should enqueue while saturated");
                        let enqueued = serde_json::json!({
                            "phase": "waiter_enqueued",
                            "entry_id": entry_id,
                            "queue_depth": waiter_bulkhead.metrics().queue_depth,
                        });
                        tracing::info!(event = %enqueued, "bulkhead_lab_checkpoint");
                        waiter_checkpoints.lock().unwrap().push(enqueued);

                        let permit = loop {
                            match waiter_bulkhead.check_entry(entry_id, waiter_task_cx.now()) {
                                Ok(Some(permit)) => break permit,
                                Ok(None) => yield_now().await,
                                other => panic!("waiter queue check failed: {other:?}"),
                            }
                        };

                        let granted = serde_json::json!({
                            "phase": "waiter_granted",
                            "entry_id": entry_id,
                            "available": waiter_bulkhead.available(),
                        });
                        tracing::info!(event = %granted, "bulkhead_lab_checkpoint");
                        waiter_checkpoints.lock().unwrap().push(granted);

                        permit.release();
                        let released = serde_json::json!({
                            "phase": "waiter_released",
                            "entry_id": entry_id,
                            "available": waiter_bulkhead.available(),
                        });
                        tracing::info!(event = %released, "bulkhead_lab_checkpoint");
                        waiter_checkpoints.lock().unwrap().push(released);
                        entry_id
                    });

                let holder_outcome = holder.await;
                crate::assert_with_log!(
                    matches!(holder_outcome, crate::types::Outcome::Ok(())),
                    "holder task completes successfully",
                    true,
                    matches!(holder_outcome, crate::types::Outcome::Ok(()))
                );

                let waiter_outcome = waiter.await;
                crate::assert_with_log!(
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_)),
                    "waiter task completes successfully",
                    true,
                    matches!(waiter_outcome, crate::types::Outcome::Ok(_))
                );
                let crate::types::Outcome::Ok(queue_entry_id) = waiter_outcome else {
                    panic!("waiter task should finish successfully");
                };

                (
                    queue_entry_id,
                    checkpoints.lock().unwrap().clone(),
                    bulkhead.metrics(),
                    bulkhead.available(),
                )
            });

        assert_eq!(queue_entry_id, 0);
        assert_eq!(final_metrics.active_permits, 0);
        assert_eq!(final_metrics.queue_depth, 0);
        assert_eq!(final_metrics.total_executed, 2);
        assert_eq!(final_metrics.total_queued, 1);
        assert_eq!(final_metrics.total_rejected, 0);
        assert_eq!(final_metrics.total_timeout, 0);
        assert_eq!(final_metrics.total_cancelled, 0);
        assert_eq!(final_available, 1);
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "holder_acquired"),
            "holder acquisition checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "waiter_enqueued"),
            "waiter enqueue checkpoint should be recorded"
        );
        assert!(
            checkpoints
                .iter()
                .any(|event| event["phase"] == "waiter_granted"),
            "waiter grant checkpoint should be recorded"
        );
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "bulkhead lab-runtime saturation test should leave runtime invariants clean: {violations:?}"
        );
    }

#[cfg(not(target_arch = "wasm32"))]
mod async_admission_tests {
    use super::*;
    use crate::cx::ChildRegionSpec;
    use crate::runtime::RuntimeBuilder;
    use crate::types::CancelKind;
    use std::future::{Future, poll_fn};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex, mpsc};
    use std::task::{Context, Poll, Wake, Waker};

    fn native<F, Fut>(workers: usize, scenario: F)
    where
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(workers)
            };
            let runtime = builder.build().unwrap();
            let completed = Arc::new(AtomicBool::new(false));
            let completion = Arc::clone(&completed);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("admitted bulkhead scenario");
                crate::time::timeout(cx.now(), Duration::from_secs(10), scenario(cx))
                    .await
                    .expect("bulkhead admission scenario watchdog");
                completion.store(true, Ordering::Release);
            }));
            assert!(completed.load(Ordering::Acquire));
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            done_tx.send(()).unwrap();
        });
        match done_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                runner.join().expect("native bulkhead admission scenario");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("native bulkhead admission exceeded watchdog");
            }
        }
    }

    fn limiter(timeout: Duration) -> Bulkhead {
        Bulkhead::new(BulkheadPolicy {
            max_concurrent: 1,
            max_queue: 4,
            queue_timeout: timeout,
            ..Default::default()
        })
    }

    async fn wait_parked(bulkhead: &Bulkhead, waiters: usize) {
        while bulkhead.changed.waiter_count() < waiters {
            yield_now().await;
        }
    }

    fn assert_empty(bulkhead: &Bulkhead, available: u32) {
        assert!(bulkhead.queue.read().is_empty());
        assert_eq!(bulkhead.pending_queue_count.load(Ordering::Acquire), 0);
        assert_eq!(bulkhead.changed.waiter_count(), 0);
        assert_eq!(bulkhead.available(), available);
    }

    #[test]
    fn immediate_admission_needs_no_timer_but_contended_wait_fails_closed() {
        let cx = Cx::for_testing();
        let bulkhead = limiter(Duration::from_secs(1));
        let mut context = Context::from_waker(Waker::noop());
        let mut immediate = Box::pin(bulkhead.acquire_async(&cx, 1));
        let permit = match immediate.as_mut().poll(&mut context) {
            Poll::Ready(Ok(permit)) => permit,
            other => panic!("immediate admission must succeed: {other:?}"),
        };
        drop(immediate);
        let mut waiting = Box::pin(bulkhead.acquire_async(&cx, 1));
        assert!(matches!(
            waiting.as_mut().poll(&mut context),
            Poll::Ready(Err(BulkheadAcquireError::TimerUnavailable))
        ));
        drop(waiting);
        assert_empty(&bulkhead, 0);
        drop(permit);

        cx.set_cancel_requested(true);
        let mut cancelled = Box::pin(bulkhead.acquire_async(&cx, 1));
        assert!(matches!(
            cancelled.as_mut().poll(&mut context),
            Poll::Ready(Err(BulkheadAcquireError::Cancelled(_)))
        ));
        drop(cancelled);
        assert_empty(&bulkhead, 1);
    }

    async fn fifo_release_scenario(cx: Cx) {
        let bulkhead = Arc::new(limiter(Duration::from_secs(30)));
        let held = bulkhead.try_acquire(1, cx.now()).unwrap();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let release = Arc::new(AtomicBool::new(false));
        let changed = Arc::new(Notify::new());

        let first_bulkhead = Arc::clone(&bulkhead);
        let first_order = Arc::clone(&order);
        let first_release = Arc::clone(&release);
        let first_changed = Arc::clone(&changed);
        let mut first = cx
            .spawn(move |owner| async move {
                let _permit = first_bulkhead.acquire_async(&owner, 1).await.unwrap();
                first_order.lock().unwrap().push(1);
                first_changed.notify_waiters();
                first_changed
                    .wait_until(|| first_release.load(Ordering::Acquire))
                    .await;
            })
            .unwrap();
        wait_parked(&bulkhead, 1).await;

        let second_bulkhead = Arc::clone(&bulkhead);
        let second_order = Arc::clone(&order);
        let mut second = cx
            .spawn(move |owner| async move {
                let _permit = second_bulkhead.acquire_async(&owner, 1).await.unwrap();
                second_order.lock().unwrap().push(2);
            })
            .unwrap();
        wait_parked(&bulkhead, 2).await;
        assert_eq!(bulkhead.metrics().queue_depth, 2);
        assert!(order.lock().unwrap().is_empty());

        // A release from another OS thread must wake the actually parked task.
        std::thread::scope(|scope| {
            scope.spawn(move || drop(held)).join().unwrap();
        });
        changed
            .wait_until(|| !order.lock().unwrap().is_empty())
            .await;
        assert_eq!(*order.lock().unwrap(), vec![1]);
        assert_eq!(bulkhead.available(), 0);
        release.store(true, Ordering::Release);
        changed.notify_waiters();
        first.join(&cx).await.unwrap();
        second.join(&cx).await.unwrap();
        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
        assert_empty(&bulkhead, 1);
    }

    #[test]
    fn native_async_admission_wakes_on_release_and_preserves_fifo() {
        for workers in [1, 2] {
            native(workers, fifo_release_scenario);
        }
    }

    #[test]
    fn native_async_admission_cancels_an_actually_parked_owner() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let bulkhead = Arc::new(limiter(Duration::from_secs(30)));
                let held = bulkhead.try_acquire(1, cx.now()).unwrap();
                let child_bulkhead = Arc::clone(&bulkhead);
                let child = cx
                    .spawn(move |owner| async move {
                        let result = child_bulkhead.acquire_async(&owner, 1).await;
                        assert!(matches!(
                            result,
                            Err(BulkheadAcquireError::Cancelled(reason))
                                if reason.kind == CancelKind::User
                        ));
                    })
                    .unwrap();
                wait_parked(&bulkhead, 1).await;
                assert_eq!(bulkhead.metrics().queue_depth, 1);
                let mut child = std::thread::spawn(move || {
                    child.abort();
                    child
                })
                .join()
                .unwrap();
                child.join(&cx).await.unwrap();
                assert_empty(&bulkhead, 0);
                drop(held);
                assert_empty(&bulkhead, 1);
            });
        }
    }

    #[test]
    fn native_async_drop_releases_pending_and_unclaimed_grants() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                for grant in [false, true] {
                    let bulkhead = limiter(Duration::from_secs(30));
                    let mut held = Some(bulkhead.try_acquire(1, cx.now()).unwrap());
                    let mut waiting = Box::pin(bulkhead.acquire_async(&cx, 1));
                    poll_fn(|task| {
                        assert!(waiting.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(bulkhead.changed.waiter_count(), 1);
                    if grant {
                        drop(held.take());
                        assert!(bulkhead.process_queue(cx.now()).is_some());
                        assert_eq!(bulkhead.pending_queue_count.load(Ordering::Acquire), 0);
                        assert_eq!(bulkhead.available(), 0);
                    }
                    drop(waiting);
                    assert_empty(&bulkhead, u32::from(grant));
                    drop(held);
                    assert_empty(&bulkhead, 1);
                }
            });
        }
    }

    #[test]
    fn native_async_admission_wakes_on_reset() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                let bulkhead = Arc::new(limiter(Duration::from_secs(30)));
                let held = bulkhead.try_acquire(1, cx.now()).unwrap();
                let child_bulkhead = Arc::clone(&bulkhead);
                let mut child = cx
                    .spawn(move |owner| async move {
                        assert!(matches!(
                            child_bulkhead.acquire_async(&owner, 1).await,
                            Err(BulkheadAcquireError::Admission(BulkheadError::Cancelled))
                        ));
                    })
                    .unwrap();
                wait_parked(&bulkhead, 1).await;
                bulkhead.reset();
                child.join(&cx).await.unwrap();
                assert_empty(&bulkhead, 1);
                drop(held);
                assert_empty(&bulkhead, 1);
            });
        }
    }

    #[test]
    fn native_async_queue_timeout_and_inherited_deadline_are_driven() {
        for workers in [1, 2] {
            native(workers, |cx| async move {
                for inherited in [false, true] {
                    let mut spec = ChildRegionSpec::inherit();
                    if inherited {
                        spec = spec.with_budget(
                            Budget::new().with_deadline(cx.now() + Duration::from_millis(250)),
                        );
                    }
                    let parent = cx.open_child_region(spec).await.unwrap();
                    let timeout = if inherited {
                        Duration::from_secs(30)
                    } else {
                        Duration::from_millis(250)
                    };
                    let bulkhead = Arc::new(limiter(timeout));
                    let held = bulkhead.try_acquire(1, cx.now()).unwrap();
                    let child_bulkhead = Arc::clone(&bulkhead);
                    let mut child = parent
                        .cx()
                        .spawn(move |owner| async move {
                            let result = child_bulkhead.acquire_async(&owner, 1).await;
                            if inherited {
                                assert!(matches!(
                                    result,
                                    Err(BulkheadAcquireError::Cancelled(reason))
                                        if reason.kind == CancelKind::Deadline
                                ));
                            } else {
                                assert!(matches!(
                                    result,
                                    Err(BulkheadAcquireError::Admission(
                                        BulkheadError::QueueTimeout { waited }
                                    )) if waited >= timeout
                                ));
                            }
                        })
                        .unwrap();
                    wait_parked(&bulkhead, 1).await;
                    child.join(&cx).await.unwrap();
                    assert_empty(&bulkhead, 0);
                    drop(held);
                    parent.close().await.unwrap();
                }
            });
        }
    }

    #[test]
    fn lab_async_follower_drives_abandoned_raw_fifo_deadline() {
        use crate::{LabConfig, LabRuntime};
        for seed in [17, 41, 93] {
            let mut lab = LabRuntime::new(LabConfig::new(seed).worker_count(2).max_steps(8192));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let (task, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async {
                    let cx = Cx::current().unwrap();
                    let bulkhead = Bulkhead::new(BulkheadPolicy {
                        max_concurrent: 2,
                        max_queue: 2,
                        queue_timeout: Duration::from_millis(100),
                        ..Default::default()
                    });
                    let started = cx.now();
                    let held = bulkhead.try_acquire(1, started).unwrap();
                    let abandoned = bulkhead.enqueue(2, started).unwrap();
                    crate::time::sleep(cx.now(), Duration::from_millis(50)).await;
                    let permit = bulkhead.acquire_async(&cx, 1).await.unwrap();
                    assert_eq!(cx.now(), started + Duration::from_millis(100));
                    assert_eq!(permit.weight(), 1);
                    bulkhead.cancel_entry(abandoned, cx.now());
                    drop(permit);
                    drop(held);
                    assert_empty(&bulkhead, 2);
                })
                .unwrap();
            lab.scheduler.lock().schedule(task, 0);
            let virtual_time = lab.run_with_auto_advance();
            let report = lab.run_until_quiescent_with_report();
            assert!(matches!(join.try_join(), Ok(Some(()))), "{virtual_time:?} {report:?}");
            assert!(lab.state.tasks_is_empty());
            assert!(lab.state.obligations_iter().all(|(_, obligation)| !obligation.is_pending()));
            assert!(report.lab_test_passed(), "{report:?}");
        }
    }

    struct PanicWake;
    impl Wake for PanicWake {
        fn wake(self: Arc<Self>) {
            panic!("bulkhead notification wake panic");
        }
    }

    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn notification_panic_cannot_interrupt_queue_owner_publication() {
        let bulkhead = limiter(Duration::from_secs(1));
        let mut hostile = Box::pin(bulkhead.changed.notified());
        let hostile_waker = Waker::from(Arc::new(PanicWake));
        assert!(
            hostile
                .as_mut()
                .poll(&mut Context::from_waker(&hostile_waker))
                .is_pending()
        );
        let counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let other_waker = Waker::from(Arc::clone(&counter));
        let mut other = Box::pin(bulkhead.changed.notified());
        assert!(
            other
                .as_mut()
                .poll(&mut Context::from_waker(&other_waker))
                .is_pending()
        );
        let queued = bulkhead.acquire_queued(1, Time::ZERO).unwrap();
        assert_eq!(counter.0.load(Ordering::Acquire), 1);
        assert_eq!(bulkhead.pending_queue_count.load(Ordering::Acquire), 1);
        drop(queued);
        drop(hostile);
        drop(other);
        assert_empty(&bulkhead, 1);
    }

    #[test]
    fn deadline_crossing_between_checkpoint_and_queue_clock_does_not_park() {
        use crate::time::{TimeSource, TimerDriver, TimerDriverHandle};
        use crate::types::{RegionId, TaskId};

        #[derive(Debug, Default)]
        struct CrossingClock {
            reads: AtomicUsize,
        }

        impl TimeSource for CrossingClock {
            fn now(&self) -> Time {
                // Initial checkpoint and enqueue use time zero. Advance on the
                // fourth sample, between the old loop checkpoint and its queue
                // clock read, then remain monotonic at the owner deadline.
                if self.reads.fetch_add(1, Ordering::SeqCst) < 3 {
                    Time::ZERO
                } else {
                    Time::from_millis(1)
                }
            }
        }

        let clock = Arc::new(CrossingClock::default());
        let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&clock))));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::new().with_deadline(Time::from_millis(1)),
            None,
            None,
            None,
            Some(driver),
            None,
        );
        let bulkhead = limiter(Duration::from_secs(30));
        let held = bulkhead.try_acquire(1, Time::ZERO).unwrap();
        clock.reads.store(0, Ordering::SeqCst);

        let mut waiting = Box::pin(bulkhead.acquire_async(&cx, 1));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(BulkheadAcquireError::Cancelled(reason)))
                if reason.kind == CancelKind::Deadline
        ));
        assert!(clock.reads.load(Ordering::SeqCst) >= 4);
        drop(waiting);
        assert_empty(&bulkhead, 0);
        drop(held);
        assert_empty(&bulkhead, 1);
    }
}
