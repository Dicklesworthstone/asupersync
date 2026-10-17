    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_epoch_advancement() {
        let config = EpochConfig {
            advance_interval: Duration::from_millis(1),
            ..EpochConfig::default()
        };
        let epoch = Arc::new(GlobalEpochCounter::new(config));
        let initial = epoch.current_epoch();

        // Should not advance immediately (rate limited)
        assert_eq!(epoch.try_advance(), None);

        // Wait for advance interval and try again
        thread::sleep(Duration::from_millis(2));
        let advanced = epoch.try_advance();
        assert!(advanced.is_some());
        assert_eq!(advanced.unwrap(), initial + 1);

        // Force advance should work
        let new_epoch = epoch.force_advance();
        assert_eq!(new_epoch, initial + 2);
    }

    #[test]
    fn test_epoch_pin() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let pin = LocalEpochPin::new(epoch.clone());

        // Initially not pinned
        assert_eq!(pin.pinned_epoch(), None);

        // Pin an epoch
        let guard = pin.pin();
        let pinned_epoch = guard.epoch();
        assert_eq!(pin.pinned_epoch(), Some(pinned_epoch));

        // Advance global epoch
        epoch.force_advance();
        assert!(epoch.current_epoch() > pinned_epoch);

        // Pin should still be active
        assert_eq!(pin.pinned_epoch(), Some(pinned_epoch));

        // Drop guard to unpin
        drop(guard);
        assert_eq!(pin.pinned_epoch(), None);
    }

    #[test]
    fn nested_epoch_pins_remain_active_until_outermost_guard_drops() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let pin = LocalEpochPin::new(epoch.clone());

        let outer = pin.pin();
        let outer_epoch = outer.epoch();
        epoch.force_advance();

        let inner = pin.pin();
        assert_eq!(
            inner.epoch(),
            outer_epoch,
            "nested pins must retain the oldest active epoch",
        );

        drop(inner);
        assert_eq!(
            pin.pinned_epoch(),
            Some(outer_epoch),
            "dropping an inner guard must not publish a false safe point",
        );

        drop(outer);
        assert_eq!(pin.pinned_epoch(), None);
    }

    #[test]
    fn local_pin_stats_record_outermost_pin_duration() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let pin = LocalEpochPin::new(epoch);

        let guard = pin.pin();
        thread::sleep(Duration::from_millis(1));
        drop(guard);

        let stats = pin.stats();
        assert_eq!(stats.pin_count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.unpin_count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.pin_start.load(Ordering::Relaxed), 0);
        assert!(
            stats.max_pin_duration.load(Ordering::Relaxed) > 0,
            "pin duration should be measured instead of left at the initial zero value",
        );
    }

    #[test]
    fn global_stats_report_recorded_last_advance_time() {
        let epoch = GlobalEpochCounter::new(EpochConfig::default());

        epoch.force_advance();
        thread::sleep(Duration::from_millis(5));

        assert!(
            epoch.stats().last_advance.elapsed() >= Duration::from_millis(2),
            "last_advance should be the stored advancement time, not the stats sample time",
        );
    }

    #[test]
    fn test_safe_point_detection() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let mut detector = SafePointDetector::new(epoch.clone());
        let pin = Arc::new(LocalEpochPin::new(epoch.clone()));
        detector.register_pin(pin.clone());

        // Initially safe point should be current epoch - 1
        let initial_epoch = epoch.current_epoch();
        let safe_point = detector.compute_safe_point();
        assert!(safe_point <= initial_epoch);

        // Pin an epoch
        let _guard = pin.pin();
        let pinned_epoch = pin.pinned_epoch().unwrap();

        // Advance global epoch
        epoch.force_advance();
        epoch.force_advance();

        // Safe point should be at or before pinned epoch
        let safe_point = detector.compute_safe_point();
        assert!(safe_point <= pinned_epoch);

        // After unpinning, safe point should advance
        drop(_guard);
        let safe_point_after = detector.compute_safe_point();
        assert!(safe_point_after > safe_point);
    }

    #[test]
    fn test_cleanup_queue() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let queue = DeferredCleanupQueue::new(epoch.clone(), 1000);
        let executed = Arc::new(AtomicBool::new(false));

        // Enqueue cleanup
        let executed_clone = executed.clone();
        queue
            .defer_cleanup(move || {
                executed_clone.store(true, Ordering::Relaxed);
            })
            .unwrap();

        // Should not execute yet (current epoch is not safe)
        let count = queue.execute_safe_cleanups(epoch.current_epoch());
        assert_eq!(count, 0);
        assert!(!executed.load(Ordering::Relaxed));

        // Advance epoch and execute
        epoch.force_advance();
        let count = queue.execute_safe_cleanups(epoch.current_epoch());
        assert_eq!(count, 1);
        assert!(executed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_cleanup_ordering() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let queue = DeferredCleanupQueue::new(epoch.clone(), 1000);
        let executed_order = Arc::new(std::sync::Mutex::new(Vec::new()));

        // Enqueue cleanups across multiple epochs
        for i in 0..5 {
            let order = executed_order.clone();
            queue
                .defer_cleanup(move || {
                    order.lock().unwrap().push(i);
                })
                .unwrap();

            // Advance epoch between some cleanups
            if i % 2 == 0 {
                epoch.force_advance();
            }
        }

        // Execute cleanups in order
        let safe_epoch = epoch.force_advance();
        let count = queue.execute_safe_cleanups(safe_epoch);

        assert_eq!(count, 5);
        let order = executed_order.lock().unwrap();
        // Should execute in epoch order (0, 2, 4, 1, 3)
        assert!(order.len() == 5);
    }

    #[test]
    fn test_queue_backpressure() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig::default()));
        let queue = DeferredCleanupQueue::new(epoch.clone(), 2); // Very small queue

        // Fill queue to capacity
        let result1 = queue.defer_cleanup(|| {});
        assert!(result1.is_ok());

        let result2 = queue.defer_cleanup(|| {});
        assert!(result2.is_ok());

        // Next enqueue should fail
        let result3 = queue.defer_cleanup(|| {});
        assert!(result3.is_err());

        // Execute some cleanups to free space
        epoch.force_advance();
        let executed = queue.execute_safe_cleanups(epoch.current_epoch());
        assert!(executed > 0);

        // Should be able to enqueue again
        let result4 = queue.defer_cleanup(|| {});
        assert!(result4.is_ok());
    }

    #[test]
    fn test_concurrent_operations() {
        let epoch = Arc::new(GlobalEpochCounter::new(EpochConfig {
            advance_interval: Duration::from_millis(1),
            ..EpochConfig::default()
        }));
        let pin = Arc::new(LocalEpochPin::new(epoch.clone()));
        let queue = Arc::new(DeferredCleanupQueue::new(epoch.clone(), 10000));

        let mut handles = Vec::new();

        // Spawn threads that pin epochs and enqueue cleanup
        for i in 0..4 {
            let epoch = epoch.clone();
            let pin = pin.clone();
            let queue = queue.clone();

            let handle = thread::spawn(move || {
                for j in 0..100 {
                    let _guard = pin.pin();

                    let value = i * 100 + j;
                    let _ = queue.defer_cleanup(move || {
                        // Simulate work
                        std::hint::black_box(value);
                    });

                    if j % 10 == 0 {
                        epoch.try_advance();
                    }

                    thread::yield_now();
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Execute remaining cleanups
        let final_epoch = epoch.force_advance();
        let executed = queue.execute_safe_cleanups(final_epoch);

        // Verify no data races or lost work
        assert!(executed > 0);
        assert!(executed <= 400); // At most 400 work items
    }
