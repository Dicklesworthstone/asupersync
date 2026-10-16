    use super::*;
    #[cfg(feature = "lock-metrics")]
    use crate::sync::lock_ordering;
    use std::sync::Arc;
    #[cfg(feature = "lock-metrics")]
    use std::thread;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn basic_lock_unlock() {
        init_test("basic_lock_unlock");
        let m = ContendedMutex::new("unknown", 42);
        {
            let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            crate::assert_with_log!(*guard == 42, "value", 42, *guard);
            drop(guard);
        }
        crate::test_complete!("basic_lock_unlock");
    }

    #[test]
    fn mutate_through_guard() {
        init_test("mutate_through_guard");
        let m = ContendedMutex::new("unknown", 0);
        {
            let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = 99;
        }
        let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::assert_with_log!(*guard == 99, "mutated value", 99, *guard);
        drop(guard);
        crate::test_complete!("mutate_through_guard");
    }

    #[test]
    fn try_lock_succeeds_when_free() {
        init_test("try_lock_succeeds_when_free");
        let m = ContendedMutex::new("unknown", 42);
        let guard = m.try_lock().expect("should succeed");
        crate::assert_with_log!(*guard == 42, "try_lock value", 42, *guard);
        drop(guard);
        crate::test_complete!("try_lock_succeeds_when_free");
    }

    #[test]
    fn try_lock_fails_when_held() {
        init_test("try_lock_fails_when_held");
        let m = ContendedMutex::new("unknown", 42);
        let _guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_err = m.try_lock().is_err();
        crate::assert_with_log!(is_err, "try_lock fails", true, is_err);
        crate::test_complete!("try_lock_fails_when_held");
    }

    #[test]
    fn snapshot_returns_name() {
        init_test("snapshot_returns_name");
        let m = ContendedMutex::new("unknown", 0);
        let snap = m.snapshot();
        crate::assert_with_log!(snap.name == "unknown", "name", "unknown", snap.name);
        crate::test_complete!("snapshot_returns_name");
    }

    #[test]
    fn name_accessor() {
        init_test("name_accessor");
        let m = ContendedMutex::new("tasks", 0);
        crate::assert_with_log!(m.name() == "tasks", "name", "tasks", m.name());
        crate::test_complete!("name_accessor");
    }

    #[test]
    fn reset_metrics_no_panic() {
        init_test("reset_metrics_no_panic");
        let m = ContendedMutex::new("unknown", 0);
        {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        m.reset_metrics();
        let snap = m.snapshot();
        // After reset, metrics should be zero (when feature enabled) or always zero
        crate::assert_with_log!(
            snap.acquisitions == 0,
            "acquisitions after reset",
            0u64,
            snap.acquisitions
        );
        crate::test_complete!("reset_metrics_no_panic");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_track_acquisitions() {
        init_test("metrics_track_acquisitions");
        let m = ContendedMutex::new("unknown", 0);
        for _ in 0..10 {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.acquisitions == 10,
            "acquisitions",
            10u64,
            snap.acquisitions
        );
        crate::test_complete!("metrics_track_acquisitions");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_track_hold_time() {
        init_test("metrics_track_hold_time");
        let m = ContendedMutex::new("unknown", 0);
        {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let snap = m.snapshot();
        // Hold time should be at least 4ms (allowing for timing variance)
        crate::assert_with_log!(
            snap.hold_ns >= 4_000_000,
            "hold_ns >= 4ms",
            true,
            snap.hold_ns >= 4_000_000
        );
        crate::assert_with_log!(
            snap.max_hold_ns >= 4_000_000,
            "max_hold_ns >= 4ms",
            true,
            snap.max_hold_ns >= 4_000_000
        );
        crate::test_complete!("metrics_track_hold_time");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_track_contention() {
        init_test("metrics_track_contention");
        let m = Arc::new(ContendedMutex::new("unknown", 0));

        // Hold the lock while another thread tries to acquire
        let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let m2 = Arc::clone(&m);
        let handle = thread::spawn(move || {
            let _g = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        });

        // Give the other thread time to contend
        thread::sleep(std::time::Duration::from_millis(10));
        drop(guard);
        handle.join().expect("thread panicked");

        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.contentions >= 1,
            "contentions >= 1",
            true,
            snap.contentions >= 1
        );
        crate::assert_with_log!(snap.wait_ns > 0, "wait_ns > 0", true, snap.wait_ns > 0);
        crate::test_complete!("metrics_track_contention");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn reset_clears_all_metrics() {
        init_test("reset_clears_all_metrics");
        let m = ContendedMutex::new("unknown", 0);
        {
            let _g = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let before = m.snapshot();
        crate::assert_with_log!(
            before.acquisitions == 1,
            "before reset",
            1u64,
            before.acquisitions
        );

        m.reset_metrics();
        let after = m.snapshot();
        crate::assert_with_log!(
            after.acquisitions == 0,
            "after reset acquisitions",
            0u64,
            after.acquisitions
        );
        crate::assert_with_log!(
            after.hold_ns == 0,
            "after reset hold_ns",
            0u64,
            after.hold_ns
        );
        crate::test_complete!("reset_clears_all_metrics");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn poisoned_lock_does_not_count_as_contention() {
        init_test("poisoned_lock_does_not_count_as_contention");
        let m = Arc::new(ContendedMutex::new("unknown", 0u8));
        let m2 = Arc::clone(&m);

        let poisoner = thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional poison");
        });
        let _ = poisoner.join();

        let poison_err = m.lock().expect_err("lock should be poisoned");
        drop(poison_err.into_inner());

        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.contentions == 0,
            "poison is not contention",
            0u64,
            snap.contentions
        );
        crate::test_complete!("poisoned_lock_does_not_count_as_contention");
    }

    // Covers both `mod inner` configs: run under `cargo test` (no-metrics arm,
    // check active via debug_assertions) and `cargo test --features lock-metrics`
    // (lock-metrics arm). Gated so it is only compiled where the ordering check
    // and clear_held_locks exist (br-asupersync-czdhfs).
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn try_lock_order_violation_does_not_poison_lower_mutex() {
        use crate::sync::lock_ordering;
        init_test("try_lock_order_violation_does_not_poison_lower_mutex");
        lock_ordering::clear_held_locks();
        let high = ContendedMutex::new("tasks", 100u32); // Tasks rank (higher)
        let low = ContendedMutex::new("regions_table", 7u32); // Regions rank (lower)
        let high_guard = high.lock().expect("acquire higher rank");

        // Holding Tasks and try_lock-ing Regions inverts the hierarchy, raising
        // ASUP-E205. The raw `low` guard must be dropped cleanly (not mid-unwind)
        // before the diagnostic is re-raised.
        let inverted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = low.try_lock();
        }));
        assert!(
            inverted.is_err(),
            "inverted try_lock must raise the lock-order diagnostic"
        );

        // Release the higher rank + reset held tracking; the lower mutex must
        // still lock with unchanged data — proving the order panic did NOT poison
        // it (a poisoning drop would leave `try_lock` returning Poisoned).
        drop(high_guard);
        lock_ordering::clear_held_locks();
        match low.try_lock() {
            Ok(guard) => assert_eq!(*guard, 7u32, "lower mutex data unchanged"),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                panic!("lower mutex was poisoned by the lock-order panic")
            }
            Err(std::sync::TryLockError::WouldBlock) => panic!("unexpected WouldBlock"),
        }
        lock_ordering::clear_held_locks();
        crate::test_complete!("try_lock_order_violation_does_not_poison_lower_mutex");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn poisoned_ranked_lock_release_clears_lock_order_state() {
        init_test("poisoned_ranked_lock_release_clears_lock_order_state");
        lock_ordering::clear_held_locks();

        let m = Arc::new(ContendedMutex::new("tasks", 0u8));
        let m2 = Arc::clone(&m);

        let poisoner = thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("intentional poison");
        });
        let _ = poisoner.join();

        let poison_err = m.lock().expect_err("lock should be poisoned");
        let guard = poison_err.into_inner();

        let held_locks = lock_ordering::current_held_locks();
        crate::assert_with_log!(
            held_locks
                .get(&lock_ordering::LockRank::Tasks)
                .map_or(0, Vec::len)
                == 1,
            "poisoned guard acquire is tracked",
            1usize,
            held_locks
                .get(&lock_ordering::LockRank::Tasks)
                .map_or(0, Vec::len)
        );

        drop(guard);

        crate::assert_with_log!(
            lock_ordering::current_held_locks().is_empty(),
            "poisoned guard drop clears held locks",
            true,
            lock_ordering::current_held_locks().is_empty()
        );
        crate::assert_with_log!(
            lock_ordering::current_held_ranks().is_empty(),
            "poisoned guard drop clears held ranks",
            true,
            lock_ordering::current_held_ranks().is_empty()
        );
        crate::test_complete!("poisoned_ranked_lock_release_clears_lock_order_state");
    }

    // =========================================================================
    // Wave 33: Data-type trait coverage
    // =========================================================================

    #[test]
    fn lock_metrics_snapshot_debug_clone_default() {
        let snap = LockMetricsSnapshot::default();
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("LockMetricsSnapshot"));
        assert_eq!(snap.acquisitions, 0);
        assert_eq!(snap.contentions, 0);
        assert_eq!(snap.wait_ns, 0);
        assert_eq!(snap.hold_ns, 0);
        assert_eq!(snap.max_wait_ns, 0);
        assert_eq!(snap.max_hold_ns, 0);
        assert_eq!(snap.wait_percentile_sample_count, 0);
        assert_eq!(snap.p95_wait_ns, 0);
        assert_eq!(snap.p999_wait_ns, 0);
        assert_eq!(snap.hold_percentile_sample_count, 0);
        assert_eq!(snap.p95_hold_ns, 0);
        assert_eq!(snap.p999_hold_ns, 0);
        let cloned = snap.clone();
        assert_eq!(cloned.name, snap.name);
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_snapshot_reports_tail_latencies() {
        init_test("metrics_snapshot_reports_tail_latencies");
        let m = ContendedMutex::new("tasks", 0u32);

        for _ in 0..4 {
            let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard += 1;
        }

        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.instrumentation_mode == "opt_in_lock_metrics",
            "instrumentation mode",
            "opt_in_lock_metrics",
            snap.instrumentation_mode
        );
        crate::assert_with_log!(
            snap.acquisitions == 4,
            "acquisitions",
            4u64,
            snap.acquisitions
        );
        crate::assert_with_log!(
            snap.p95_wait_ns <= snap.max_wait_ns,
            "p95 wait <= max wait",
            true,
            snap.p95_wait_ns <= snap.max_wait_ns
        );
        crate::assert_with_log!(
            snap.p999_wait_ns <= snap.max_wait_ns,
            "p999 wait <= max wait",
            true,
            snap.p999_wait_ns <= snap.max_wait_ns
        );
        crate::assert_with_log!(
            snap.p95_hold_ns <= snap.max_hold_ns,
            "p95 hold <= max hold",
            true,
            snap.p95_hold_ns <= snap.max_hold_ns
        );
        crate::assert_with_log!(
            snap.p999_hold_ns <= snap.max_hold_ns,
            "p999 hold <= max hold",
            true,
            snap.p999_hold_ns <= snap.max_hold_ns
        );
        crate::test_complete!("metrics_snapshot_reports_tail_latencies");
    }

    /// Regression for uqm6ex: every snapshot must observe a coherent
    /// `p95 <= p999 <= max` tuple for both the wait and hold domains, even
    /// while recorders and resets run concurrently. Before the fix, snapshot()
    /// cloned each population separately per percentile and read the max
    /// outside the sample lock, so an interleaved record could yield
    /// `p95 > p999` and a torn reset could zero the max while a larger sample
    /// survived (`p999 > max`).
    #[cfg(feature = "lock-metrics")]
    #[test]
    fn metrics_snapshot_and_reset_coherent_under_concurrency() {
        use std::sync::atomic::{AtomicBool, Ordering as AtOrd};

        init_test("metrics_snapshot_and_reset_coherent_under_concurrency");
        let m = Arc::new(ContendedMutex::new("tasks", 0u64));
        let stop = Arc::new(AtomicBool::new(false));

        // Four recorders hammer the lock: each acquire records a wait sample and
        // each guard drop records a hold sample.
        let mut recorders = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&m);
            let stop = Arc::clone(&stop);
            recorders.push(thread::spawn(move || {
                while !stop.load(AtOrd::Relaxed) {
                    let mut guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    *guard = guard.wrapping_add(1);
                    drop(guard);
                }
            }));
        }

        // A resetter periodically clears the metrics, exercising the store+clear
        // atomicity of reset() against the recorders and the snapshotter.
        let resetter = {
            let m = Arc::clone(&m);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut i = 0u32;
                while !stop.load(AtOrd::Relaxed) {
                    i = i.wrapping_add(1);
                    if i.is_multiple_of(64) {
                        m.reset_metrics();
                    }
                    std::hint::spin_loop();
                }
            })
        };

        // Snapshot repeatedly and assert coherence on every read.
        for _ in 0..2000 {
            let snap = m.snapshot();
            crate::assert_with_log!(
                snap.p95_wait_ns <= snap.p999_wait_ns,
                "p95_wait <= p999_wait under concurrency",
                true,
                snap.p95_wait_ns <= snap.p999_wait_ns
            );
            crate::assert_with_log!(
                snap.p999_wait_ns <= snap.max_wait_ns,
                "p999_wait <= max_wait under concurrency",
                true,
                snap.p999_wait_ns <= snap.max_wait_ns
            );
            crate::assert_with_log!(
                snap.p95_hold_ns <= snap.p999_hold_ns,
                "p95_hold <= p999_hold under concurrency",
                true,
                snap.p95_hold_ns <= snap.p999_hold_ns
            );
            crate::assert_with_log!(
                snap.p999_hold_ns <= snap.max_hold_ns,
                "p999_hold <= max_hold under concurrency",
                true,
                snap.p999_hold_ns <= snap.max_hold_ns
            );
        }

        stop.store(true, AtOrd::Relaxed);
        for h in recorders {
            let _ = h.join();
        }
        let _ = resetter.join();

        // Linearizable reset: with recorders quiesced, a final reset zeroes
        // every counter and clears both sample populations coherently.
        m.reset_metrics();
        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.acquisitions == 0,
            "reset zeroes acquisitions",
            0u64,
            snap.acquisitions
        );
        crate::assert_with_log!(
            snap.max_wait_ns == 0,
            "reset zeroes max_wait_ns",
            0u64,
            snap.max_wait_ns
        );
        crate::assert_with_log!(
            snap.max_hold_ns == 0,
            "reset zeroes max_hold_ns",
            0u64,
            snap.max_hold_ns
        );
        crate::assert_with_log!(
            snap.p999_wait_ns == 0,
            "reset clears wait samples",
            0u64,
            snap.p999_wait_ns
        );
        crate::assert_with_log!(
            snap.p999_hold_ns == 0,
            "reset clears hold samples",
            0u64,
            snap.p999_hold_ns
        );
        crate::test_complete!("metrics_snapshot_and_reset_coherent_under_concurrency");
    }

    #[test]
    fn contended_mutex_debug() {
        let m = ContendedMutex::new("unknown", 42_i32);
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ContendedMutex"));
    }

    #[test]
    fn contended_mutex_guard_debug() {
        let m = ContendedMutex::new("unknown", 42_i32);
        let guard = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("ContendedMutexGuard"));
        drop(guard);
    }

    #[test]
    fn try_lock_returns_poisoned_after_panic() {
        init_test("try_lock_returns_poisoned_after_panic");
        let m = Arc::new(ContendedMutex::new("unknown", 7u32));
        let m2 = Arc::clone(&m);
        let poisoner = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("deliberate poison");
        });
        let _ = poisoner.join();

        let result = m.try_lock();
        let is_poisoned = matches!(result, Err(std::sync::TryLockError::Poisoned(_)));
        crate::assert_with_log!(is_poisoned, "try_lock returns Poisoned", true, is_poisoned);

        // Recover data through the poison error.
        if let Err(std::sync::TryLockError::Poisoned(pe)) = m.try_lock() {
            let guard = pe.into_inner();
            crate::assert_with_log!(*guard == 7, "data preserved", 7u32, *guard);
        }
        crate::test_complete!("try_lock_returns_poisoned_after_panic");
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn hold_time_recorded_on_panic_in_critical_section() {
        init_test("hold_time_recorded_on_panic_in_critical_section");
        let m = Arc::new(ContendedMutex::new("unknown", 0u32));
        let m2 = Arc::clone(&m);

        let handle = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::thread::sleep(std::time::Duration::from_millis(5));
            panic!("panic while holding guard");
        });
        let _ = handle.join();

        // Guard::drop should have recorded hold time even though thread panicked.
        let snap = m.snapshot();
        crate::assert_with_log!(
            snap.hold_ns >= 4_000_000,
            "hold_ns recorded despite panic",
            true,
            snap.hold_ns >= 4_000_000
        );
        crate::test_complete!("hold_time_recorded_on_panic_in_critical_section");
    }
