    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::observability::metrics::NoOpMetrics;
    use crate::trace::TraceBufferHandle;
    use crate::util::OsEntropy;

    fn test_config() -> ShardedConfig {
        ShardedConfig {
            io_driver: None,
            timer_driver: None,
            logical_clock_mode: LogicalClockMode::Lamport,
            cancel_attribution: CancelAttributionConfig::default(),
            entropy_source: Arc::new(OsEntropy),
            blocking_pool: None,
            obligation_leak_response: ObligationLeakResponse::Log,
            leak_escalation: None,
            observability: None,
        }
    }

    #[test]
    fn sharded_state_creation() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        assert!(state.root_region().is_none());
        assert_eq!(state.current_time(), Time::ZERO);
        assert_eq!(state.leak_count(), 0);
    }

    #[test]
    fn root_region_set_once() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let first = RegionId::from_arena(ArenaIndex::new(1, 0));
        let second = RegionId::from_arena(ArenaIndex::new(2, 0));

        assert!(state.set_root_region(first));
        assert_eq!(state.root_region(), Some(first));
        assert!(!state.set_root_region(second));
        assert_eq!(state.root_region(), Some(first));
    }

    #[test]
    fn time_operations() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        state.set_time(Time::from_nanos(12345));
        assert_eq!(state.current_time(), Time::from_nanos(12345));
    }

    #[test]
    fn leak_count_increment() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        assert_eq!(state.increment_leak_count(), 1);
        assert_eq!(state.increment_leak_count(), 2);
        assert_eq!(state.leak_count(), 2);
    }

    #[test]
    fn tasks_only_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::tasks_only(&state);
        assert!(guard.tasks.is_some());
        assert!(guard.regions.is_none());
        assert!(guard.obligations.is_none());
    }

    #[test]
    fn for_task_completed_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_task_completed(&state);
        assert!(guard.tasks.is_some());
        assert!(guard.regions.is_some());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn regions_only_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::regions_only(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_none());
        assert!(guard.obligations.is_none());
    }

    #[test]
    fn obligations_only_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::obligations_only(&state);
        assert!(guard.obligations.is_some());
        assert!(guard.regions.is_none());
        assert!(guard.tasks.is_none());
    }

    #[test]
    fn for_cancel_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_cancel(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn for_obligation_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_obligation(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_none());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn for_obligation_resolve_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_obligation_resolve(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_some());
    }

    #[test]
    fn for_spawn_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::for_spawn(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_none());
    }

    #[test]
    fn all_guard() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let guard = ShardGuard::all(&state);
        assert!(guard.regions.is_some());
        assert!(guard.tasks.is_some());
        assert!(guard.obligations.is_some());
    }

    // ── Lock ordering enforcement tests ──────────────────────────────────

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_held_count_tracks_acquisitions() {
        // Verify held_count is 0 at start, increments on acquire, decrements on drop.
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_task_completed(&state);
            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_single_shard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::tasks_only(&state);
            assert_eq!(lock_order::held_count(), 1);
            assert_eq!(lock_order::held_labels(), vec!["A:Tasks"]);
        }
        assert_eq!(lock_order::held_count(), 0);

        {
            let _guard = ShardGuard::regions_only(&state);
            assert_eq!(lock_order::held_count(), 1);
            assert_eq!(lock_order::held_labels(), vec!["B:Regions"]);
        }
        assert_eq!(lock_order::held_count(), 0);

        {
            let _guard = ShardGuard::obligations_only(&state);
            assert_eq!(lock_order::held_count(), 1);
            assert_eq!(lock_order::held_labels(), vec!["C:Obligations"]);
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_spawn_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_spawn(&state);
            assert_eq!(lock_order::held_count(), 2);
            assert_eq!(lock_order::held_labels(), vec!["B:Regions", "A:Tasks"]);
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_cancel_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_cancel(&state);
            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_obligation_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_obligation(&state);
            assert_eq!(lock_order::held_count(), 2);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_obligation_resolve_guard_tracking() {
        assert_eq!(lock_order::held_count(), 0);

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _guard = ShardGuard::for_obligation_resolve(&state);
            assert_eq!(lock_order::held_count(), 3);
            assert_eq!(
                lock_order::held_labels(),
                vec!["B:Regions", "A:Tasks", "C:Obligations"]
            );
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    // ── Lock ordering violation tests (should_panic) ─────────────────────
    //
    // These tests verify that debug assertions catch out-of-order
    // lock acquisitions. Each test directly manipulates the lock_order
    // module to simulate a violation without needing two ShardedState
    // instances (which would introduce real deadlock risk).

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_tasks_before_regions() {
        // Holding Tasks (order 1) then acquiring Regions (order 0) is illegal.
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Regions); // ← panic
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_obligations_before_tasks() {
        // Holding Obligations (order 2) then acquiring Tasks (order 1) is illegal.
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);
        lock_order::before_lock(LockShard::Tasks); // ← panic
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_obligations_before_regions() {
        // Holding Obligations (order 2) then acquiring Regions (order 0) is illegal.
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);
        lock_order::before_lock(LockShard::Regions); // ← panic
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    #[should_panic(expected = "lock order violation")]
    fn lock_order_violation_duplicate_shard() {
        // Acquiring the same shard twice is also a violation (order not strictly increasing).
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Tasks); // ← panic (1 not < 1)
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_valid_full_sequence() {
        // Canonical order: Regions → Tasks → Obligations should succeed.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);

        assert_eq!(lock_order::held_count(), 3);
        assert_eq!(
            lock_order::held_labels(),
            vec!["B:Regions", "A:Tasks", "C:Obligations"]
        );

        // Clean up
        lock_order::unlock_n(3);
        assert_eq!(lock_order::held_count(), 0);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_unlock_then_reacquire() {
        // After releasing all locks, any shard can be acquired again.
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);
        assert_eq!(lock_order::held_count(), 1);

        lock_order::unlock_n(1);
        assert_eq!(lock_order::held_count(), 0);

        // Now Regions (lower order) is fine because nothing is held.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        assert_eq!(lock_order::held_count(), 1);
        assert_eq!(lock_order::held_labels(), vec!["B:Regions"]);

        lock_order::unlock_n(1);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_partial_sequence_regions_tasks() {
        // Regions → Tasks is a valid subsequence.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);

        assert_eq!(lock_order::held_count(), 2);
        lock_order::unlock_n(2);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_partial_sequence_regions_obligations() {
        // Regions → Obligations (skipping Tasks) is valid.
        lock_order::before_lock(LockShard::Regions);
        lock_order::after_lock(LockShard::Regions);
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);

        assert_eq!(lock_order::held_count(), 2);
        lock_order::unlock_n(2);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn lock_order_partial_sequence_tasks_obligations() {
        // Tasks → Obligations is valid.
        lock_order::before_lock(LockShard::Tasks);
        lock_order::after_lock(LockShard::Tasks);
        lock_order::before_lock(LockShard::Obligations);
        lock_order::after_lock(LockShard::Obligations);

        assert_eq!(lock_order::held_count(), 2);
        lock_order::unlock_n(2);
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn lock_rank(shard: LockShard) -> usize {
        match shard {
            LockShard::Regions => 0,
            LockShard::Tasks => 1,
            LockShard::Obligations => 2,
        }
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn canonicalize_labels(mut labels: Vec<&'static str>) -> Vec<&'static str> {
        labels.sort_by_key(|label| match *label {
            "B:Regions" => 0,
            "A:Tasks" => 1,
            "C:Obligations" => 2,
            other => panic!("unexpected shard label: {other}"),
        });
        labels.dedup();
        labels
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn capture_labels(guard: ShardGuard<'_>) -> Vec<&'static str> {
        let labels = lock_order::held_labels();
        drop(guard);
        assert_eq!(lock_order::held_count(), 0);
        labels
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn metamorphic_lock_order_accepts_only_canonical_permutations() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let sequences = [
            vec![LockShard::Regions],
            vec![LockShard::Tasks],
            vec![LockShard::Obligations],
            vec![LockShard::Regions, LockShard::Tasks],
            vec![LockShard::Tasks, LockShard::Regions],
            vec![LockShard::Regions, LockShard::Obligations],
            vec![LockShard::Obligations, LockShard::Regions],
            vec![LockShard::Tasks, LockShard::Obligations],
            vec![LockShard::Obligations, LockShard::Tasks],
            vec![LockShard::Regions, LockShard::Tasks, LockShard::Obligations],
            vec![LockShard::Regions, LockShard::Obligations, LockShard::Tasks],
            vec![LockShard::Tasks, LockShard::Regions, LockShard::Obligations],
            vec![LockShard::Tasks, LockShard::Obligations, LockShard::Regions],
            vec![LockShard::Obligations, LockShard::Regions, LockShard::Tasks],
            vec![LockShard::Obligations, LockShard::Tasks, LockShard::Regions],
        ];

        for sequence in sequences {
            let expected_ok = sequence
                .windows(2)
                .all(|pair| lock_rank(pair[0]) < lock_rank(pair[1]));
            let expected_labels: Vec<_> = sequence.iter().map(|shard| shard.label()).collect();

            let result = catch_unwind(AssertUnwindSafe(|| {
                for shard in &sequence {
                    lock_order::before_lock(*shard);
                    lock_order::after_lock(*shard);
                }
                let labels = lock_order::held_labels();
                lock_order::unlock_n(sequence.len());
                labels
            }));

            assert_eq!(
                result.is_ok(),
                expected_ok,
                "canonical lock-order expectation disagreed for {:?}",
                expected_labels
            );

            if let Ok(labels) = result {
                assert_eq!(labels, expected_labels);
            }

            let leaked = lock_order::held_count();
            if leaked > 0 {
                lock_order::unlock_n(leaked);
            }
        }
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn metamorphic_guard_unions_match_canonical_supersets() {
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        let regions = capture_labels(ShardGuard::regions_only(&state));
        let tasks = capture_labels(ShardGuard::tasks_only(&state));
        let obligations = capture_labels(ShardGuard::obligations_only(&state));

        let spawn_union = canonicalize_labels([regions.clone(), tasks.clone()].concat());
        let obligation_union = canonicalize_labels([regions.clone(), obligations.clone()].concat());
        let full_union = canonicalize_labels([regions, tasks, obligations].concat());

        assert_eq!(capture_labels(ShardGuard::for_spawn(&state)), spawn_union);
        assert_eq!(
            capture_labels(ShardGuard::for_obligation(&state)),
            obligation_union
        );
        assert_eq!(capture_labels(ShardGuard::for_cancel(&state)), full_union);
        assert_eq!(
            capture_labels(ShardGuard::for_task_completed(&state)),
            full_union
        );
        assert_eq!(
            capture_labels(ShardGuard::for_obligation_resolve(&state)),
            full_union
        );
        assert_eq!(capture_labels(ShardGuard::all(&state)), full_union);
    }

    // ── Concurrent guard tests ───────────────────────────────────────────

    #[test]
    fn concurrent_guard_access_no_deadlock() {
        // Multiple threads acquire ShardGuards simultaneously.
        // This verifies no deadlock occurs when using the guard API correctly.
        use std::sync::Barrier;
        use std::thread;

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = Arc::new(ShardedState::new(trace, metrics, test_config()));
        let barrier = Arc::new(Barrier::new(4));
        let iterations = 100;

        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..iterations {
                        // Each thread cycles through different guard types.
                        match thread_id % 4 {
                            0 => {
                                let _g = ShardGuard::tasks_only(&state);
                            }
                            1 => {
                                let _g = ShardGuard::for_spawn(&state);
                            }
                            2 => {
                                let _g = ShardGuard::for_obligation(&state);
                            }
                            3 => {
                                let _g = ShardGuard::for_task_completed(&state);
                            }
                            _ => unreachable!(),
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    #[test]
    fn concurrent_mixed_guards_no_deadlock() {
        // All threads use ALL guard types in rotation.
        // This is a stronger test than the above because each thread
        // exercises all ordering patterns.
        use std::sync::Barrier;
        use std::thread;

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = Arc::new(ShardedState::new(trace, metrics, test_config()));
        let barrier = Arc::new(Barrier::new(4));
        let iterations = 50;

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for i in 0..iterations {
                        match i % 8 {
                            0 => {
                                let _g = ShardGuard::tasks_only(&state);
                            }
                            1 => {
                                let _g = ShardGuard::regions_only(&state);
                            }
                            2 => {
                                let _g = ShardGuard::obligations_only(&state);
                            }
                            3 => {
                                let _g = ShardGuard::for_spawn(&state);
                            }
                            4 => {
                                let _g = ShardGuard::for_cancel(&state);
                            }
                            5 => {
                                let _g = ShardGuard::for_obligation(&state);
                            }
                            6 => {
                                let _g = ShardGuard::for_obligation_resolve(&state);
                            }
                            7 => {
                                let _g = ShardGuard::all(&state);
                            }
                            _ => unreachable!(),
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[test]
    fn guard_drop_cleans_up_lock_order_state() {
        // Verify that dropping a guard properly cleans up thread-local state
        // so subsequent guards don't see stale entries.
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        assert_eq!(lock_order::held_count(), 0);

        {
            let _g = ShardGuard::all(&state);
            assert_eq!(lock_order::held_count(), 3);
        }
        assert_eq!(lock_order::held_count(), 0);

        // After drop, we can acquire in any order (starting fresh).
        {
            let _g = ShardGuard::obligations_only(&state);
            assert_eq!(lock_order::held_count(), 1);
        }
        assert_eq!(lock_order::held_count(), 0);

        {
            let _g = ShardGuard::regions_only(&state);
            assert_eq!(lock_order::held_count(), 1);
        }
        assert_eq!(lock_order::held_count(), 0);
    }

    // ── Audit regression tests ───────────────────────────────────────────

    #[test]
    fn root_region_encoding_roundtrip_zero() {
        // (0, 0) is a valid ArenaIndex and must roundtrip correctly.
        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        let encoded = encode_root_region(region);
        assert_ne!(encoded, ROOT_REGION_NONE, "encoded must differ from NONE");
        let decoded = decode_root_region(encoded);
        assert_eq!(decoded, Some(region));
    }

    #[test]
    fn root_region_encoding_roundtrip_large() {
        // Large but valid (index, generation) must roundtrip.
        let region = RegionId::from_arena(ArenaIndex::new(u32::MAX, u32::MAX - 1));
        let encoded = encode_root_region(region);
        let decoded = decode_root_region(encoded);
        assert_eq!(decoded, Some(region));
    }

    #[test]
    #[should_panic(expected = "region ID too large")]
    fn root_region_encoding_max_panics() {
        // (u32::MAX, u32::MAX) encodes to u64::MAX and must be rejected.
        let region = RegionId::from_arena(ArenaIndex::new(u32::MAX, u32::MAX));
        let _ = encode_root_region(region);
    }

    #[test]
    fn guard_drop_releases_in_reverse_order() {
        // Verify that after dropping a full guard, we can immediately
        // acquire any single shard (obligations first, which is the
        // "last" in lock order and would fail if drop leaked state).
        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn MetricsProvider> = Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        {
            let _g = ShardGuard::all(&state);
        }

        // If drop didn't properly release, this would deadlock.
        let g = ShardGuard::obligations_only(&state);
        assert!(g.obligations.is_some());
    }

    #[cfg(feature = "lock-metrics")]
    #[test]
    fn lock_ordering_validation_with_lock_metrics_feature() {
        // This test verifies that lock ordering validation is enabled in production
        // builds when the lock-metrics feature is enabled.
        use crate::observability::metrics::NoOpMetrics;
        use crate::trace::TraceBufferHandle;
        use std::sync::Arc;

        let trace = TraceBufferHandle::new(1024);
        let metrics: Arc<dyn crate::observability::metrics::MetricsProvider> =
            Arc::new(NoOpMetrics);
        let state = ShardedState::new(trace, metrics, test_config());

        // Valid order: Regions -> Tasks -> Obligations
        let _regions_guard = ShardGuard::regions_only(&state);
        drop(_regions_guard);

        let _spawn_guard = ShardGuard::for_spawn(&state);
        drop(_spawn_guard);

        let _full_guard = ShardGuard::all(&state);
        drop(_full_guard);

        // This test demonstrates that lock ordering validation is active
        // in production builds with the lock-metrics feature
    }
