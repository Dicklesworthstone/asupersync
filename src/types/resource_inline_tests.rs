    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn pool_allocate_deallocate() {
        let config = PoolConfig::new(64, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config);
        let buffer = pool.allocate().expect("expected allocation");
        assert_eq!(buffer.len(), 64);
        pool.deallocate(buffer);
        assert_eq!(pool.stats().current_usage, 0);
    }

    #[test]
    fn pool_exhaustion() {
        let config = PoolConfig::new(32, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config);
        let _ = pool.allocate().expect("first allocation");
        assert!(matches!(pool.allocate(), Err(PoolExhausted)));
    }

    #[test]
    fn pool_growth() {
        let config = PoolConfig::new(16, 0, 2, true, 2);
        let mut pool = SymbolPool::new(config);
        let _ = pool.allocate().expect("allocation after growth");
        assert_eq!(pool.stats().growth_events, 1);
        assert_eq!(pool.stats().pool_misses, 1);
    }

    #[test]
    fn pool_no_growth_when_disabled() {
        let config = PoolConfig::new(16, 0, 2, false, 2);
        let mut pool = SymbolPool::new(config);
        assert!(matches!(pool.allocate(), Err(PoolExhausted)));
    }

    #[test]
    fn pool_max_size_respected() {
        let config = PoolConfig::new(16, 1, 1, true, 1);
        let mut pool = SymbolPool::new(config);
        let _ = pool.allocate().expect("first allocation");
        assert!(matches!(pool.allocate(), Err(PoolExhausted)));
    }

    #[test]
    fn pool_stats_tracking() {
        let config = PoolConfig::new(8, 2, 2, false, 0);
        let mut pool = SymbolPool::new(config);
        let a = pool.allocate().expect("alloc a");
        let b = pool.allocate().expect("alloc b");
        pool.deallocate(a);
        pool.deallocate(b);
        assert_eq!(pool.stats().allocations, 2);
        assert_eq!(pool.stats().deallocations, 2);
        assert_eq!(pool.stats().pool_hits, 2);
    }

    #[test]
    fn pool_deallocate_rejects_foreign_sized_buffers_without_mutating_state() {
        let config = PoolConfig::new(8, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config);
        let valid = pool.allocate().expect("alloc valid");

        for invalid_len in [4_u16, 16_u16] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                pool.deallocate(SymbolBuffer::new(invalid_len));
            }));
            assert!(
                result.is_err(),
                "invalid buffer length {invalid_len} must panic"
            );
            assert_eq!(pool.stats().deallocations, 0);
            assert_eq!(pool.stats().current_usage, 1);
            assert_eq!(pool.free_count(), 0);
        }

        pool.deallocate(valid);
        assert_eq!(pool.stats().deallocations, 1);
        assert_eq!(pool.stats().current_usage, 0);
        assert_eq!(pool.free_count(), 1);
    }

    #[test]
    fn pool_deallocate_rejects_unchecked_or_cross_pool_buffers_without_mutating_state() {
        let config = PoolConfig::new(8, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config.clone());
        let valid = pool.allocate().expect("alloc valid");
        let mut other_pool = SymbolPool::new(config);
        let foreign = other_pool.allocate().expect("foreign alloc");

        for invalid in [SymbolBuffer::new(8), foreign] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                pool.deallocate(invalid);
            }));
            assert!(result.is_err(), "invalid buffer return must panic");
            assert_eq!(pool.stats().deallocations, 0);
            assert_eq!(pool.stats().current_usage, 1);
            assert_eq!(pool.free_count(), 0);
        }

        pool.deallocate(valid);
        assert_eq!(pool.stats().deallocations, 1);
        assert_eq!(pool.stats().current_usage, 0);
        assert_eq!(pool.free_count(), 1);
        assert_eq!(other_pool.stats().current_usage, 1);
        assert_eq!(other_pool.free_count(), 0);
    }

    #[test]
    fn pool_shrink_and_warm() {
        let config = PoolConfig::new(8, 1, 4, true, 1);
        let mut pool = SymbolPool::new(config);
        pool.warm(4);
        assert_eq!(pool.free_count(), 4);
        let _ = pool.allocate().expect("allocation");
        pool.shrink_to_fit();
        assert!(pool.free_count() <= 1);
    }

    #[test]
    fn pool_reuses_zeroed_buffers_after_deallocate() {
        let config = PoolConfig::new(8, 1, 1, false, 0);
        let mut pool = SymbolPool::new(config);

        let mut buffer = pool.allocate().expect("initial allocation");
        buffer.as_mut_slice().fill(0xAA);
        pool.deallocate(buffer);

        let reused = pool.allocate().expect("reused allocation");
        assert!(
            reused.as_slice().iter().all(|byte| *byte == 0),
            "recycled buffers must not retain prior payload bytes"
        );
    }

    #[test]
    fn resource_acquire_within_limits() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard =
            ResourceTracker::try_acquire_encoding(&tracker, 50).expect("expected acquisition");
        drop(guard);
        let usage = tracker.lock().usage().clone();
        assert_eq!(usage.symbol_memory, 0);
    }

    #[test]
    fn resource_acquire_exceeds_limit() {
        let limits = ResourceLimits {
            max_symbol_memory: 10,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 10,
        };
        let tracker = ResourceTracker::shared(limits);
        let err = ResourceTracker::try_acquire_encoding(&tracker, 20)
            .expect_err("expected limit failure");
        assert_eq!(err, ResourceExhausted::PerObjectMemory);
    }

    #[test]
    fn resource_guard_releases_on_drop() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 1,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        {
            let _guard = ResourceTracker::try_acquire_encoding(&tracker, 10).expect("acquire");
        }
        let usage = tracker.lock().usage().clone();
        assert_eq!(usage.symbol_memory, 0);
        assert_eq!(usage.encoding_ops, 0);
    }

    #[test]
    fn resource_zero_limit_fails() {
        let limits = ResourceLimits {
            max_symbol_memory: 0,
            max_encoding_ops: 0,
            max_decoding_ops: 0,
            max_symbols_in_flight: 0,
            max_per_object_memory: 0,
        };
        let tracker = ResourceTracker::shared(limits);
        let err = ResourceTracker::try_acquire_encoding(&tracker, 1).expect_err("expected failure");
        assert_eq!(err, ResourceExhausted::PerObjectMemory);
    }

    struct TestObserver {
        pressure_calls: Arc<AtomicUsize>,
        limit_calls: Arc<AtomicUsize>,
    }

    impl TestObserver {
        fn new(pressure_calls: Arc<AtomicUsize>, limit_calls: Arc<AtomicUsize>) -> Self {
            Self {
                pressure_calls,
                limit_calls,
            }
        }
    }

    impl ResourceObserver for TestObserver {
        fn on_pressure_change(&self, _pressure: f64) {
            self.pressure_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn on_limit_approached(&self, _resource: ResourceKind, _usage_percent: f64) {
            self.limit_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn on_limit_exceeded(&self, _resource: ResourceKind) {
            self.limit_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn resource_observer_notified() {
        let limits = ResourceLimits {
            max_symbol_memory: 10,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 1,
            max_per_object_memory: 10,
        };
        let tracker = ResourceTracker::shared(limits);
        let pressure_calls = Arc::new(AtomicUsize::new(0));
        let limit_calls = Arc::new(AtomicUsize::new(0));
        let observer = Box::new(TestObserver::new(
            Arc::clone(&pressure_calls),
            Arc::clone(&limit_calls),
        ));
        tracker.lock().add_observer(observer);
        let _guard = ResourceTracker::try_acquire_encoding(&tracker, 9).expect("acquire");
        assert!(pressure_calls.load(Ordering::Relaxed) > 0);
        assert!(limit_calls.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn pressure_ignores_per_object_limit_as_aggregate() {
        let limits = ResourceLimits {
            max_symbol_memory: 1000,
            max_encoding_ops: 10,
            max_decoding_ops: 10,
            max_symbols_in_flight: 100,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard = ResourceTracker::try_acquire(&tracker, ResourceRequest::new(90, 0, 0, 0))
            .expect("acquire should satisfy per-object limit");

        let pressure = tracker.lock().pressure();
        assert!(
            (pressure - 0.09).abs() < f64::EPSILON,
            "pressure={pressure}"
        );
        drop(guard);
    }

    #[test]
    fn observer_does_not_emit_per_object_limit_for_aggregate_usage() {
        let limits = ResourceLimits {
            max_symbol_memory: 1000,
            max_encoding_ops: 10,
            max_decoding_ops: 10,
            max_symbols_in_flight: 100,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let pressure_calls = Arc::new(AtomicUsize::new(0));
        let limit_calls = Arc::new(AtomicUsize::new(0));
        let observer = Box::new(TestObserver::new(
            Arc::clone(&pressure_calls),
            Arc::clone(&limit_calls),
        ));
        tracker.lock().add_observer(observer);

        let _guard = ResourceTracker::try_acquire(&tracker, ResourceRequest::new(90, 0, 0, 0))
            .expect("acquire should satisfy per-object limit");

        assert!(pressure_calls.load(Ordering::Relaxed) > 0);
        assert_eq!(
            limit_calls.load(Ordering::Relaxed),
            0,
            "aggregate usage should not trigger per-object notifications"
        );
    }

    #[test]
    fn resource_tracker_lock_survives_panicking_holder() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 1,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let tracker_clone = Arc::clone(&tracker);

        let panicked = std::thread::spawn(move || {
            let _guard = tracker_clone.lock();
            panic!("simulate panic while holding resource tracker lock");
        })
        .join();
        assert!(panicked.is_err(), "panic thread should panic");

        let guard =
            ResourceTracker::try_acquire_encoding(&tracker, 10).expect("acquire after panic");
        drop(guard);

        let usage = tracker.lock().usage().clone();
        assert_eq!(usage.symbol_memory, 0);
        assert_eq!(usage.encoding_ops, 0);
    }

    // ---- Pure data type tests ----

    #[test]
    fn pool_config_default() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.symbol_size, DEFAULT_SYMBOL_SIZE as u16);
        assert_eq!(cfg.initial_size, 0);
        assert_eq!(cfg.max_size, 0);
        assert!(!cfg.allow_growth);
        assert_eq!(cfg.growth_increment, 0);
    }

    #[test]
    fn pool_config_debug() {
        let cfg = PoolConfig::new(256, 10, 100, true, 5);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("PoolConfig"), "{dbg}");
        assert!(dbg.contains("256"), "{dbg}");
    }

    #[test]
    fn pool_stats_default() {
        let stats = PoolStats::default();
        assert_eq!(stats.allocations, 0);
        assert_eq!(stats.deallocations, 0);
        assert_eq!(stats.pool_hits, 0);
        assert_eq!(stats.pool_misses, 0);
        assert_eq!(stats.peak_usage, 0);
        assert_eq!(stats.current_usage, 0);
        assert_eq!(stats.growth_events, 0);
    }

    #[test]
    fn pool_stats_debug() {
        let stats = PoolStats {
            allocations: 5,
            ..PoolStats::default()
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("PoolStats"), "{dbg}");
        assert!(dbg.contains('5'), "{dbg}");
    }

    #[test]
    fn symbol_buffer_operations() {
        let mut buf = SymbolBuffer::new(16);
        assert_eq!(buf.len(), 16);
        assert!(!buf.is_empty());
        assert_eq!(buf.as_slice().len(), 16);
        assert!(buf.as_slice().iter().all(|&b| b == 0));

        buf.as_mut_slice()[0] = 42;
        assert_eq!(buf.as_slice()[0], 42);

        let boxed = buf.into_boxed_slice();
        assert_eq!(boxed.len(), 16);
        assert_eq!(boxed[0], 42);
    }

    #[test]
    fn symbol_buffer_zero_size() {
        let buf = SymbolBuffer::new(0);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn symbol_buffer_debug() {
        let buf = SymbolBuffer::new(4);
        let dbg = format!("{buf:?}");
        assert!(dbg.contains("SymbolBuffer"), "{dbg}");
    }

    #[test]
    fn pool_exhausted_display_and_error() {
        let err = PoolExhausted;
        assert_eq!(err.to_string(), "symbol pool exhausted");
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(err, PoolExhausted);
    }

    #[test]
    fn resource_exhausted_display_all_variants() {
        let cases = [
            (ResourceExhausted::SymbolMemory, "symbol memory"),
            (ResourceExhausted::EncodingOps, "encoding operations"),
            (ResourceExhausted::DecodingOps, "decoding operations"),
            (ResourceExhausted::SymbolsInFlight, "symbols in flight"),
            (ResourceExhausted::PerObjectMemory, "per-object memory"),
        ];
        for (variant, expected_substr) in cases {
            let msg = variant.to_string();
            assert!(msg.contains(expected_substr), "{msg}");
            assert!(std::error::Error::source(&variant).is_none());
        }
    }

    #[test]
    fn resource_kind_debug_all_variants() {
        let kinds = [
            ResourceKind::SymbolMemory,
            ResourceKind::EncodingOps,
            ResourceKind::DecodingOps,
            ResourceKind::SymbolsInFlight,
            ResourceKind::PerObjectMemory,
        ];
        for kind in &kinds {
            let dbg = format!("{kind:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn resource_limits_default_is_zero() {
        let limits = ResourceLimits::default();
        assert!(limits.is_zero());
    }

    #[test]
    fn resource_limits_non_zero() {
        let limits = ResourceLimits {
            max_symbol_memory: 1,
            ..ResourceLimits::default()
        };
        assert!(!limits.is_zero());
    }

    #[test]
    fn resource_usage_default() {
        let usage = ResourceUsage::default();
        assert_eq!(usage.symbol_memory, 0);
        assert_eq!(usage.encoding_ops, 0);
        assert_eq!(usage.decoding_ops, 0);
        assert_eq!(usage.symbols_in_flight, 0);
    }

    #[test]
    fn resource_request_default_and_accessor() {
        let req = ResourceRequest::default();
        assert_eq!(req.symbol_memory(), 0);

        let req = ResourceRequest::new(1024, 2, 3, 10);
        assert_eq!(req.symbol_memory(), 1024);
    }

    #[test]
    fn resource_tracker_debug() {
        let limits = ResourceLimits::default();
        let tracker = ResourceTracker::new(limits);
        let dbg = format!("{tracker:?}");
        assert!(dbg.contains("ResourceTracker"), "{dbg}");
    }

    #[test]
    fn resource_tracker_pressure_with_zero_limits() {
        let limits = ResourceLimits::default();
        let tracker = ResourceTracker::new(limits);
        // No usage, no limits → pressure = 0
        assert!(
            (tracker.pressure()).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            tracker.pressure()
        );
    }

    #[test]
    fn resource_tracker_can_acquire_predicate() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::new(limits);
        let req = ResourceRequest::new(50, 1, 0, 0);
        assert!(tracker.can_acquire(&req));

        let req = ResourceRequest::new(200, 1, 0, 0);
        assert!(!tracker.can_acquire(&req));
    }

    #[test]
    fn resource_guard_debug() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard = ResourceTracker::try_acquire_encoding(&tracker, 10).expect("acquire");
        let dbg = format!("{guard:?}");
        assert!(dbg.contains("ResourceGuard"), "{dbg}");
    }

    #[test]
    fn pool_reset_stats() {
        let config = PoolConfig::new(8, 2, 2, false, 0);
        let mut pool = SymbolPool::new(config);
        let buf = pool.allocate().expect("alloc");
        pool.deallocate(buf);
        assert!(pool.stats().allocations > 0);

        pool.reset_stats();
        assert_eq!(pool.stats().allocations, 0);
        assert_eq!(pool.stats().deallocations, 0);
    }

    #[test]
    fn pool_peak_usage_tracking() {
        let config = PoolConfig::new(8, 4, 4, false, 0);
        let mut pool = SymbolPool::new(config);
        let a = pool.allocate().expect("a");
        let b = pool.allocate().expect("b");
        let c = pool.allocate().expect("c");
        assert_eq!(pool.stats().peak_usage, 3);
        pool.deallocate(a);
        pool.deallocate(b);
        // Peak stays at 3 even after deallocation
        assert_eq!(pool.stats().peak_usage, 3);
        assert_eq!(pool.stats().current_usage, 1);
        pool.deallocate(c);
    }

    #[test]
    fn try_acquire_decoding() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            max_encoding_ops: 1,
            max_decoding_ops: 1,
            max_symbols_in_flight: 10,
            max_per_object_memory: 100,
        };
        let tracker = ResourceTracker::shared(limits);
        let guard = ResourceTracker::try_acquire_decoding(&tracker, 50).expect("decode acquire");
        {
            let t = tracker.lock();
            assert_eq!(t.usage().decoding_ops, 1);
            assert_eq!(t.usage().symbol_memory, 50);
            drop(t);
        }
        drop(guard);
        let t = tracker.lock();
        assert_eq!(t.usage().decoding_ops, 0);
        drop(t);
    }

    #[test]
    fn pool_config_max_clamp() {
        // When max_size < initial_size, constructor clamps max_size
        let config = PoolConfig::new(8, 5, 2, false, 0);
        let pool = SymbolPool::new(config);
        assert!(pool.config().max_size >= pool.config().initial_size);
    }

    // ── derive-trait coverage (wave 74) ──────────────────────────────────

    #[test]
    fn pool_stats_debug_clone_default() {
        let s = PoolStats::default();
        assert_eq!(s.allocations, 0);
        assert_eq!(s.current_usage, 0);
        let s2 = s;
        let dbg = format!("{s2:?}");
        assert!(dbg.contains("PoolStats"));
    }

    #[test]
    fn pool_exhausted_debug_clone_copy_eq() {
        let e = PoolExhausted;
        let e2 = e; // Copy
        let e3 = e;
        assert_eq!(e, e2);
        assert_eq!(e2, e3);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("PoolExhausted"));
    }

    #[test]
    fn resource_kind_debug_clone_copy_eq() {
        let k = ResourceKind::SymbolMemory;
        let k2 = k; // Copy
        assert_eq!(k, k2);
        assert_ne!(k, ResourceKind::EncodingOps);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("SymbolMemory"));
    }

    #[test]
    fn resource_limits_debug_clone_default() {
        let l = ResourceLimits::default();
        assert!(l.is_zero());
        let l2 = l;
        assert_eq!(l2.max_symbol_memory, 0);
        let dbg = format!("{l2:?}");
        assert!(dbg.contains("ResourceLimits"));
    }

    #[test]
    fn resource_usage_debug_clone_default_eq() {
        let u = ResourceUsage::default();
        let u2 = u.clone();
        assert_eq!(u, u2);
        assert_eq!(u.symbol_memory, 0);
        let dbg = format!("{u:?}");
        assert!(dbg.contains("ResourceUsage"));
    }

    #[test]
    fn resource_request_debug_clone_copy_default() {
        let r = ResourceRequest::default();
        let r2 = r; // Copy
        let r3 = r;
        let _ = r2;
        let _ = r3;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ResourceRequest"));
    }

    #[test]
    fn resource_exhausted_debug_clone_copy_eq() {
        let e = ResourceExhausted::SymbolMemory;
        let e2 = e; // Copy
        let e3 = e;
        assert_eq!(e, e2);
        assert_eq!(e2, e3);
        assert_ne!(e, ResourceExhausted::DecodingOps);
        let dbg = format!("{e:?}");
        assert!(dbg.contains("SymbolMemory"));
    }

    /// br-asupersync-jpzl5a — `new_with_pool_id` honours the supplied
    /// id rather than minting a new one from the global allocator.
    /// This is the deterministic-replay-friendly path.
    #[test]
    fn new_with_pool_id_uses_supplied_id() {
        let cfg = PoolConfig {
            symbol_size: 64,
            initial_size: 0,
            max_size: 0,
            allow_growth: false,
            growth_increment: 0,
        };
        let pool = SymbolPool::new_with_pool_id(cfg.clone(), 0xCAFE_BABE);
        assert_eq!(pool.pool_id, 0xCAFE_BABE);
    }

    /// br-asupersync-jpzl5a — `new` mints distinct ids from the
    /// process-global counter (the documented behaviour for
    /// determinism-insensitive callers).
    #[test]
    fn new_mints_distinct_pool_ids() {
        let cfg = PoolConfig {
            symbol_size: 64,
            initial_size: 0,
            max_size: 0,
            allow_growth: false,
            growth_increment: 0,
        };
        let a = SymbolPool::new(cfg.clone());
        let b = SymbolPool::new(cfg);
        assert_ne!(a.pool_id, b.pool_id);
    }
