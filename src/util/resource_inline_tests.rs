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

    #[test]
    fn test_pool_allocate_deallocate() {
        let mut pool = SymbolPool::new(PoolConfig::default());
        let buf = pool.allocate().expect("should allocate");
        assert_eq!(buf.len(), 1024);
        pool.deallocate(buf);
        assert_eq!(pool.stats.allocations, 1);
        assert_eq!(pool.stats.deallocations, 1);
        assert_eq!(pool.stats.current_usage, 0);
    }

    #[test]
    fn test_pool_exhaustion() {
        let config = PoolConfig {
            initial_size: 1,
            max_size: 1,
            allow_growth: false,
            ..Default::default()
        };
        let mut pool = SymbolPool::new(config);
        let _buf1 = pool.allocate().expect("should allocate");
        assert!(pool.allocate().is_err());
        assert_eq!(pool.stats.pool_misses, 1);
    }

    #[test]
    fn test_pool_growth() {
        let config = PoolConfig {
            initial_size: 1,
            max_size: 5,
            growth_increment: 2,
            allow_growth: true,
            ..Default::default()
        };
        let mut pool = SymbolPool::new(config);
        let _buf1 = pool.allocate().expect("1");
        let _buf2 = pool.allocate().expect("2"); // triggers growth
        let _buf3 = pool.allocate().expect("3");
        assert_eq!(pool.stats.growth_events, 1);
        assert_eq!(pool.stats.current_usage, 3);
    }

    #[test]
    fn test_resource_tracker_acquire_release() {
        let limits = ResourceLimits {
            max_encoding_ops: 2,
            ..Default::default()
        };
        let tracker = ResourceTracker::new(limits);

        let g1 = tracker.try_acquire_encoding(100).expect("1");
        assert_eq!(tracker.usage().encoding_ops, 1);

        let _g2 = tracker.try_acquire_encoding(100).expect("2");
        assert_eq!(tracker.usage().encoding_ops, 2);

        assert!(tracker.try_acquire_encoding(100).is_err());

        drop(g1);
        assert_eq!(tracker.usage().encoding_ops, 1);

        let _g3 = tracker.try_acquire_encoding(100).expect("3");
    }

    #[test]
    fn test_resource_pressure() {
        let limits = ResourceLimits {
            max_symbol_memory: 100,
            ..Default::default()
        };
        let tracker = ResourceTracker::new(limits);

        assert!((tracker.pressure() - 0.0).abs() < f64::EPSILON);

        let _g1 = tracker
            .try_acquire(ResourceUsage {
                symbol_memory: 50,
                ..Default::default()
            })
            .unwrap();
        assert!((tracker.pressure() - 0.5).abs() < f64::EPSILON);

        let _g2 = tracker
            .try_acquire(ResourceUsage {
                symbol_memory: 50,
                ..Default::default()
            })
            .unwrap();
        assert!((tracker.pressure() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reset_stats_preserves_current_usage() {
        let mut pool = SymbolPool::new(PoolConfig::default());
        let _buf = pool.allocate().expect("should allocate");
        assert_eq!(pool.stats.current_usage, 1);
        assert_eq!(pool.stats.allocations, 1);

        pool.reset_stats();
        // After reset, current_usage and peak_usage should reflect actual allocated count.
        assert_eq!(pool.stats.current_usage, 1);
        assert_eq!(pool.stats.peak_usage, 1);
        // But cumulative counters should be zero.
        assert_eq!(pool.stats.allocations, 0);
        assert_eq!(pool.stats.deallocations, 0);
    }

    #[test]
    fn test_within_limits_ignores_per_object_memory() {
        // per_object_memory is smaller than total symbol_memory: must NOT block global checks.
        let limits = ResourceLimits {
            max_symbol_memory: 1000,
            max_per_object_memory: 100,
            ..Default::default()
        };
        let usage = ResourceUsage {
            symbol_memory: 500,
            ..Default::default()
        };
        // Global usage (500) exceeds per_object limit (100) but is within global limit (1000).
        // within_limits must return true because per-object enforcement is not its job.
        assert!(within_limits(&usage, &limits));
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn pool_config_debug_clone() {
        let cfg = PoolConfig::default();
        let cfg2 = cfg;
        assert!(format!("{cfg2:?}").contains("PoolConfig"));
    }

    #[test]
    fn pool_config_default_values() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.symbol_size, 1024);
        assert_eq!(cfg.initial_size, 0);
        assert_eq!(cfg.max_size, 1024);
        assert!(cfg.allow_growth);
        assert_eq!(cfg.growth_increment, 64);
    }

    #[test]
    fn pool_config_normalized_clamps() {
        let cfg = PoolConfig {
            initial_size: 10,
            max_size: 5,
            growth_increment: 0,
            ..Default::default()
        }
        .normalized();
        assert!(cfg.max_size >= cfg.initial_size);
        assert!(cfg.growth_increment >= 1);
    }

    #[test]
    fn symbol_buffer_debug_new_len_empty() {
        let buf = SymbolBuffer::new(64);
        assert_eq!(buf.len(), 64);
        assert!(!buf.is_empty());
        assert!(format!("{buf:?}").contains("SymbolBuffer"));
    }

    #[test]
    fn symbol_buffer_as_slice() {
        let mut buf = SymbolBuffer::new(4);
        assert_eq!(buf.as_slice().len(), 4);
        buf.as_mut_slice()[0] = 0xFF;
        assert_eq!(buf.as_slice()[0], 0xFF);
    }

    #[test]
    fn symbol_buffer_zero_size_is_empty() {
        let buf = SymbolBuffer::new(0);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn pool_stats_debug_clone_default() {
        let stats = PoolStats::default();
        let stats2 = stats;
        assert_eq!(stats2.allocations, 0);
        assert!(format!("{stats2:?}").contains("PoolStats"));
    }

    #[test]
    fn pool_exhausted_debug_clone_copy() {
        let e = PoolExhausted;
        let e2 = e;
        assert!(format!("{e2:?}").contains("PoolExhausted"));
    }

    #[test]
    fn pool_exhausted_display_error() {
        let e = PoolExhausted;
        assert!(e.to_string().contains("exhausted"));
        let err: Box<dyn std::error::Error> = Box::new(e);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn resource_limits_debug_clone_default() {
        let lim = ResourceLimits::default();
        let lim2 = lim;
        assert_eq!(lim2.max_symbol_memory, usize::MAX);
        assert!(format!("{lim2:?}").contains("ResourceLimits"));
    }

    #[test]
    fn resource_usage_debug_clone_copy_default_eq() {
        let u = ResourceUsage::default();
        let u2 = u;
        assert_eq!(u, u2);
        assert!(format!("{u:?}").contains("ResourceUsage"));
    }

    #[test]
    fn resource_usage_ne() {
        let u1 = ResourceUsage::default();
        let u2 = ResourceUsage {
            symbol_memory: 100,
            ..Default::default()
        };
        assert_ne!(u1, u2);
    }

    #[test]
    fn resource_request_debug_clone_copy_default() {
        let req = ResourceRequest::default();
        let req2 = req;
        assert_eq!(req2.usage, ResourceUsage::default());
        assert!(format!("{req2:?}").contains("ResourceRequest"));
    }

    #[test]
    fn resource_kind_debug_clone_copy_eq() {
        let k = ResourceKind::SymbolMemory;
        let k2 = k;
        assert_eq!(k, k2);
        assert!(format!("{k:?}").contains("SymbolMemory"));
    }

    #[test]
    fn resource_kind_all_variants() {
        let variants = [
            ResourceKind::SymbolMemory,
            ResourceKind::EncodingOps,
            ResourceKind::DecodingOps,
            ResourceKind::SymbolsInFlight,
        ];
        for (i, v) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v, v2);
                } else {
                    assert_ne!(v, v2);
                }
            }
        }
    }

    #[test]
    fn resource_exhausted_debug_clone_copy() {
        let e = ResourceExhausted;
        let e2 = e;
        assert!(format!("{e2:?}").contains("ResourceExhausted"));
    }

    #[test]
    fn resource_exhausted_display_error() {
        let e = ResourceExhausted;
        assert!(e.to_string().contains("resource limits exceeded"));
        let err: Box<dyn std::error::Error> = Box::new(e);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn symbol_pool_debug() {
        let pool = SymbolPool::new(PoolConfig::default());
        assert!(format!("{pool:?}").contains("SymbolPool"));
    }

    #[test]
    fn symbol_pool_warm() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 0,
            max_size: 10,
            ..Default::default()
        });
        pool.warm(5);
        // Should be able to allocate at least 5 without growth.
        for _ in 0..5 {
            assert!(pool.allocate().is_ok());
        }
    }

    #[test]
    fn symbol_pool_warm_respects_max_with_live_allocations() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 0,
            max_size: 4,
            allow_growth: false,
            ..Default::default()
        });
        pool.warm(4);

        let b1 = pool.allocate().expect("alloc 1");
        let b2 = pool.allocate().expect("alloc 2");
        let b3 = pool.allocate().expect("alloc 3");

        // Warm must account for already allocated buffers, so total capacity
        // (free + allocated) never exceeds max_size.
        pool.warm(4);

        let b4 = pool.allocate().expect("alloc 4");
        assert!(
            pool.allocate().is_err(),
            "pool exceeded max_size after warm"
        );

        pool.deallocate(b1);
        pool.deallocate(b2);
        pool.deallocate(b3);
        pool.deallocate(b4);
    }

    #[test]
    fn deallocate_rejects_invalid_buffers_without_mutating_state() {
        let mut pool = SymbolPool::new(PoolConfig {
            symbol_size: 1024,
            initial_size: 0,
            max_size: 8,
            allow_growth: false,
            growth_increment: 1,
        });

        let baseline = pool.stats().clone();

        for invalid in [SymbolBuffer::new(8), SymbolBuffer::new(1024)] {
            let result = catch_unwind(AssertUnwindSafe(|| {
                pool.deallocate(invalid);
            }));
            assert!(result.is_err(), "invalid buffer return must panic");
            assert_eq!(pool.stats().deallocations, baseline.deallocations);
            assert_eq!(pool.stats().current_usage, baseline.current_usage);
        }
    }

    #[test]
    fn deallocate_rejects_cross_pool_buffers_without_mutating_state() {
        let config = PoolConfig {
            symbol_size: 8,
            initial_size: 1,
            max_size: 1,
            allow_growth: false,
            growth_increment: 1,
        };
        let mut pool = SymbolPool::new(config.clone());
        let valid = pool.allocate().expect("valid alloc");

        let mut other_pool = SymbolPool::new(config);
        let foreign = other_pool.allocate().expect("foreign alloc");

        let result = catch_unwind(AssertUnwindSafe(|| {
            pool.deallocate(foreign);
        }));
        assert!(result.is_err(), "cross-pool return must panic");
        assert_eq!(pool.stats().deallocations, 0);
        assert_eq!(pool.stats().current_usage, 1);
        assert!(
            pool.try_allocate().is_none(),
            "foreign buffer must not expand capacity"
        );
        assert_eq!(other_pool.stats().current_usage, 1);
        assert!(
            other_pool.try_allocate().is_none(),
            "foreign pool must still account for its live checkout"
        );

        pool.deallocate(valid);
        assert_eq!(pool.stats().deallocations, 1);
        assert_eq!(pool.stats().current_usage, 0);
    }

    #[test]
    fn symbol_pool_shrink_to_fit() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 2,
            max_size: 10,
            allow_growth: true,
            growth_increment: 4,
            ..Default::default()
        });
        pool.warm(8);
        pool.shrink_to_fit();
        // After shrink, free list should be at most initial_size.
    }

    #[test]
    fn symbol_pool_try_allocate() {
        let mut pool = SymbolPool::new(PoolConfig {
            initial_size: 1,
            max_size: 1,
            allow_growth: false,
            ..Default::default()
        });
        assert!(pool.try_allocate().is_some());
        assert!(pool.try_allocate().is_none());
    }

    #[test]
    fn symbol_pool_reuses_zeroed_buffers_after_deallocate() {
        let mut pool = SymbolPool::new(PoolConfig {
            symbol_size: 8,
            initial_size: 1,
            max_size: 1,
            allow_growth: false,
            growth_increment: 1,
        });

        let mut buffer = pool.allocate().expect("allocate");
        buffer.as_mut_slice().fill(0xAA);
        pool.deallocate(buffer);

        let reused = pool.allocate().expect("reallocate");
        assert!(
            reused.as_slice().iter().all(|byte| *byte == 0),
            "reused buffers must not retain prior payload bytes"
        );
    }

    #[test]
    fn resource_tracker_clone() {
        let tracker = ResourceTracker::new(ResourceLimits::default());
        let tracker2 = tracker;
        assert_eq!(tracker2.usage(), ResourceUsage::default());
    }
