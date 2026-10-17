    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn latency_models_are_deterministic() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);
        let model = LatencyModel::Uniform {
            min: Duration::from_millis(1),
            max: Duration::from_millis(5),
        };
        for _ in 0..100 {
            assert_eq!(model.sample(&mut rng1), model.sample(&mut rng2));
        }
    }

    #[test]
    fn latency_models_constant_cases() {
        let mut rng = DetRng::new(7);
        let fixed = LatencyModel::Fixed(Duration::from_millis(5));
        assert_eq!(fixed.sample(&mut rng), Duration::from_millis(5));

        let uniform = LatencyModel::Uniform {
            min: Duration::from_millis(3),
            max: Duration::from_millis(3),
        };
        assert_eq!(uniform.sample(&mut rng), Duration::from_millis(3));

        let normal = LatencyModel::Normal {
            mean: Duration::from_millis(12),
            std_dev: Duration::ZERO,
        };
        assert_eq!(normal.sample(&mut rng), Duration::from_millis(12));

        let log_normal = LatencyModel::LogNormal {
            mu: 0.0,
            sigma: 0.0,
        };
        assert_eq!(log_normal.sample(&mut rng), duration_from_secs_f64(1.0));

        let bimodal_low = LatencyModel::Bimodal {
            low: Duration::from_millis(4),
            high: Duration::from_millis(9),
            high_probability: 0.0,
        };
        assert_eq!(bimodal_low.sample(&mut rng), Duration::from_millis(4));

        let bimodal_high = LatencyModel::Bimodal {
            low: Duration::from_millis(4),
            high: Duration::from_millis(9),
            high_probability: 1.0,
        };
        assert_eq!(bimodal_high.sample(&mut rng), Duration::from_millis(9));
    }

    // ========================================================================
    // Pure data-type tests (wave 10 – CyanBarn)
    // ========================================================================

    #[test]
    fn network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.seed, 0x4E45_5457);
        assert!(!config.capture_trace);
        assert_eq!(config.max_queue_depth, 10_000);
        assert_eq!(config.tick_resolution, Duration::from_micros(100));
        assert!(!config.enable_bandwidth);
        assert_eq!(config.default_bandwidth, 1_000_000_000);
    }

    #[test]
    fn network_config_debug_clone() {
        let config = NetworkConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("NetworkConfig"), "{dbg}");
        let cloned = config;
        assert_eq!(cloned.seed, 0x4E45_5457);
    }

    #[test]
    fn network_conditions_ideal() {
        let c = NetworkConditions::ideal();
        assert!(
            (c.packet_loss).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_loss
        );
        assert!(
            (c.packet_corrupt).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_corrupt
        );
        assert!(
            (c.packet_duplicate).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_duplicate
        );
        assert!(
            (c.packet_reorder).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_reorder
        );
        assert_eq!(c.max_in_flight, usize::MAX);
        assert!(c.bandwidth.is_none());
        assert!(c.jitter.is_none());
        assert!(matches!(c.latency, LatencyModel::Fixed(d) if d == Duration::ZERO));
    }

    #[test]
    fn network_conditions_local() {
        let c = NetworkConditions::local();
        assert!(matches!(c.latency, LatencyModel::Fixed(d) if d == Duration::from_millis(1)));
        assert!(
            (c.packet_loss).abs() < f64::EPSILON,
            "expected 0.0, got {}",
            c.packet_loss
        );
    }

    #[test]
    fn network_conditions_lan() {
        let c = NetworkConditions::lan();
        assert!(matches!(c.latency, LatencyModel::Uniform { .. }));
        assert!(c.packet_loss > 0.0);
        assert_eq!(c.bandwidth, Some(1_000_000_000));
    }

    #[test]
    fn network_conditions_wan() {
        let c = NetworkConditions::wan();
        assert!(matches!(c.latency, LatencyModel::Normal { .. }));
        assert!(c.packet_loss > 0.0);
        assert!(c.packet_reorder > 0.0);
        assert_eq!(c.bandwidth, Some(100_000_000));
        assert!(c.jitter.is_some());
    }

    #[test]
    fn network_conditions_lossy() {
        let c = NetworkConditions::lossy();
        assert!((c.packet_loss - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn network_conditions_satellite() {
        let c = NetworkConditions::satellite();
        assert!(
            matches!(c.latency, LatencyModel::Normal { mean, .. } if mean > Duration::from_millis(500))
        );
        assert!(c.packet_loss > 0.0);
        assert_eq!(c.bandwidth, Some(10_000_000));
    }

    #[test]
    fn network_conditions_congested() {
        let c = NetworkConditions::congested();
        assert!(c.packet_loss > 0.01);
        assert!(c.packet_reorder > 0.0);
        assert_eq!(c.max_in_flight, 100);
        assert!(matches!(c.jitter, Some(JitterModel::Bursty { .. })));
    }

    #[test]
    fn network_conditions_debug_clone() {
        let c = NetworkConditions::wan();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("NetworkConditions"), "{dbg}");
        let cloned = c.clone();
        assert!((cloned.packet_loss - c.packet_loss).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_model_debug_clone() {
        let fixed = LatencyModel::Fixed(Duration::from_millis(5));
        let dbg = format!("{fixed:?}");
        assert!(dbg.contains("Fixed"), "{dbg}");
        let cloned = fixed.clone();
        let mut rng1 = DetRng::new(1);
        let mut rng2 = DetRng::new(1);
        assert_eq!(cloned.sample(&mut rng1), fixed.sample(&mut rng2));
    }

    #[test]
    fn latency_model_log_normal_produces_positive() {
        let model = LatencyModel::LogNormal {
            mu: -2.0,
            sigma: 0.5,
        };
        let mut rng = DetRng::new(123);
        for _ in 0..50 {
            let sample = model.sample(&mut rng);
            assert!(sample >= Duration::ZERO);
        }
    }

    #[test]
    fn latency_model_uniform_min_exceeds_max() {
        let model = LatencyModel::Uniform {
            min: Duration::from_millis(10),
            max: Duration::from_millis(5),
        };
        let mut rng = DetRng::new(7);
        // When min >= max, returns min
        assert_eq!(model.sample(&mut rng), Duration::from_millis(10));
    }

    #[test]
    fn jitter_model_debug_clone() {
        let uniform = JitterModel::Uniform {
            max: Duration::from_millis(5),
        };
        let cloned = uniform.clone();
        let dbg = format!("{uniform:?}");
        assert!(dbg.contains("Uniform"), "{dbg}");
        assert!(format!("{cloned:?}").contains("Uniform"));
    }

    #[test]
    fn jitter_model_uniform_zero_max() {
        let model = JitterModel::Uniform {
            max: Duration::ZERO,
        };
        let mut rng = DetRng::new(42);
        assert_eq!(model.sample(&mut rng), Duration::ZERO);
    }

    #[test]
    fn jitter_model_bursty_zero_ranges() {
        let model = JitterModel::Bursty {
            normal_jitter: Duration::ZERO,
            burst_jitter: Duration::ZERO,
            burst_probability: 0.5,
        };
        let mut rng = DetRng::new(99);
        for _ in 0..20 {
            assert_eq!(model.sample(&mut rng), Duration::ZERO);
        }
    }

    #[test]
    fn duration_from_secs_f64_negative() {
        assert_eq!(duration_from_secs_f64(-1.0), Duration::ZERO);
    }

    #[test]
    fn duration_from_secs_f64_nan() {
        assert_eq!(duration_from_secs_f64(f64::NAN), Duration::ZERO);
    }

    #[test]
    fn duration_from_secs_f64_infinity() {
        assert_eq!(duration_from_secs_f64(f64::INFINITY), Duration::ZERO);
    }

    #[test]
    fn duration_from_secs_f64_valid() {
        let d = duration_from_secs_f64(0.001);
        assert_eq!(d, Duration::from_millis(1));
    }

    #[test]
    fn duration_from_secs_f64_large_value_preserved() {
        let secs = 1_000_000_000_000.0;
        let d = duration_from_secs_f64(secs);
        assert_eq!(d.as_secs(), 1_000_000_000_000);
    }

    #[test]
    fn latency_model_uniform_large_range_does_not_truncate() {
        let min = Duration::from_secs(20_000_000_000);
        let max = min + Duration::from_secs(1);
        let model = LatencyModel::Uniform { min, max };
        let mut rng = DetRng::new(1234);
        for _ in 0..64 {
            let sample = model.sample(&mut rng);
            assert!(sample >= min, "sample below min: {sample:?} < {min:?}");
            assert!(sample <= max, "sample above max: {sample:?} > {max:?}");
        }
    }

    #[test]
    fn jitter_model_uniform_large_max_does_not_truncate() {
        // When max exceeds u64::MAX nanos (~18.4e9 seconds), samples must still
        // be valid Durations within [0, max]. The RNG is u64-bounded so offset
        // itself cannot exceed u64::MAX, but the conversion path must not panic
        // or wrap.
        let max = Duration::from_secs(20_000_000_000);
        let model = JitterModel::Uniform { max };
        let mut rng = DetRng::new(2026);
        for _ in 0..256 {
            let sample = model.sample(&mut rng);
            assert!(sample <= max, "sample above max: {sample:?} > {max:?}");
        }
    }

    #[test]
    fn jitter_models_respect_bounds() {
        let mut rng = DetRng::new(99);
        let uniform = JitterModel::Uniform {
            max: Duration::from_millis(6),
        };
        for _ in 0..100 {
            assert!(uniform.sample(&mut rng) <= Duration::from_millis(6));
        }

        let bursty_normal = JitterModel::Bursty {
            normal_jitter: Duration::from_millis(2),
            burst_jitter: Duration::from_millis(10),
            burst_probability: 0.0,
        };
        for _ in 0..100 {
            assert!(bursty_normal.sample(&mut rng) <= Duration::from_millis(2));
        }

        let bursty_burst = JitterModel::Bursty {
            normal_jitter: Duration::from_millis(2),
            burst_jitter: Duration::from_millis(10),
            burst_probability: 1.0,
        };
        for _ in 0..100 {
            assert!(bursty_burst.sample(&mut rng) <= Duration::from_millis(10));
        }
    }
