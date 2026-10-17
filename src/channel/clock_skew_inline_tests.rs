    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::evidence_sink::CollectorSink;
    use crate::time::VirtualClock;

    fn make_base_clock() -> Arc<VirtualClock> {
        Arc::new(VirtualClock::new())
    }

    fn make_sink() -> (Arc<CollectorSink>, Arc<dyn EvidenceSink>) {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        (collector, sink)
    }

    #[test]
    fn no_skew_passthrough() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000); // 1s
        assert_eq!(skewed.now(), Time::from_secs(1));

        let stats = skewed.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.skewed_reads, 0);
    }

    #[test]
    fn static_offset_ahead() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(50); // 50ms ahead
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000); // 1s
        let t = skewed.now();
        // Expect 1s + 50ms = 1.05s
        assert_eq!(t, Time::from_nanos(1_050_000_000));

        let stats = skewed.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.skewed_reads, 1);
        assert_eq!(stats.max_abs_skew_ns, 50_000_000);
    }

    #[test]
    fn jump_evidence_uses_base_clock_timestamp() {
        let base = make_base_clock();
        let (collector, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_jump(1_000_000_000, 50_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000);
        let _ = skewed.now();

        let entries = collector.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "inject_clock_jump");
        assert_eq!(entries[0].ts_unix_ms, 1_000);
    }

    #[test]
    fn static_offset_emits_skew_evidence() {
        let base = make_base_clock();
        let (collector, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(25);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000);
        let _ = skewed.now();

        let entries = collector.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "inject_clock_skew");
        assert_eq!(entries[0].ts_unix_ms, 1_000);
    }

    #[test]
    fn static_offset_behind() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(-100); // 100ms behind
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000); // 1s
        let t = skewed.now();
        // Expect 1s - 100ms = 0.9s
        assert_eq!(t, Time::from_nanos(900_000_000));
    }

    #[test]
    fn static_offset_saturates_at_zero() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Offset behind by 200ms but base is only 100ms
        let config = ClockSkewConfig::new(42).with_static_offset_ms(-200);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(100_000_000); // 100ms
        let t = skewed.now();
        assert_eq!(t, Time::ZERO); // Saturated
    }

    #[test]
    fn drift_makes_clock_run_fast() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Drift: +1ms per second of base time
        let config = ClockSkewConfig::new(42).with_drift_rate(1_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // At 10s base time, drift = 10ms
        base.advance(10_000_000_000);
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(10_010_000_000));
    }

    #[test]
    fn drift_makes_clock_run_slow() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Drift: -2ms per second
        let config = ClockSkewConfig::new(42).with_drift_rate(-2_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // At 5s base time, drift = -10ms
        base.advance(5_000_000_000);
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(4_990_000_000));
    }

    #[test]
    fn jump_fires_once_at_trigger() {
        let base = make_base_clock();
        let (collector, sink) = make_sink();
        // Jump +100ms when base exceeds 2s
        let config = ClockSkewConfig::new(42).with_jump(2_000_000_000, 100_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // Before trigger: no jump
        base.advance(1_000_000_000);
        assert_eq!(skewed.now(), Time::from_secs(1));

        // At trigger: jump fires
        base.advance(1_500_000_000); // base = 2.5s
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(2_600_000_000)); // 2.5s + 100ms

        // After trigger: jump remains applied
        base.advance(1_000_000_000); // base = 3.5s
        let t2 = skewed.now();
        assert_eq!(t2, Time::from_nanos(3_600_000_000)); // 3.5s + 100ms

        let stats = skewed.stats();
        assert!(stats.jump_fired);

        // Evidence should have been emitted
        let entries = collector.entries();
        assert!(
            entries.iter().any(|e| e.action.contains("clock_jump")),
            "Expected evidence for clock_jump"
        );
    }

    #[test]
    fn jump_backward_simulates_ntp_correction() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Jump -50ms when base exceeds 1s (NTP correction backward)
        let config = ClockSkewConfig::new(42).with_jump(1_000_000_000, -50_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(2_000_000_000); // 2s
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(1_950_000_000)); // 2s - 50ms
    }

    #[test]
    fn jitter_is_deterministic() {
        let base1 = make_base_clock();
        let base2 = make_base_clock();
        let (_, sink1) = make_sink();
        let (_, sink2) = make_sink();
        let config = ClockSkewConfig::new(42).with_jitter(1.0, 10_000_000); // always jitter, ±10ms

        let skewed1 = SkewClock::new(base1.clone() as Arc<dyn TimeSource>, config.clone(), sink1);
        let skewed2 = SkewClock::new(base2.clone() as Arc<dyn TimeSource>, config, sink2);

        let mut times1 = Vec::new();
        let mut times2 = Vec::new();

        for i in 1..=20 {
            base1.set(Time::from_secs(i));
            base2.set(Time::from_secs(i));
            times1.push(skewed1.now());
            times2.push(skewed2.now());
        }

        assert_eq!(
            times1, times2,
            "Same seed must produce same jitter sequence"
        );
    }

    #[test]
    fn one_nanosecond_jitter_does_not_collapse_to_zero() {
        let base = make_base_clock();
        let (collector, sink) = make_sink();
        let config = ClockSkewConfig::new(7).with_jitter(1.0, 1);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.set(Time::from_secs(3));
        let observed = skewed.now();
        let diff = observed.as_nanos().abs_diff(Time::from_secs(3).as_nanos());

        assert_eq!(diff, 1);
        let stats = skewed.stats();
        assert_eq!(stats.jitter_count, 1);
        assert_eq!(stats.skewed_reads, 1);

        let entries = collector.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "inject_clock_jitter");
    }

    #[test]
    fn signed_jitter_conversion_accepts_full_valid_range() {
        let max = i64::MAX.unsigned_abs();
        let config = ClockSkewConfig::new(42).with_jitter(1.0, max);

        assert_eq!(config.jitter_max_ns, max);
        assert_eq!(SkewClock::signed_jitter_ns(0, true), 0);
        assert_eq!(SkewClock::signed_jitter_ns(max, true), i64::MAX);
        assert_eq!(SkewClock::signed_jitter_ns(max, false), -i64::MAX);

        let base = make_base_clock();
        let (_, sink) = make_sink();
        let mut direct_config = ClockSkewConfig::new(42);
        direct_config.jitter_probability = 1.0;
        direct_config.jitter_max_ns = max;
        let direct = SkewClock::new(base as Arc<dyn TimeSource>, direct_config, sink);
        assert_eq!(direct.config.jitter_max_ns, max);
    }

    #[test]
    fn jitter_bounded() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let max_jitter_ns: u64 = 5_000_000; // 5ms
        let config = ClockSkewConfig::new(42).with_jitter(1.0, max_jitter_ns);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(10_000_000_000); // 10s (far enough to avoid saturation)

        for _ in 0..100 {
            let t = skewed.now();
            let diff = if t.as_nanos() >= 10_000_000_000 {
                t.as_nanos() - 10_000_000_000
            } else {
                10_000_000_000 - t.as_nanos()
            };
            assert!(
                diff <= max_jitter_ns,
                "Jitter {diff}ns exceeds max {max_jitter_ns}ns"
            );
        }

        let stats = skewed.stats();
        assert_eq!(stats.jitter_count, 100);
    }

    #[test]
    fn combined_offset_and_drift() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42)
            .with_static_offset_ms(10) // 10ms ahead
            .with_drift_rate(500_000); // +0.5ms per second

        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // At 20s: offset=10ms, drift=10ms, total=20ms
        base.advance(20_000_000_000);
        let t = skewed.now();
        assert_eq!(t, Time::from_nanos(20_020_000_000));
    }

    #[test]
    fn stats_track_reads() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        let config = ClockSkewConfig::new(42).with_static_offset_ms(1);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        base.advance(1_000_000_000);
        for _ in 0..10 {
            let _ = skewed.now();
        }

        let stats = skewed.stats();
        assert_eq!(stats.reads, 10);
        assert_eq!(stats.skewed_reads, 10);
    }

    #[test]
    fn config_default_disabled() {
        let config = ClockSkewConfig::new(42);
        assert!(!config.is_enabled());
    }

    #[test]
    fn config_static_offset_enabled() {
        let config = ClockSkewConfig::new(42).with_static_offset_ms(1);
        assert!(config.is_enabled());
    }

    #[test]
    fn config_drift_enabled() {
        let config = ClockSkewConfig::new(42).with_drift_rate(1);
        assert!(config.is_enabled());
    }

    #[test]
    fn config_jitter_enabled() {
        let config = ClockSkewConfig::new(42).with_jitter(0.5, 1000);
        assert!(config.is_enabled());
    }

    #[test]
    #[should_panic(expected = "probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_jitter_probability() {
        let _ = ClockSkewConfig::new(42).with_jitter(1.5, 1000);
    }

    #[test]
    fn config_builder_rejects_jitter_above_signed_range() {
        for max in [i64::MAX.unsigned_abs() + 1, u64::MAX] {
            let result = std::panic::catch_unwind(|| {
                let _ = ClockSkewConfig::new(42).with_jitter(1.0, max);
            });
            assert!(result.is_err(), "builder accepted jitter_max_ns={max}");
        }
    }

    #[test]
    fn skew_clock_rejects_direct_config_above_signed_range() {
        for max in [i64::MAX.unsigned_abs() + 1, u64::MAX] {
            let base = make_base_clock();
            let (_, sink) = make_sink();
            let mut config = ClockSkewConfig::new(42);
            config.jitter_probability = 1.0;
            config.jitter_max_ns = max;

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = SkewClock::new(base as Arc<dyn TimeSource>, config, sink);
            }));
            assert!(result.is_err(), "constructor accepted jitter_max_ns={max}");
        }
    }

    #[test]
    fn zero_base_time_with_offset() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // Positive offset at time zero should work.
        let config = ClockSkewConfig::new(42).with_static_offset_ms(100);
        let skewed = SkewClock::new(base as Arc<dyn TimeSource>, config, sink);
        let t = skewed.now();
        assert_eq!(t, Time::from_millis(100));
    }

    // =========================================================================
    // Pure data-type tests (wave 42 – CyanBarn)
    // =========================================================================

    #[test]
    fn clock_skew_stats_snapshot_debug_clone_eq() {
        let snap = ClockSkewStatsSnapshot {
            reads: 100,
            skewed_reads: 50,
            jitter_count: 10,
            jump_fired: false,
            max_abs_skew_ns: 5000,
        };
        let cloned = snap.clone();
        assert_eq!(cloned, snap);
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("ClockSkewStatsSnapshot"));
        assert_ne!(
            snap,
            ClockSkewStatsSnapshot {
                reads: 0,
                skewed_reads: 0,
                jitter_count: 0,
                jump_fired: false,
                max_abs_skew_ns: 0,
            }
        );
    }

    #[test]
    fn clock_skew_config_debug_clone() {
        let config = ClockSkewConfig::new(42)
            .with_static_offset_ms(1)
            .with_drift_rate(500);
        let cloned = config.clone();
        assert_eq!(cloned.seed, 42);
        assert_eq!(cloned.static_offset_ns, 1_000_000);
        assert_eq!(cloned.drift_rate_ns_per_sec, 500);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ClockSkewConfig"));
    }

    #[test]
    fn drift_precision_is_stable_at_large_timestamps() {
        let base = make_base_clock();
        let (_, sink) = make_sink();
        // 1 second drift per second of base time.
        let config = ClockSkewConfig::new(42).with_drift_rate(1_000_000_000);
        let skewed = SkewClock::new(base.clone() as Arc<dyn TimeSource>, config, sink);

        // 2^53 + 1: not exactly representable in f64, so float-based math loses 1ns.
        let base_nanos = 9_007_199_254_740_993_u64;
        base.set(Time::from_nanos(base_nanos));

        let actual = skewed.now();
        let expected = Time::from_nanos(base_nanos.saturating_mul(2));
        assert_eq!(actual, expected);
    }
