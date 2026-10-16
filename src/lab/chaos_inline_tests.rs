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
    fn config_off_has_no_chaos() {
        let config = ChaosConfig::off();
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");
    }

    #[test]
    fn config_light_has_chaos() {
        let config = ChaosConfig::light();
        assert!(config.is_enabled());
        assert!(config.cancel_probability > 0.0);
        assert!(config.delay_probability > 0.0);
    }

    #[test]
    fn config_heavy_has_higher_probabilities() {
        let light = ChaosConfig::light();
        let heavy = ChaosConfig::heavy();
        assert!(heavy.cancel_probability > light.cancel_probability);
        assert!(heavy.delay_probability > light.delay_probability);
        assert!(heavy.io_error_probability > light.io_error_probability);
    }

    #[test]
    fn config_builder_pattern() {
        let config = ChaosConfig::new(42)
            .with_cancel_probability(0.1)
            .with_delay_probability(0.2)
            .with_delay_range(Duration::from_millis(5)..Duration::from_millis(50))
            .with_io_error_probability(0.05)
            .with_io_error_kinds(vec![io::ErrorKind::ConnectionReset])
            .with_wakeup_storm_probability(0.01)
            .with_wakeup_storm_count(1..10)
            .with_budget_exhaust_probability(0.02);

        assert_eq!(config.seed, 42);
        assert!((config.cancel_probability - 0.1).abs() < f64::EPSILON);
        assert!((config.delay_probability - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.delay_range.start, Duration::from_millis(5));
        assert_eq!(config.delay_range.end, Duration::from_millis(50));
        assert!((config.io_error_probability - 0.05).abs() < f64::EPSILON);
        assert_eq!(config.io_error_kinds.len(), 1);
        assert!((config.wakeup_storm_probability - 0.01).abs() < f64::EPSILON);
        assert_eq!(config.wakeup_storm_count, 1..10);
        assert!((config.budget_exhaust_probability - 0.02).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_probability() {
        let _ = ChaosConfig::new(42).with_cancel_probability(1.5);
    }

    #[test]
    fn config_summary() {
        let config = ChaosConfig::new(42)
            .with_cancel_probability(0.1)
            .with_io_error_probability(0.05)
            .with_io_error_kinds(vec![std::io::ErrorKind::ConnectionReset]);
        let summary = config.summary();
        assert!(summary.contains("cancel:10.0%"));
        assert!(summary.contains("io_err:5.0%"));
    }

    #[test]
    fn rng_deterministic() {
        let config = ChaosConfig::new(42).with_cancel_probability(0.5);

        let mut rng1 = ChaosRng::from_config(&config);
        let mut rng2 = ChaosRng::from_config(&config);

        // Same seed produces same sequence
        for _ in 0..100 {
            assert_eq!(
                rng1.should_inject_cancel(&config),
                rng2.should_inject_cancel(&config)
            );
        }
    }

    /// Small seeds used to start xorshift64 near zero, so every run's first
    /// chaos decision fired (br-asupersync-6g0qlk). The first draws of seeds
    /// 0..256 must now spread over [0, 1).
    #[test]
    fn small_seeds_do_not_bias_the_first_draws() {
        for draw in 0..3 {
            let firsts: Vec<f64> = (0..256_u64)
                .map(|seed| {
                    let mut rng = ChaosRng::new(seed);
                    for _ in 0..draw {
                        let _ = rng.next_f64();
                    }
                    rng.next_f64()
                })
                .collect();
            let below_tenth = firsts.iter().filter(|value| **value < 0.1).count();
            let mean = firsts.iter().sum::<f64>() / 256.0;
            assert!(
                (8..=48).contains(&below_tenth),
                "draw {draw}: {below_tenth} of 256 seeds below 0.1"
            );
            assert!((0.4..0.6).contains(&mean), "draw {draw}: mean {mean}");
        }
    }

    #[test]
    fn rng_f64_range() {
        let mut rng = ChaosRng::new(42);
        for _ in 0..1000 {
            let val = rng.next_f64();
            assert!((0.0..1.0).contains(&val), "f64 out of range: {val}");
        }
    }

    #[test]
    fn rng_should_inject_bounds() {
        let mut rng = ChaosRng::new(42);

        // 0% probability never injects
        for _ in 0..100 {
            assert!(!rng.should_inject(0.0));
        }

        // 100% probability always injects
        for _ in 0..100 {
            assert!(rng.should_inject(1.0));
        }
    }

    #[test]
    fn rng_delay_generation() {
        let config = ChaosConfig::new(42)
            .with_delay_range(Duration::from_millis(10)..Duration::from_millis(100));

        let mut rng = config.rng();
        for _ in 0..100 {
            let delay = rng.next_delay(&config);
            assert!(delay >= Duration::from_millis(10));
            assert!(delay < Duration::from_millis(100));
        }
    }

    #[test]
    fn delay_probability_without_nonzero_delay_range_is_effectively_disabled() {
        let config = ChaosConfig::new(42)
            .with_delay_probability(1.0)
            .with_delay_range(Duration::ZERO..Duration::ZERO);
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_delay(&config),
                "delay chaos without a nonzero delay range must never inject"
            );
            assert_eq!(rng.next_delay(&config), Duration::ZERO);
        }
    }

    #[test]
    fn delay_probability_with_reversed_range_is_effectively_disabled() {
        let config = ChaosConfig::new(42)
            .with_delay_probability(1.0)
            .with_delay_range(Duration::from_millis(5)..Duration::from_millis(1));
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_delay(&config),
                "delay chaos with a reversed range must never inject"
            );
            assert_eq!(rng.next_delay(&config), Duration::ZERO);
        }
    }

    #[test]
    fn delay_probability_with_empty_positive_range_is_effectively_disabled() {
        let config = ChaosConfig::new(42)
            .with_delay_probability(1.0)
            .with_delay_range(Duration::from_millis(5)..Duration::from_millis(5));
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_delay(&config),
                "delay chaos with an empty range must never inject"
            );
            assert_eq!(rng.next_delay(&config), Duration::ZERO);
        }
    }

    #[test]
    fn rng_delay_generation_excludes_zero_when_positive_delays_are_possible() {
        let config = ChaosConfig::new(42).with_delay_range(Duration::ZERO..Duration::from_nanos(3));

        let mut rng = config.rng();
        for _ in 0..64 {
            let delay = rng.next_delay(&config);
            assert!(
                delay >= Duration::from_nanos(1),
                "delay {delay:?} should exclude zero when positive delays are possible"
            );
            assert!(
                delay < Duration::from_nanos(3),
                "delay {delay:?} should stay within configured range"
            );
        }
    }

    #[test]
    fn rng_delay_generation_handles_large_duration_ranges() {
        let start = Duration::from_secs(40_000_000_000);
        let end = start + Duration::from_secs(100);
        let config = ChaosConfig::new(42).with_delay_range(start..end);

        let mut rng = config.rng();
        for _ in 0..100 {
            let delay = rng.next_delay(&config);
            assert!(
                delay >= start,
                "delay {delay:?} should be >= start {start:?}"
            );
            assert!(delay < end, "delay {delay:?} should be < end {end:?}");
        }
    }

    #[test]
    fn rng_io_error_kind() {
        let config = ChaosConfig::new(42).with_io_error_kinds(vec![
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
        ]);

        let mut rng = config.rng();
        for _ in 0..100 {
            let kind = rng.next_io_error_kind(&config).unwrap();
            assert!(
                kind == io::ErrorKind::ConnectionReset || kind == io::ErrorKind::TimedOut,
                "Unexpected error kind: {kind:?}"
            );
        }
    }

    #[test]
    fn io_error_probability_without_kinds_is_effectively_disabled() {
        let config = ChaosConfig::new(42).with_io_error_probability(1.0);
        assert!(
            !config.is_enabled(),
            "io-error chaos without error kinds should not report enabled"
        );
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_io_error(&config),
                "io-error chaos without kinds must never inject"
            );
            assert!(
                rng.next_io_error_kind(&config).is_none(),
                "io-error chaos without kinds must not fabricate an error kind"
            );
        }
    }

    #[test]
    fn rng_wakeup_count() {
        let config = ChaosConfig::new(42).with_wakeup_storm_count(5..15);

        let mut rng = config.rng();
        for _ in 0..100 {
            let count = rng.next_wakeup_count(&config);
            assert!((5..15).contains(&count), "Count out of range: {count}");
        }
    }

    #[test]
    fn wakeup_probability_without_positive_count_is_effectively_disabled() {
        let config = ChaosConfig::new(42)
            .with_wakeup_storm_probability(1.0)
            .with_wakeup_storm_count(0..1);
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_wakeup_storm(&config, true),
                "wakeup storms without positive wake counts must never inject"
            );
            assert_eq!(rng.next_wakeup_count(&config), 0);
        }
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn wakeup_probability_with_reversed_count_range_is_effectively_disabled() {
        let config = ChaosConfig::new(42)
            .with_wakeup_storm_probability(1.0)
            .with_wakeup_storm_count(5..1);
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_wakeup_storm(&config, true),
                "wakeup storms with a reversed count range must never inject"
            );
            assert_eq!(rng.next_wakeup_count(&config), 0);
        }
    }

    #[test]
    fn wakeup_probability_with_empty_positive_count_range_is_effectively_disabled() {
        let config = ChaosConfig::new(42)
            .with_wakeup_storm_probability(1.0)
            .with_wakeup_storm_count(5..5);
        assert!(!config.is_enabled());
        assert_eq!(config.summary(), "off");

        let mut rng = config.rng();
        for _ in 0..32 {
            assert!(
                !rng.should_inject_wakeup_storm(&config, true),
                "wakeup storms with an empty count range must never inject"
            );
            assert_eq!(rng.next_wakeup_count(&config), 0);
        }
    }

    // br-asupersync-4so3w3: with probability 1.0 and a positive count
    // range, wakeup_storm must STILL be suppressed when the runtime
    // reports no open regions. Otherwise the chaos engine fabricates
    // a wakeup at quiescence — a schedule production cannot produce
    // and which silently masks the genuine bug a fuzz seed was
    // chasing.
    #[test]
    fn wakeup_storm_is_gated_on_at_least_one_open_region() {
        let config = ChaosConfig::new(42)
            .with_wakeup_storm_probability(1.0)
            .with_wakeup_storm_count(1..5);
        let mut rng = config.rng();

        // No open region -> never inject, regardless of probability.
        for _ in 0..64 {
            assert!(
                !rng.should_inject_wakeup_storm(&config, false),
                "wakeup storm must be suppressed when no region is open"
            );
        }

        // At least one open region -> probability=1.0 always injects.
        for _ in 0..64 {
            assert!(
                rng.should_inject_wakeup_storm(&config, true),
                "wakeup storm must fire when a region is open and probability is 1.0"
            );
        }
    }

    #[test]
    fn rng_wakeup_count_excludes_zero_when_positive_counts_are_possible() {
        let config = ChaosConfig::new(42).with_wakeup_storm_count(0..3);

        let mut rng = config.rng();
        for _ in 0..64 {
            let count = rng.next_wakeup_count(&config);
            assert!(count > 0, "wakeup storm count should exclude zero");
            assert!(count < 3, "count should stay within configured range");
        }
    }

    #[test]
    fn injection_point_applicable_chaos() {
        // TaskPoll can inject Cancel, Delay, and BudgetExhaust
        let applicable = InjectionPoint::TaskPoll.applicable_chaos();
        assert!(applicable.contains(&ChaosType::Cancel));
        assert!(applicable.contains(&ChaosType::Delay));
        assert!(applicable.contains(&ChaosType::BudgetExhaust));
        assert!(!applicable.contains(&ChaosType::IoError));

        // ReactorPoll can inject IoError and Delay
        let applicable = InjectionPoint::ReactorPoll.applicable_chaos();
        assert!(applicable.contains(&ChaosType::IoError));
        assert!(applicable.contains(&ChaosType::Delay));
        assert!(!applicable.contains(&ChaosType::Cancel));
    }

    #[test]
    fn stats_tracking() {
        let mut stats = ChaosStats::new();
        stats.record_cancel();
        stats.record_delay(Duration::from_millis(10));
        stats.record_io_error();
        stats.record_wakeup_storm(5);
        stats.record_budget_exhaust();
        stats.record_no_injection();
        stats.record_no_injection();

        assert_eq!(stats.cancellations, 1);
        assert_eq!(stats.delays, 1);
        assert_eq!(stats.total_delay, Duration::from_millis(10));
        assert_eq!(stats.io_errors, 1);
        assert_eq!(stats.wakeup_storms, 1);
        assert_eq!(stats.spurious_wakeups, 5);
        assert_eq!(stats.budget_exhaustions, 1);
        assert_eq!(stats.decision_points, 7);

        // 5 injections out of 7 decision points
        let rate = stats.injection_rate();
        assert!((rate - 5.0 / 7.0).abs() < 0.001);
    }

    #[test]
    fn stats_merge() {
        let mut stats1 = ChaosStats::new();
        stats1.record_cancel();
        stats1.record_cancel();

        let mut stats2 = ChaosStats::new();
        stats2.record_io_error();
        stats2.record_delay(Duration::from_millis(5));

        stats1.merge(&stats2);

        assert_eq!(stats1.cancellations, 2);
        assert_eq!(stats1.io_errors, 1);
        assert_eq!(stats1.delays, 1);
        assert_eq!(stats1.decision_points, 4);
    }

    #[test]
    fn pre_poll_outcomes_count_as_one_decision_point() {
        let mut stats = ChaosStats::new();
        stats.record_pre_poll_outcomes(true, Some(Duration::from_millis(2)), true);

        assert_eq!(stats.cancellations, 1);
        assert_eq!(stats.delays, 1);
        assert_eq!(stats.total_delay, Duration::from_millis(2));
        assert_eq!(stats.budget_exhaustions, 1);
        assert_eq!(stats.decision_points, 1);
    }

    #[test]
    fn stats_display() {
        let mut stats = ChaosStats::new();
        stats.record_cancel();
        stats.record_delay(Duration::from_millis(10));

        let display = format!("{stats}");
        assert!(display.contains("cancels: 1"));
        assert!(display.contains("delays: 1"));
    }

    // =========================================================================
    // Wave 48 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn injection_point_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let all = [
            InjectionPoint::SchedulerPoll,
            InjectionPoint::TaskPoll,
            InjectionPoint::ReactorPoll,
            InjectionPoint::WakerInvoke,
            InjectionPoint::BudgetCheck,
            InjectionPoint::TimerFire,
            InjectionPoint::SyncAcquire,
            InjectionPoint::ChannelSend,
            InjectionPoint::ChannelRecv,
        ];
        let mut set = HashSet::new();
        for ip in &all {
            let copied = *ip;
            let cloned = *ip;
            assert_eq!(copied, cloned);
            assert!(!format!("{ip:?}").is_empty());
            set.insert(*ip);
        }
        assert_eq!(set.len(), 9);
    }

    #[test]
    fn chaos_type_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let all = [
            ChaosType::Cancel,
            ChaosType::Delay,
            ChaosType::IoError,
            ChaosType::WakeupStorm,
            ChaosType::BudgetExhaust,
        ];
        let mut set = HashSet::new();
        for ct in &all {
            let copied = *ct;
            let cloned = *ct;
            assert_eq!(copied, cloned);
            set.insert(*ct);
        }
        assert_eq!(set.len(), 5);
        assert_ne!(ChaosType::Cancel, ChaosType::Delay);
    }

    #[test]
    fn chaos_stats_debug_clone_default() {
        let def = ChaosStats::default();
        assert_eq!(def.cancellations, 0);
        assert_eq!(def.delays, 0);
        assert_eq!(def.io_errors, 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("ChaosStats"), "{dbg}");
        let cloned = def;
        assert_eq!(cloned.cancellations, 0);
    }

    // Security regression test for DoS vulnerability br-asupersync-e51d48
    #[test]
    #[should_panic(
        expected = "wakeup storm count end (200000) must be <= 10000 to prevent DoS attacks"
    )]
    fn wakeup_storm_count_rejects_dos_attack() {
        let _ = ChaosConfig::new(42).with_wakeup_storm_count(0..200_000);
    }

    #[test]
    fn wakeup_storm_count_accepts_reasonable_values() {
        let config = ChaosConfig::new(42).with_wakeup_storm_count(1..1000);
        assert_eq!(config.wakeup_storm_count, 1..1000);
    }

    #[test]
    fn wakeup_storm_count_accepts_max_limit() {
        let config = ChaosConfig::new(42).with_wakeup_storm_count(1..10_000);
        assert_eq!(config.wakeup_storm_count, 1..10_000);
    }

    #[test]
    #[should_panic(
        expected = "wakeup storm count end (10001) must be <= 10000 to prevent DoS attacks"
    )]
    fn wakeup_storm_count_rejects_above_limit() {
        let _ = ChaosConfig::new(42).with_wakeup_storm_count(1..10_001);
    }

    #[test]
    fn wakeup_range_can_emit_positive_rejects_excessive_values() {
        // Should reject ranges that could cause DoS
        assert!(!wakeup_range_can_emit_positive(&(0..200_000)));
        assert!(!wakeup_range_can_emit_positive(&(1..100_001)));
        assert!(!wakeup_range_can_emit_positive(&(1..10_001)));

        // Should accept reasonable ranges
        assert!(wakeup_range_can_emit_positive(&(1..1000)));
        assert!(wakeup_range_can_emit_positive(&(0..10_000)));
    }
