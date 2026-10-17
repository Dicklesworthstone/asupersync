    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_normal_waker_lifecycle() {
        let mut oracle = WakerDedupOracle::with_defaults();

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        // Register waker
        oracle.on_waker_registered(waker_id, channel_id, true, None);

        // Request wake
        oracle.on_waker_wake_requested(waker_id, "channel_send".to_string(), None);

        // Actually wake
        oracle.on_waker_actually_woken(waker_id, None);

        // Drop waker
        oracle.on_waker_dropped(waker_id);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_wakers_registered, 1);
        assert_eq!(stats.total_wakers_woken, 1);
        assert_eq!(stats.total_wakers_dropped, 1);
        assert_eq!(stats.total_violations, 0);
    }

    #[test]
    fn test_double_wakeup_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);
        oracle.on_waker_actually_woken(waker_id, None);
        oracle.on_waker_actually_woken(waker_id, None); // This should be a violation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::DoubleWakeup { .. }
        ));
    }

    #[test]
    fn test_spurious_wakeup_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);

        // Wakeup without registration
        oracle.on_waker_actually_woken(waker_id, None);

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::SpuriousWakeup { .. }
        ));
    }

    #[test]
    fn test_use_after_drop_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);
        oracle.on_waker_dropped(waker_id);
        oracle.on_waker_actually_woken(waker_id, None); // Use after drop

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::UseAfterDrop { .. }
        ));
    }

    #[test]
    fn test_queued_state_verification() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);
        oracle.verify_queued_state(waker_id, false, None); // Inconsistent state

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::InconsistentQueuedState { .. }
        ));
    }

    #[test]
    fn test_registration_race_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            race_detection_window_ms: 100, // 100ms window
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, true, None);

        // Simulate recent wakeup
        oracle
            .recent_wakeups
            .push_back((waker_id, waker_event_now()));

        // Register again soon after wakeup (simulating race)
        oracle.on_waker_registered(waker_id, channel_id, true, None);

        let _violations = oracle.check_for_violations().unwrap();
        // May or may not detect race depending on timing
    }

    #[test]
    fn logical_time_makes_registration_race_window_exact() {
        fn registration_races_at(reregistered_at: Time) -> usize {
            let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
                enforcement: EnforcementMode::Collect,
                race_detection_window_ms: 5,
                ..Default::default()
            });
            let waker_id = WakerId(7);
            let channel_id = ChannelId(11);

            oracle.set_logical_time(Time::ZERO);
            oracle.on_waker_registered(waker_id, channel_id, true, None);
            oracle.set_logical_time(Time::from_millis(20));
            oracle.on_waker_actually_woken(waker_id, None);
            oracle.set_logical_time(reregistered_at);
            oracle.on_waker_registered(waker_id, channel_id, true, None);

            oracle
                .check_for_violations()
                .expect("collect mode returns violations")
                .iter()
                .filter(|violation| {
                    matches!(violation, WakerDedupViolation::RegistrationRace { .. })
                })
                .count()
        }

        assert_eq!(registration_races_at(Time::from_millis(24)), 1);
        assert_eq!(registration_races_at(Time::from_millis(26)), 0);
    }

    #[test]
    fn logical_time_activates_lost_wakeup_and_leak_thresholds() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        oracle.set_logical_time(Time::ZERO);
        oracle.on_waker_registered(WakerId(1), ChannelId(1), true, None);

        oracle.set_logical_time(Time::from_secs(31));
        let violations = oracle
            .check_for_violations()
            .expect("collect mode returns violations");
        assert!(matches!(
            violations.as_slice(),
            [WakerDedupViolation::LostWakeup { .. }]
        ));

        oracle.set_logical_time(Time::from_secs(61));
        let violations = oracle
            .check_for_violations()
            .expect("collect mode returns violations");
        assert_eq!(
            violations
                .iter()
                .filter(|violation| matches!(violation, WakerDedupViolation::WakerLeak { .. }))
                .count(),
            1
        );
        assert_eq!(oracle.statistics().total_lost_wakeups, 1);
        assert_eq!(oracle.statistics().total_leaks, 1);
        assert_eq!(oracle.statistics().active_wakers, 0);
    }

    #[test]
    fn logical_time_violation_order_is_replay_stable() {
        fn lost_wakeup_order() -> Vec<WakerId> {
            let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
                enforcement: EnforcementMode::Collect,
                ..Default::default()
            });
            oracle.set_logical_time(Time::ZERO);
            for id in [9, 2, 17, 4, 31, 6] {
                oracle.on_waker_registered(WakerId(id), ChannelId(id % 3), true, None);
            }
            oracle.set_logical_time(Time::from_secs(31));
            oracle
                .check_for_violations()
                .expect("collect mode returns violations")
                .into_iter()
                .filter_map(|violation| match violation {
                    WakerDedupViolation::LostWakeup { waker_id, .. } => Some(waker_id),
                    _ => None,
                })
                .collect()
        }

        let expected = lost_wakeup_order();
        assert_eq!(expected.len(), 6);
        for _ in 0..16 {
            assert_eq!(lost_wakeup_order(), expected);
        }
    }

    #[test]
    fn test_waker_leak_detection() {
        let mut oracle = WakerDedupOracle::new(WakerDedupConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        // Register waker with old timestamp
        oracle.on_waker_registered(waker_id, channel_id, true, None);

        // Manually set old registration time to trigger leak detection
        if let Some(state) = oracle.wakers.get_mut(&waker_id) {
            state.registered_at = waker_event_now() - Duration::from_secs(120); // 2 minutes ago
        }

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            WakerDedupViolation::WakerLeak { .. }
        ));
    }

    #[test]
    fn test_violation_record_creation() {
        let config = WakerDedupConfig {
            include_stack_traces: true,
            enable_replay_commands: true,
            structured_logging: false,
            ..Default::default()
        };

        let violation = WakerDedupViolation::LostWakeup {
            waker_id: WakerId(1),
            channel_id: ChannelId(1),
            registered_at: waker_event_now(),
            expected_wake_at: waker_event_now(),
            trace_id: Some(DistTraceId::new_for_test(1)),
        };

        let record = ViolationRecord::new(violation, &config);

        assert!(record.trace_id.is_some());
        assert!(record.stack_trace.is_some());
        assert!(record.replay_command.is_some());
    }

    #[test]
    fn test_oracle_reset() {
        let mut oracle = WakerDedupOracle::with_defaults();

        // Add some state
        oracle.on_waker_registered(WakerId(1), ChannelId(1), true, None);
        oracle.on_waker_actually_woken(WakerId(999), None); // Spurious wakeup

        // Verify state exists
        assert!(!oracle.wakers.is_empty());
        assert!(!oracle.violations.is_empty());

        // Reset and verify clean state
        oracle.reset();

        assert!(oracle.wakers.is_empty());
        assert!(oracle.violations.is_empty());
        assert_eq!(oracle.statistics().total_wakers_registered, 0);
    }
