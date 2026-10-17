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
    fn test_reservation_lifecycle_happy_path() {
        let mut oracle = ChannelAtomicityOracle::with_defaults();

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        // Create reservation
        oracle.on_reservation_created(reservation_id, channel_id, None);

        // Commit reservation
        oracle.on_reservation_committed(reservation_id, 100);

        // Should have no violations
        let violations = oracle.check_for_violations().unwrap();
        assert!(violations.is_empty());

        let stats = oracle.statistics();
        assert_eq!(stats.total_reservations_created, 1);
        assert_eq!(stats.total_reservations_committed, 1);
        assert_eq!(stats.total_violations, 0);
    }

    #[test]
    fn test_double_commit_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        oracle.on_reservation_created(reservation_id, channel_id, None);
        oracle.on_reservation_committed(reservation_id, 100);
        oracle.on_reservation_committed(reservation_id, 200); // This should be a violation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::DoubleCommit { .. }
        ));
    }

    #[test]
    fn test_use_after_abort_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        oracle.on_reservation_created(reservation_id, channel_id, None);
        oracle.on_reservation_aborted(reservation_id, "cancelled".to_string());
        oracle.on_reservation_committed(reservation_id, 100); // This should be a violation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::UseAfterAbort { .. }
        ));
    }

    #[test]
    fn test_reservation_leak_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            max_reservation_age_seconds: 0, // Immediate leak detection
            ..Default::default()
        });

        let reservation_id = ReservationId(1);
        let channel_id = ChannelId(1);

        oracle.on_reservation_created(reservation_id, channel_id, None);

        // Let some time pass
        std::thread::sleep(Duration::from_millis(10));

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::ReservationLeak { .. }
        ));
    }

    #[test]
    fn test_spurious_wakeup_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);

        oracle.on_waker_registered(waker_id, channel_id, None);
        oracle.on_waker_wakeup(waker_id, SystemTime::now()); // Wakeup without expectation

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::SpuriousWakeup { .. }
        ));
    }

    #[test]
    fn test_lost_wakeup_detection() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let waker_id = WakerId(1);
        let channel_id = ChannelId(1);
        let now = SystemTime::now();

        oracle.on_waker_registered(waker_id, channel_id, None);
        oracle.on_waker_expected(waker_id, now);

        // Simulate significant delay
        let delayed_wakeup = now + Duration::from_millis(200);
        oracle.on_waker_wakeup(waker_id, delayed_wakeup);

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::LostWakeup { .. }
        ));
    }

    #[test]
    fn test_data_loss_on_cancel() {
        let mut oracle = ChannelAtomicityOracle::new(ChannelAtomicityConfig {
            enforcement: EnforcementMode::Collect,
            ..Default::default()
        });

        let channel_id = ChannelId(1);
        oracle.on_cancel_data_loss(channel_id, 1024, None);

        let violations = oracle.check_for_violations().unwrap();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ChannelAtomicityViolation::DataLossOnCancel { .. }
        ));
    }

    #[test]
    fn test_violation_record_creation() {
        let config = ChannelAtomicityConfig {
            include_stack_traces: true,
            enable_replay_commands: true,
            structured_logging: false,
            ..Default::default()
        };

        let violation = ChannelAtomicityViolation::ReservationLeak {
            reservation_id: ReservationId(1),
            channel_id: ChannelId(1),
            created_at: SystemTime::now(),
            trace_id: Some(DistTraceId::new_for_test(1)),
        };

        let record = ViolationRecord::new(violation, &config);

        assert!(record.trace_id.is_some());
        assert!(record.stack_trace.is_some());
        assert!(record.replay_command.is_some());
    }

    #[test]
    fn test_oracle_reset() {
        let mut oracle = ChannelAtomicityOracle::with_defaults();

        // Add some state
        oracle.on_reservation_created(ReservationId(1), ChannelId(1), None);
        oracle.on_waker_registered(WakerId(1), ChannelId(1), None);
        oracle.on_cancel_data_loss(ChannelId(1), 100, None);

        // Verify state exists
        assert!(!oracle.reservations.is_empty());
        assert!(!oracle.wakers.is_empty());
        assert!(!oracle.violations.is_empty());

        // Reset and verify clean state
        oracle.reset();

        assert!(oracle.reservations.is_empty());
        assert!(oracle.wakers.is_empty());
        assert!(oracle.violations.is_empty());
        assert_eq!(oracle.statistics().total_reservations_created, 0);
    }
