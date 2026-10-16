    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;

    #[test]
    fn test_normal_epoch_transitions() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();
        let now = Time::ZERO;

        // All modules start at epoch 1
        assert_eq!(
            oracle.module_epoch(RuntimeModule::Scheduler),
            Some(EpochId::new(1))
        );

        // Normal transition for scheduler
        oracle.notify_epoch_transition_start(RuntimeModule::Scheduler, EpochId::new(1), now);
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(2),
            Time::from_nanos(1000),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.transitions_tracked, 1);
        assert_eq!(
            oracle.module_epoch(RuntimeModule::Scheduler),
            Some(EpochId::new(2))
        );
    }

    #[test]
    fn test_epoch_skew_detection() {
        init_test_logging();

        let config = RuntimeEpochConfig {
            max_epoch_skew: 1, // Very low tolerance for testing
            ..Default::default()
        };
        let oracle = RuntimeEpochOracle::new(config);
        let now = Time::ZERO;

        // Advance scheduler to epoch 3
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(3), now);

        // Leave region table at epoch 1 - should cause skew violation
        oracle.check_epoch_consistency(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);
        assert_eq!(stats.epoch_variance, 2); // epochs 1 and 3

        let violations = oracle.get_recent_violations(1);
        assert!(!violations.is_empty());
        assert!(matches!(
            violations[0],
            RuntimeEpochViolation::EpochSkew { .. }
        ));
    }

    #[test]
    fn test_slow_transition_detection() {
        init_test_logging();

        let config = RuntimeEpochConfig {
            max_transition_duration_ns: 100_000, // 100μs max for testing
            ..Default::default()
        };
        let oracle = RuntimeEpochOracle::new(config);
        let now = Time::ZERO;

        // Start transition
        oracle.notify_epoch_transition_start(RuntimeModule::Scheduler, EpochId::new(1), now);

        // Complete much later (should trigger violation)
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(2),
            Time::from_nanos(1_000_000), // 1ms later
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            RuntimeEpochViolation::SlowTransition { .. }
        ));
    }

    #[test]
    fn test_stale_epoch_update_detection() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();
        let now = Time::ZERO;

        // Advance scheduler to epoch 2 (the next valid epoch). Jumping past
        // the expected next epoch would itself record a `MissedTransition`
        // violation and inflate the count beyond what this test targets.
        oracle.notify_epoch_transition_complete(RuntimeModule::Scheduler, EpochId::new(2), now);

        // Try to update using old epoch 1 - should trigger stale update violation
        oracle.notify_epoch_update(RuntimeModule::Scheduler, EpochId::new(1), now);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            RuntimeEpochViolation::StaleEpochUpdate { .. }
        ));
    }

    #[test]
    fn test_oracle_check_method() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        // Normal operation should pass
        let result = oracle.check(Time::ZERO);
        assert!(result.is_ok());

        // Create a violation by advancing one module too far
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(10),
            Time::ZERO,
        );

        // Check should now return error
        let result = oracle.check(Time::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_reset() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        // Advance some epochs and create violations
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(5),
            Time::ZERO,
        );
        oracle.check_epoch_consistency(Time::ZERO);

        let stats_before = oracle.get_statistics();
        assert!(stats_before.violations_detected > 0);
        assert!(stats_before.global_epoch.as_u64() > 1);

        // Reset should restore initial state
        oracle.reset();

        let stats_after = oracle.get_statistics();
        assert_eq!(stats_after.violations_detected, 0);
        assert_eq!(stats_after.transitions_tracked, 0);
        assert_eq!(stats_after.global_epoch.as_u64(), 1);
        assert_eq!(stats_after.epoch_variance, 0);

        // All modules should be back at epoch 1
        for &module in RuntimeModule::all_modules() {
            assert_eq!(oracle.module_epoch(module), Some(EpochId::new(1)));
        }
    }

    #[test]
    fn test_global_epoch_tracking() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();
        assert_eq!(oracle.global_epoch().as_u64(), 1);

        // Advance some modules
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(3),
            Time::ZERO,
        );
        oracle.notify_epoch_transition_complete(
            RuntimeModule::TaskTable,
            EpochId::new(2),
            Time::ZERO,
        );

        // Global epoch should be the maximum
        assert_eq!(oracle.global_epoch().as_u64(), 3);
    }

    #[test]
    fn test_all_modules_tracked() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        // Verify all expected modules are tracked
        let module_states = oracle.get_module_states();
        assert_eq!(module_states.len(), RuntimeModule::all_modules().len());

        for &expected_module in RuntimeModule::all_modules() {
            assert!(
                module_states
                    .iter()
                    .any(|(module, _, _)| *module == expected_module)
            );
        }
    }

    #[test]
    fn test_stale_transition_start_is_ignored_and_recorded() {
        init_test_logging();

        let config = RuntimeEpochConfig {
            max_transition_duration_ns: 100,
            ..Default::default()
        };
        let oracle = RuntimeEpochOracle::new(config);

        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(2),
            Time::from_nanos(10),
        );
        oracle.notify_epoch_transition_start(
            RuntimeModule::Scheduler,
            EpochId::new(1),
            Time::from_nanos(20),
        );

        oracle.check_epoch_consistency(Time::from_nanos(1_000));

        assert!(
            !oracle
                .get_recent_violations(4)
                .iter()
                .any(|violation| matches!(violation, RuntimeEpochViolation::SlowTransition { .. })),
            "stale start witness must not manufacture an in-flight slow transition"
        );
        assert!(matches!(
            oracle.get_recent_violations(1).first(),
            Some(RuntimeEpochViolation::MissedTransition {
                module: RuntimeModule::Scheduler,
                expected_epoch,
                actual_epoch,
                ..
            }) if *expected_epoch == EpochId::new(2) && *actual_epoch == EpochId::new(1)
        ));
    }

    #[test]
    fn test_backward_transition_completion_does_not_rewind_epoch() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(2),
            Time::from_nanos(10),
        );
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(1),
            Time::from_nanos(20),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.transitions_tracked, 1);
        assert_eq!(
            oracle.module_epoch(RuntimeModule::Scheduler),
            Some(EpochId::new(2))
        );
        assert!(matches!(
            oracle.get_recent_violations(1).first(),
            Some(RuntimeEpochViolation::OrderViolation {
                first_module: RuntimeModule::Scheduler,
                first_epoch,
                second_module: RuntimeModule::Scheduler,
                second_epoch,
                ..
            }) if *first_epoch == EpochId::new(2) && *second_epoch == EpochId::new(1)
        ));
    }

    #[test]
    fn test_skipped_forward_transition_records_missing_transition_and_advances() {
        init_test_logging();

        let oracle = RuntimeEpochOracle::with_default_config();

        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(4),
            Time::from_nanos(10),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.transitions_tracked, 1);
        assert_eq!(
            oracle.module_epoch(RuntimeModule::Scheduler),
            Some(EpochId::new(4))
        );
        assert!(matches!(
            oracle.get_recent_violations(1).first(),
            Some(RuntimeEpochViolation::MissedTransition {
                module: RuntimeModule::Scheduler,
                expected_epoch,
                actual_epoch,
                ..
            }) if *expected_epoch == EpochId::new(2) && *actual_epoch == EpochId::new(4)
        ));
    }

    #[test]
    fn test_slow_transition_reports_actual_from_epoch() {
        init_test_logging();

        let config = RuntimeEpochConfig {
            max_transition_duration_ns: 50,
            ..Default::default()
        };
        let oracle = RuntimeEpochOracle::new(config);

        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(5),
            Time::from_nanos(10),
        );
        oracle.notify_epoch_transition_start(
            RuntimeModule::Scheduler,
            EpochId::new(5),
            Time::from_nanos(20),
        );
        oracle.notify_epoch_transition_complete(
            RuntimeModule::Scheduler,
            EpochId::new(8),
            Time::from_nanos(200),
        );

        let violations = oracle.get_recent_violations(2);
        assert!(violations.iter().any(|violation| {
            matches!(
                violation,
                RuntimeEpochViolation::SlowTransition {
                    module: RuntimeModule::Scheduler,
                    from_epoch,
                    to_epoch,
                    transition_duration_ns: 180,
                    ..
                } if *from_epoch == EpochId::new(5) && *to_epoch == EpochId::new(8)
            )
        }));
        assert!(violations.iter().any(|violation| {
            matches!(
                violation,
                RuntimeEpochViolation::MissedTransition {
                    module: RuntimeModule::Scheduler,
                    expected_epoch,
                    actual_epoch,
                    ..
                } if *expected_epoch == EpochId::new(6) && *actual_epoch == EpochId::new(8)
            )
        }));
    }
