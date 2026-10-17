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
    use crate::types::{RegionId, TaskId, Time};

    #[test]
    fn test_normal_cancellation_flow() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        // Normal flow: Requested → Cancelling → Finalizing → Completed
        let reason = CancelReason::user("test_cancel");

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Completed, reason),
            now,
        );

        oracle.notify_task_completed(task_id, now);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.witnesses_processed, 4);
    }

    #[test]
    fn test_premature_completion_detection() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        let reason = CancelReason::user("test_cancel");

        // Task gets cancelled but completes prematurely
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Requested, reason),
            now,
        );

        oracle.notify_task_completed(task_id, now);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::PrematureCompletion { .. }
        ));
    }

    #[test]
    fn test_invalid_transition_detection() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        let reason = CancelReason::user("test_cancel");

        // Normal start
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            now,
        );

        // Invalid transition: Finalizing → Cancelling (backwards)
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Cancelling, reason),
            now,
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::InvalidTransition { .. }
        ));
    }

    #[test]
    fn test_missed_finalization_detection() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        let reason = CancelReason::user("test_cancel");

        // Skip finalization: Requested → Cancelling → Completed (missing Finalizing)
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Completed, reason),
            now,
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::MissedFinalization { .. }
        ));
    }

    #[test]
    fn test_concurrent_cancellation_safety() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("concurrent_test");

        // Simulate concurrent witnesses for the same task
        std::thread::scope(|s| {
            for i in 0..4 {
                let oracle = &oracle;
                let reason = reason.clone();
                s.spawn(move || {
                    oracle.notify_cancel_witness(
                        CancelWitness::new(
                            task_id,
                            region_id,
                            1,
                            match i {
                                0 => CancelPhase::Requested,
                                1 => CancelPhase::Cancelling,
                                2 => CancelPhase::Finalizing,
                                _ => CancelPhase::Completed,
                            },
                            reason,
                        ),
                        now + Duration::from_nanos(i * 1000),
                    );
                });
            }
        });

        // Should handle concurrent updates without panicking
        let stats = oracle.get_statistics();
        assert!(stats.witnesses_processed >= 4);
    }

    #[test]
    fn test_multiple_task_tracking() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("multi_task_test");

        // Track multiple tasks through normal cancellation flow
        for i in 0..5 {
            let task_id = TaskId::new_for_test(i, 0);

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Requested,
                    reason.clone(),
                ),
                now,
            );

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Cancelling,
                    reason.clone(),
                ),
                now + Duration::from_nanos(1000),
            );

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Finalizing,
                    reason.clone(),
                ),
                now + Duration::from_nanos(2000),
            );

            oracle.notify_cancel_witness(
                CancelWitness::new(
                    task_id,
                    region_id,
                    1,
                    CancelPhase::Completed,
                    reason.clone(),
                ),
                now + Duration::from_nanos(3000),
            );
        }

        let stats = oracle.get_statistics();
        assert_eq!(stats.witnesses_processed, 20); // 5 tasks × 4 witnesses each
        assert_eq!(stats.violations_detected, 0); // No violations in normal flow
    }

    #[test]
    fn test_stuck_cancellation_detection() {
        init_test_logging();

        let config = CancelCorrectnessConfig {
            max_phase_duration_ns: 1000, // Very short timeout for testing
            ..Default::default()
        };
        let oracle = CancelCorrectnessOracle::new(config);
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("stuck_test");

        // Task gets stuck in Cancelling phase
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Cancelling, reason),
            now + Duration::from_nanos(100),
        );

        // Check for stuck cancellations after timeout period
        oracle.check_stuck_cancellations(now + Duration::from_nanos(2000));

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::StuckCancellation { .. }
        ));
    }

    #[test]
    fn test_stuck_cancellation_is_reported_once_until_phase_changes() {
        init_test_logging();

        let config = CancelCorrectnessConfig {
            max_phase_duration_ns: 1000,
            ..Default::default()
        };
        let oracle = CancelCorrectnessOracle::new(config);
        let task_id = TaskId::new_for_test(41, 0);
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("stuck-once");

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Cancelling, reason),
            now + Duration::from_nanos(100),
        );

        oracle.check_stuck_cancellations(now + Duration::from_nanos(2000));
        oracle.check_stuck_cancellations(now + Duration::from_nanos(3000));

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);
        assert_eq!(oracle.get_recent_violations(10).len(), 1);
    }

    #[test]
    fn test_repeated_same_phase_witnesses_do_not_mask_stuck_detection() {
        init_test_logging();

        let config = CancelCorrectnessConfig {
            max_phase_duration_ns: 1000,
            ..Default::default()
        };
        let oracle = CancelCorrectnessOracle::new(config);
        let task_id = TaskId::new_for_test(42, 0);
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("same-phase-repeat");

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            now + Duration::from_nanos(100),
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Cancelling, reason),
            now + Duration::from_nanos(1500),
        );

        oracle.check_stuck_cancellations(now + Duration::from_nanos(2000));

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::StuckCancellation {
                phase: CancelPhase::Cancelling,
                ..
            }
        ));
    }

    #[test]
    fn test_violation_statistics_tracking() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;
        let reason = CancelReason::user("stats_test");

        // Create several violation types

        // 1. Premature completion
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            now,
        );
        oracle.notify_task_completed(task_id, now);

        // 2. Invalid transition (different task)
        let task_id2 = TaskId::new_for_test(2, 0);
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id2,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            now,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id2, region_id, 1, CancelPhase::Cancelling, reason),
            now,
        );

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected >= 2);

        let violations = oracle.get_recent_violations(10);
        assert!(!violations.is_empty());
    }

    #[test]
    fn test_oracle_configuration() {
        init_test_logging();

        // Test default configuration
        let oracle = CancelCorrectnessOracle::with_default_config();
        let stats = oracle.get_statistics();
        assert_eq!(stats.witnesses_processed, 0);
        assert_eq!(stats.violations_detected, 0);

        // Test custom configuration
        let config = CancelCorrectnessConfig {
            max_phase_duration_ns: 5000,
            max_violations: 50,
            panic_on_violation: false,
            capture_stack_traces: false,
            max_stack_trace_depth: 16,
        };

        let oracle = CancelCorrectnessOracle::new(config);
        let task_id = TaskId::testing_default();
        let region_id = RegionId::testing_default();
        let now = Time::ZERO;

        // Normal flow should work with custom config
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                CancelReason::user("config_test"),
            ),
            now,
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.witnesses_processed, 1);
    }

    #[test]
    fn test_tracked_tasks_expose_cancel_epoch_and_reason() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(9, 0);
        let region_id = RegionId::testing_default();
        let requested_at = Time::from_nanos(1234);
        let updated_at = Time::from_nanos(5678);
        let requested_reason = CancelReason::user("snapshot-test");
        let updated_reason = CancelReason::timeout().with_message("snapshot-updated");

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                7,
                CancelPhase::Requested,
                requested_reason,
            ),
            requested_at,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                7,
                CancelPhase::Cancelling,
                updated_reason.clone(),
            ),
            updated_at,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);

        let snapshot = &tracked[0];
        assert_eq!(snapshot.task_id, task_id);
        assert_eq!(snapshot.region_id, region_id);
        assert_eq!(snapshot.current_phase, CancelPhase::Cancelling);
        assert_eq!(snapshot.epoch, 7);
        assert_eq!(snapshot.cancel_reason, updated_reason);
        assert_eq!(snapshot.last_transition, updated_at);
        assert_eq!(snapshot.witness_history_len, 2);
    }

    #[test]
    fn test_epoch_mismatch_records_validation_failure_without_mutating_state() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(43, 0);
        let region_id = RegionId::testing_default();
        let requested_at = Time::from_nanos(10);
        let invalid_at = Time::from_nanos(20);
        let reason = CancelReason::timeout();

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                7,
                CancelPhase::Requested,
                reason.clone(),
            ),
            requested_at,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 8, CancelPhase::Cancelling, reason),
            invalid_at,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].epoch, 7);
        assert_eq!(tracked[0].current_phase, CancelPhase::Requested);
        assert_eq!(tracked[0].last_transition, requested_at);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::WitnessValidationFailed {
                error: CancelWitnessError::EpochMismatch,
                ..
            }
        ));
    }

    #[test]
    fn test_reason_weakening_records_validation_failure_without_mutating_state() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(44, 0);
        let region_id = RegionId::testing_default();
        let requested_at = Time::from_nanos(10);
        let invalid_at = Time::from_nanos(20);
        let stronger_reason = CancelReason::timeout();
        let weaker_reason = CancelReason::user("weaker");

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                stronger_reason.clone(),
            ),
            requested_at,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                weaker_reason,
            ),
            invalid_at,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].current_phase, CancelPhase::Requested);
        assert_eq!(tracked[0].cancel_reason, stronger_reason);
        assert_eq!(tracked[0].last_transition, requested_at);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::WitnessValidationFailed {
                error: CancelWitnessError::ReasonWeakened { .. },
                ..
            }
        ));
    }

    #[test]
    fn test_skipping_cancelling_phase_records_invalid_transition_without_mutating_state() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(47, 0);
        let region_id = RegionId::testing_default();
        let requested_at = Time::from_nanos(10);
        let invalid_at = Time::from_nanos(20);
        let reason = CancelReason::timeout();

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            requested_at,
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Finalizing, reason),
            invalid_at,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].current_phase, CancelPhase::Requested);
        assert_eq!(tracked[0].last_transition, requested_at);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::InvalidTransition {
                task_id: observed_task,
                region_id: observed_region,
                from_phase: CancelPhase::Requested,
                to_phase: CancelPhase::Finalizing,
                transition_time,
                ..
            } if observed_task == task_id && observed_region == region_id && transition_time == invalid_at
        ));
    }

    #[test]
    fn test_initial_midstream_witness_is_accepted_without_violation() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(45, 0);
        let region_id = RegionId::testing_default();
        let now = Time::from_nanos(10);
        let reason = CancelReason::timeout();

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            now,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].task_id, task_id);
        assert_eq!(tracked[0].region_id, region_id);
        assert_eq!(tracked[0].current_phase, CancelPhase::Cancelling);
        assert_eq!(tracked[0].epoch, 1);
        assert_eq!(tracked[0].cancel_reason, reason);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
    }

    #[test]
    fn test_initial_completed_witness_is_accepted_without_violation() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(451, 0);
        let region_id = RegionId::testing_default();
        let witness_at = Time::from_nanos(10);
        let completed_at = Time::from_nanos(20);
        let reason = CancelReason::timeout();

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Completed,
                reason.clone(),
            ),
            witness_at,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].current_phase, CancelPhase::Completed);
        assert_eq!(tracked[0].last_transition, witness_at);
        assert_eq!(tracked[0].cancel_reason, reason);

        oracle.notify_task_completed(task_id, completed_at);

        assert!(oracle.tracked_tasks().is_empty());
        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
    }

    #[test]
    fn test_initial_witness_rejects_zero_epoch_without_poisoning_state() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(46, 0);
        let region_id = RegionId::testing_default();
        let invalid_at = Time::from_nanos(10);
        let valid_at = Time::from_nanos(20);
        let reason = CancelReason::timeout();

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                0,
                CancelPhase::Requested,
                reason.clone(),
            ),
            invalid_at,
        );

        assert!(oracle.tracked_tasks().is_empty());

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Requested, reason),
            valid_at,
        );

        let tracked = oracle.tracked_tasks();
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].epoch, 1);
        assert_eq!(tracked[0].last_transition, valid_at);

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::InvalidInitialWitness {
                phase: CancelPhase::Requested,
                epoch: 0,
                kind: InvalidInitialWitnessKind::ZeroEpoch,
                ..
            }
        ));
    }

    #[test]
    fn test_late_requested_witness_after_completion_does_not_reopen_task_state() {
        init_test_logging();

        let oracle = CancelCorrectnessOracle::with_default_config();
        let task_id = TaskId::new_for_test(48, 0);
        let region_id = RegionId::testing_default();
        let reason = CancelReason::timeout();

        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Requested,
                reason.clone(),
            ),
            Time::from_nanos(10),
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Cancelling,
                reason.clone(),
            ),
            Time::from_nanos(20),
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Finalizing,
                reason.clone(),
            ),
            Time::from_nanos(30),
        );
        oracle.notify_cancel_witness(
            CancelWitness::new(
                task_id,
                region_id,
                1,
                CancelPhase::Completed,
                reason.clone(),
            ),
            Time::from_nanos(40),
        );
        oracle.notify_task_completed(task_id, Time::from_nanos(50));

        oracle.notify_cancel_witness(
            CancelWitness::new(task_id, region_id, 1, CancelPhase::Requested, reason),
            Time::from_nanos(60),
        );

        assert!(oracle.tracked_tasks().is_empty());

        let violations = oracle.get_recent_violations(1);
        assert!(matches!(
            violations[0],
            CancelCorrectnessViolation::WitnessAfterCompletion {
                task_id: observed_task,
                region_id: observed_region,
                phase: CancelPhase::Requested,
                epoch: 1,
                observed_at,
                ..
            } if observed_task == task_id
                && observed_region == region_id
                && observed_at == Time::from_nanos(60)
        ));
    }
