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
    fn test_normal_operation_no_violations() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();
        let now = Time::ZERO;

        // Add some work items
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::testing_default()),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            now,
        );

        // Complete them quickly
        oracle.on_work_items_completed("finalizers", 1, Time::from_nanos(1000));

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.work_items_tracked, 1);
        assert_eq!(stats.completions_tracked, 1);
    }

    #[test]
    fn test_debt_threshold_violation() {
        init_test_logging();

        let config = CancelDebtConfig {
            max_debt_items: 5, // Low threshold for testing
            ..Default::default()
        };
        let oracle = CancelDebtOracle::new(config);
        let now = Time::ZERO;

        // Add more items than the threshold
        for i in 0..10 {
            oracle.on_work_item_added(
                "finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution,
                Time::from_nanos(i * 1000),
            );
        }

        // Check for violations
        oracle.check_debt_accumulation(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);

        let violations = oracle.get_recent_violations(5);
        assert!(!violations.is_empty());
        assert!(matches!(
            violations[0],
            CancelDebtViolation::DebtThresholdExceeded { .. }
        ));
    }

    #[test]
    fn test_debt_accumulation_rate_violation() {
        init_test_logging();

        let config = CancelDebtConfig {
            max_debt_rate_per_sec: 1.0,           // Very low rate for testing
            measurement_window_ns: 1_000_000_000, // 1 second
            ..Default::default()
        };
        let oracle = CancelDebtOracle::new(config);

        // Add items rapidly without completing them
        for i in 0..10 {
            oracle.on_work_item_added(
                "finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution,
                Time::from_nanos(i * 100_000_000), // 100ms intervals
            );
        }

        // Check within the measurement window so that rapidly-added items
        // are counted by `debt_accumulation_rate` (which only considers
        // items with `created_at >= now - window`).
        let now = Time::from_nanos(1_000_000_000); // 1 second later (end of window)
        oracle.check_debt_accumulation(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);

        let violations = oracle.get_recent_violations(5);
        assert!(!violations.is_empty());
        // Should have both threshold and rate violations
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CancelDebtViolation::DebtAccumulationTooFast { .. }))
        );
    }

    #[test]
    fn test_cleanup_stall_detection() {
        init_test_logging();

        let config = CancelDebtConfig {
            measurement_window_ns: 1_000_000_000, // 1 second
            ..Default::default()
        };
        let oracle = CancelDebtOracle::new(config);

        // Add some work
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::testing_default()),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            Time::ZERO,
        );

        // Complete one item initially
        oracle.on_work_items_completed("finalizers", 1, Time::from_nanos(100_000_000));

        // Add more work but don't complete it
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::new_for_test(2, 0)),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            Time::from_nanos(500_000_000),
        );

        // Check after a long stall (3 seconds later)
        let now = Time::from_nanos(3_500_000_000);
        oracle.check_debt_accumulation(now);

        let stats = oracle.get_statistics();
        assert!(stats.violations_detected > 0);

        let violations = oracle.get_recent_violations(5);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CancelDebtViolation::CleanupStall { .. }))
        );
    }

    #[test]
    fn test_oracle_check_method() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();

        // Normal operation should pass
        let result = oracle.check(Time::ZERO);
        assert!(result.is_ok());

        // Create a violation by exceeding threshold
        for i in 0..1500 {
            // Above default threshold of 1000
            oracle.on_work_item_added(
                "finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution,
                Time::from_nanos(i * 1000),
            );
        }

        // Check should now return error
        let result = oracle.check(Time::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_reset() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();

        // Add some state and violations
        oracle.on_work_item_added(
            "finalizers",
            Some(TaskId::testing_default()),
            Some(RegionId::testing_default()),
            CleanupWorkType::FinalizerExecution,
            Time::ZERO,
        );

        let stats_before = oracle.get_statistics();
        assert!(stats_before.work_items_tracked > 0);

        // Reset should clear everything
        oracle.reset();

        let stats_after = oracle.get_statistics();
        assert_eq!(stats_after.work_items_tracked, 0);
        assert_eq!(stats_after.completions_tracked, 0);
        assert_eq!(stats_after.violations_detected, 0);
        assert_eq!(stats_after.tracked_queues, 0);
        assert_eq!(stats_after.total_current_debt, 0);
    }

    #[test]
    fn test_resource_pressure_detection() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();

        // Add many large work items to trigger memory pressure
        for i in 0..5000 {
            oracle.on_work_item_added(
                "large_finalizers",
                Some(TaskId::new_for_test(i as u32, 0)),
                Some(RegionId::testing_default()),
                CleanupWorkType::FinalizerExecution, // ~250 bytes each
                Time::from_nanos(i * 1000),
            );
        }

        oracle.check_debt_accumulation(Time::ZERO);

        let violations = oracle.get_recent_violations(10);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, CancelDebtViolation::ResourcePressure { .. }))
        );
    }

    #[test]
    fn test_queue_state_snapshots_expose_pending_work_metadata() {
        init_test_logging();

        let oracle = CancelDebtOracle::with_default_config();
        let task_id = TaskId::new_for_test(11, 0);
        let region_id = RegionId::testing_default();
        let created_at = Time::from_nanos(42);

        oracle.on_work_item_added(
            "finalizers",
            Some(task_id),
            Some(region_id),
            CleanupWorkType::FinalizerExecution,
            created_at,
        );

        let snapshots = oracle.get_queue_state_snapshots();
        assert_eq!(snapshots.len(), 1);

        let queue = &snapshots[0];
        assert_eq!(queue.queue_type, "finalizers");
        assert_eq!(queue.pending_items, 1);
        assert_eq!(queue.work_items.len(), 1);

        let item = &queue.work_items[0];
        assert_eq!(item.task_id, Some(task_id));
        assert_eq!(item.region_id, Some(region_id));
        assert_eq!(item.work_type, CleanupWorkType::FinalizerExecution);
        assert_eq!(item.work_type_name, "finalizer_execution");
        assert_eq!(item.created_at, created_at);
        assert_eq!(
            item.estimated_size_bytes,
            CleanupWorkType::FinalizerExecution.estimated_size_bytes()
        );
        assert_eq!(queue.estimated_memory_usage, item.estimated_size_bytes);
    }
