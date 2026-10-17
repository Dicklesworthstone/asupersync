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
    fn test_correct_parent_child_ordering() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel parent first (correct order)
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Then cancel child (correct order)
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::from_nanos(1000),
            CancelReason::user("test"),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 0);
        assert_eq!(stats.signals_processed, 2);
    }

    #[test]
    fn test_child_before_parent_violation() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel child first (incorrect order)
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Then cancel parent (should detect violation)
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::from_nanos(1000),
            CancelReason::user("test"),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 2); // orphaned child + child before parent

        let violations = oracle.get_recent_violations(5);
        assert_eq!(violations.len(), 2);

        // Check that we detected child before parent violation
        let has_child_before_parent = violations
            .iter()
            .any(|v| matches!(v, CancelOrderingViolation::ChildBeforeParent { .. }));
        assert!(has_child_before_parent);
    }

    #[test]
    fn test_orphaned_child_cancellation() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel only child, not parent (orphaned cancellation)
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelOrderingViolation::OrphanedChildCancellation { .. }
        ));
    }

    #[test]
    fn test_missing_child_cancellation() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel only parent
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Wait long enough to trigger violation
        let later_time = Time::from_nanos(2_000_000_000); // 2 seconds
        oracle.check_ordering_violations(later_time);

        let stats = oracle.get_statistics();
        assert_eq!(stats.violations_detected, 1);

        let violations = oracle.get_recent_violations(1);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            CancelOrderingViolation::MissingChildCancellation { .. }
        ));
    }

    #[test]
    fn test_oracle_check_method() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        // Register parent-child relationship
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Normal operation should pass
        let result = oracle.check(Time::ZERO);
        assert!(result.is_ok());

        // Create a violation
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        // Check should now return error
        let result = oracle.check(Time::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_oracle_reset() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        // Add some state
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);
        oracle.on_cancel_signal(
            child_task,
            child_region,
            Time::ZERO,
            CancelReason::user("test"),
        );

        let stats_before = oracle.get_statistics();
        assert!(stats_before.violations_detected > 0);

        // Reset should clear everything
        oracle.reset();

        let stats_after = oracle.get_statistics();
        assert_eq!(stats_after.violations_detected, 0);
        assert_eq!(stats_after.signals_processed, 0);
        assert_eq!(stats_after.tracked_signals, 0);
        assert_eq!(stats_after.tracked_relationships, 0);
    }

    #[test]
    fn test_task_region_tracking() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(42, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(123, 0);

        // Spawn a task - this should record the task-region mappings
        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        // Cancel the parent task
        oracle.on_cancel_signal(
            parent_task,
            parent_region,
            Time::from_nanos(1000),
            CancelReason::user("test"),
        );

        // Wait for the ordering window (default 1s) to expire so missing child
        // cancellation is detected.
        oracle.check_ordering_violations(Time::from_nanos(2_000_000_000));

        // Should detect a violation with the correct child region, not the default sentinel.
        let violations = oracle.get_recent_violations(10);
        assert_eq!(violations.len(), 1);

        match &violations[0] {
            CancelOrderingViolation::MissingChildCancellation {
                child_region: detected_child_region,
                ..
            } => {
                assert_eq!(
                    *detected_child_region, child_region,
                    "Should use actual child region, not testing_default sentinel"
                );
            }
            other => panic!("Expected MissingChildCancellation, got: {:?}", other),
        }
    }

    #[test]
    fn test_tracked_signals_preserve_reason_and_ancestry() {
        init_test_logging();

        let oracle = CancelOrderingOracle::with_default_config();
        let parent_task = TaskId::testing_default();
        let child_task = TaskId::new_for_test(2, 0);
        let parent_region = RegionId::testing_default();
        let child_region = RegionId::new_for_test(2, 0);

        oracle.on_task_spawned(parent_task, child_task, parent_region, child_region);

        let reason = CancelReason::user("ordered shutdown");
        let cancel_time = Time::from_nanos(1234);
        oracle.on_cancel_signal(child_task, child_region, cancel_time, reason.clone());

        let tracked = oracle.tracked_signals();
        assert_eq!(tracked.len(), 1);

        let snapshot = &tracked[0];
        assert_eq!(snapshot.task_id, child_task);
        assert_eq!(snapshot.region_id, child_region);
        assert_eq!(snapshot.cancel_time, cancel_time);
        assert_eq!(snapshot.cancel_reason, reason);
        assert_eq!(snapshot.parent_task, Some(parent_task));
        assert_eq!(snapshot.parent_region, Some(parent_region));
    }
