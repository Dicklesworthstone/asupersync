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
    fn test_basic_ownership_tracking() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let _worker2 = 2;
        let task = TaskId::new_for_test(100, 0);

        // Queue task on worker 1
        checker.track_task_queued(task, worker1);

        // Start execution on worker 1
        checker.track_task_execution_start(task, worker1);
        assert!(!checker.has_violations());

        // Complete execution
        checker.track_task_execution_complete(task, worker1);
        assert!(!checker.has_violations());
    }

    #[test]
    fn test_steal_operation() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(100, 0);

        // Queue task on worker 1
        checker.track_task_queued(task, worker1);

        // Start steal operation
        if let Some(tracker) = checker.track_steal_start(task, worker1, worker2) {
            // Complete steal successfully
            tracker.success();
        }

        // Execute on worker 2 (after successful steal)
        checker.track_task_execution_start(task, worker2);
        checker.track_task_execution_complete(task, worker2);

        let stats = checker.stats();
        assert_eq!(stats.successful_steals, 1);
        assert_eq!(stats.failed_steals, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn test_failed_steal_restores_original_owner() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(101, 0);

        checker.track_task_queued(task, worker1);

        if let Some(tracker) = checker.track_steal_start(task, worker1, worker2) {
            tracker.failure();
        }

        checker.track_task_execution_start(task, worker1);
        checker.track_task_execution_complete(task, worker1);

        let stats = checker.stats();
        assert_eq!(stats.failed_steals, 1);
        assert_eq!(stats.successful_steals, 0);
        assert!(!checker.has_violations());
    }

    #[test]
    fn test_dropped_tracker_counts_single_failure() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(102, 0);

        checker.track_task_queued(task, worker1);
        let tracker = checker
            .track_steal_start(task, worker1, worker2)
            .expect("steal tracker should be created");
        drop(tracker);

        let stats = checker.stats();
        assert_eq!(stats.failed_steals, 1);
        assert_eq!(stats.successful_steals, 0);

        checker.track_task_execution_start(task, worker1);
        checker.track_task_execution_complete(task, worker1);
        assert!(!checker.has_violations());
    }

    #[test]
    fn test_double_execution_detection() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(100, 0);

        checker.track_task_queued(task, worker1);

        // Start execution on worker 1
        checker.track_task_execution_start(task, worker1);

        // Try to start execution on worker 2 (should detect violation)
        checker.track_task_execution_start(task, worker2);

        assert!(checker.has_violations());
        let violations = checker.violations();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ViolationType::DoubleExecution { .. }
        ));
    }

    #[test]
    fn test_ownership_violation_detection() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let worker3 = 3;
        let task = TaskId::new_for_test(100, 0);

        checker.track_task_queued(task, worker1);

        // Try to steal from wrong worker (should detect violation)
        let tracker = checker.track_steal_start(task, worker2, worker3);
        assert!(tracker.is_none()); // Should fail to create tracker

        assert!(checker.has_violations());
    }

    #[test]
    fn test_steal_start_rejects_unknown_task() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(103, 0);

        let tracker = checker.track_steal_start(task, worker1, worker2);
        assert!(tracker.is_none());

        let stats = checker.stats();
        assert_eq!(stats.steal_attempts, 0);
        assert_eq!(stats.successful_steals, 0);
        assert_eq!(stats.failed_steals, 0);
        assert_eq!(stats.lost_work_violations, 1);

        let violations = checker.violations();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ViolationType::LostWork {
                task_id,
                last_owner
            } if task_id == task && last_owner == worker1
        ));
    }

    #[test]
    fn test_steal_start_rejects_currently_executing_task() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(104, 0);

        checker.track_task_queued(task, worker1);
        checker.track_task_execution_start(task, worker1);

        let tracker = checker.track_steal_start(task, worker1, worker2);
        assert!(tracker.is_none());

        let stats = checker.stats();
        assert_eq!(stats.steal_attempts, 0);
        assert_eq!(stats.successful_steals, 0);
        assert_eq!(stats.failed_steals, 0);
        assert_eq!(stats.ownership_violations, 1);
        assert_eq!(stats.lost_work_violations, 0);
        assert_eq!(checker.executing_tasks.read().get(&task), Some(&worker1));
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Owned(worker1))
        );

        let violations = checker.violations();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ViolationType::MultipleOwners { ref owners, task_id }
                if task_id == task && owners == &vec![worker1, worker2]
        ));
    }

    #[test]
    fn test_steal_success_without_tracked_owner_is_not_counted() {
        let checker = WorkStealingChecker::new();
        let task = TaskId::new_for_test(105, 0);

        checker.track_steal_success(task, 1, 2, Duration::ZERO);

        let stats = checker.stats();
        assert_eq!(stats.successful_steals, 0);
        assert_eq!(stats.lost_work_violations, 1);
    }

    #[test]
    fn test_execution_of_unknown_task_detects_lost_work() {
        let checker = WorkStealingChecker::new();
        let task = TaskId::new_for_test(106, 0);

        checker.track_task_execution_start(task, 7);

        let stats = checker.stats();
        assert_eq!(stats.double_execution_violations, 0);
        assert_eq!(stats.lost_work_violations, 1);

        let violations = checker.violations();
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ViolationType::LostWork {
                task_id,
                last_owner
            } if task_id == task && last_owner == 7
        ));
        assert_eq!(checker.executing_tasks.read().get(&task), None);
        assert_eq!(checker.task_owners.read().get(&task), None);
    }

    #[test]
    fn test_wrong_owner_execution_start_does_not_poison_active_execution() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(109, 0);

        checker.track_task_queued(task, worker1);
        checker.track_task_execution_start(task, worker2);

        let stats = checker.stats();
        assert_eq!(stats.ownership_violations, 1);
        assert_eq!(stats.double_execution_violations, 0);
        assert_eq!(checker.executing_tasks.read().get(&task), None);
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Owned(worker1))
        );

        checker.track_task_execution_start(task, worker1);
        checker.track_task_execution_complete(task, worker1);
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Completed)
        );
    }

    #[test]
    fn test_completed_task_execution_start_does_not_poison_active_execution() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let task = TaskId::new_for_test(110, 0);

        checker.track_task_queued(task, worker1);
        checker.track_task_execution_start(task, worker1);
        checker.track_task_execution_complete(task, worker1);
        assert!(!checker.has_violations());

        checker.track_task_execution_start(task, worker1);

        let stats = checker.stats();
        assert_eq!(stats.lost_work_violations, 1);
        assert_eq!(stats.double_execution_violations, 0);
        assert_eq!(checker.executing_tasks.read().get(&task), None);
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Completed)
        );
    }

    #[test]
    fn test_completion_from_wrong_worker_preserves_active_execution() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let worker2 = 2;
        let task = TaskId::new_for_test(107, 0);

        checker.track_task_queued(task, worker1);
        checker.track_task_execution_start(task, worker1);
        checker.track_task_execution_complete(task, worker2);

        let stats = checker.stats();
        assert_eq!(stats.double_execution_violations, 1);
        assert_eq!(stats.lost_work_violations, 0);
        assert_eq!(checker.executing_tasks.read().get(&task), Some(&worker1));
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Owned(worker1))
        );

        checker.track_task_execution_complete(task, worker1);
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Completed)
        );
    }

    #[test]
    fn test_completion_without_execution_start_detects_lost_work() {
        let checker = WorkStealingChecker::new();
        let worker1 = 1;
        let task = TaskId::new_for_test(108, 0);

        checker.track_task_queued(task, worker1);
        checker.track_task_execution_complete(task, worker1);

        let stats = checker.stats();
        assert_eq!(stats.lost_work_violations, 1);
        assert_eq!(stats.double_execution_violations, 0);
        assert_eq!(
            checker.task_owners.read().get(&task),
            Some(&OwnershipState::Owned(worker1))
        );
    }
