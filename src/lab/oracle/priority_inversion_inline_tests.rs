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
    fn test_oracle_creation() {
        let oracle = PriorityInversionOracle::with_defaults();
        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
        assert_eq!(stats.active_inversion_count, 0);
    }

    #[test]
    fn test_task_lifecycle() {
        let oracle = PriorityInversionOracle::with_defaults();
        let task_id = TaskId::testing_default();

        oracle.on_task_spawn(task_id, Priority::High);
        oracle.on_task_start(task_id);
        oracle.on_task_complete(task_id);

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
    }

    #[test]
    fn test_direct_priority_inversion_detection() {
        let oracle = PriorityInversionOracle::with_defaults();
        let high_task = TaskId::testing_default();
        let low_task = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        // Spawn tasks
        oracle.on_task_spawn(high_task, Priority::High);
        oracle.on_task_spawn(low_task, Priority::Cooperative);

        // Low priority task acquires resource
        oracle.on_resource_acquire(low_task, resource);

        // High priority task waits for same resource - should detect inversion
        oracle.on_resource_wait(high_task, resource);

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 1);
        assert_eq!(stats.direct_inversions, 1);
        assert_eq!(stats.active_inversion_count, 1);
        assert!(oracle.has_active_inversions());
    }

    #[test]
    fn test_inversion_resolution() {
        let oracle = PriorityInversionOracle::with_defaults();
        let high_task = TaskId::testing_default();
        let low_task = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        // Create inversion
        oracle.on_task_spawn(high_task, Priority::High);
        oracle.on_task_spawn(low_task, Priority::Cooperative);
        oracle.on_resource_acquire(low_task, resource);
        oracle.on_resource_wait(high_task, resource);

        assert_eq!(oracle.statistics().active_inversion_count, 1);

        // Resolve inversion by releasing resource
        oracle.on_resource_release(low_task, resource);
        oracle.on_resource_acquire(high_task, resource);

        let stats = oracle.statistics();
        assert_eq!(stats.active_inversion_count, 0);
        assert_eq!(stats.total_inversions, 1);
        assert!(!oracle.has_active_inversions());
    }

    #[test]
    fn test_no_inversion_when_priorities_equal() {
        let oracle = PriorityInversionOracle::with_defaults();
        let task1 = TaskId::testing_default();
        let task2 = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        oracle.on_task_spawn(task1, Priority::Normal);
        oracle.on_task_spawn(task2, Priority::Normal);
        oracle.on_resource_acquire(task1, resource);
        oracle.on_resource_wait(task2, resource);

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
        assert!(!oracle.has_active_inversions());
    }

    #[test]
    fn test_report_generation() {
        let oracle = PriorityInversionOracle::with_defaults();
        let report = oracle.generate_report();
        assert!(report.contains("Priority Inversion Oracle Report"));
        assert!(report.contains("Total Inversions: 0"));
    }

    #[test]
    fn test_oracle_reset() {
        let oracle = PriorityInversionOracle::with_defaults();
        let high_task = TaskId::testing_default();
        let low_task = TaskId::new_for_test(100, 1);
        let resource = ResourceId(1);

        // Create some activity
        oracle.on_task_spawn(high_task, Priority::High);
        oracle.on_task_spawn(low_task, Priority::Cooperative);
        oracle.on_resource_acquire(low_task, resource);
        oracle.on_resource_wait(high_task, resource);

        assert_eq!(oracle.statistics().total_inversions, 1);

        oracle.reset();

        let stats = oracle.statistics();
        assert_eq!(stats.total_inversions, 0);
        assert_eq!(stats.active_inversion_count, 0);
        assert!(!oracle.has_active_inversions());
    }
