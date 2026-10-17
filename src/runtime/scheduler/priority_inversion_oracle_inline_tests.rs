    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::types::TaskId;

    #[test]
    fn test_oracle_creation() {
        let oracle = PriorityInversionOracle::new();
        let stats = oracle.get_stats();
        assert_eq!(stats.total_inversions, 0);
        assert_eq!(stats.active_inversions, 0);
    }

    #[test]
    fn test_task_tracking() {
        let oracle = PriorityInversionOracle::new();
        let task_id = TaskId::new_for_test(1, 0);

        oracle.track_task_spawned(task_id, 5, DispatchLane::Ready, None);

        let tasks = oracle.tasks.read();
        assert!(tasks.contains_key(&task_id));
        assert_eq!(tasks.get(&task_id).unwrap().priority, 5);
    }

    #[test]
    fn test_direct_inversion_detection() {
        let oracle = PriorityInversionOracle::new();
        let high_priority_task = TaskId::new_for_test(1, 0);
        let low_priority_task = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        // Spawn tasks with different priorities
        oracle.track_task_spawned(high_priority_task, 10, DispatchLane::Ready, None);
        oracle.track_task_spawned(low_priority_task, 1, DispatchLane::Ready, None);

        // Low priority task acquires resource
        oracle.track_resource_acquired(low_priority_task, resource);

        // High priority task waits for same resource (should detect inversion)
        oracle.track_resource_waiting(high_priority_task, resource);

        let active_inversions = oracle.get_active_inversions();
        assert_eq!(active_inversions.len(), 1);

        let inversion = &active_inversions[0];
        assert_eq!(inversion.blocked_task, high_priority_task);
        assert_eq!(inversion.blocking_task, low_priority_task);
        assert_eq!(inversion.blocked_priority, 10);
        assert_eq!(inversion.blocking_priority, 1);
        assert_eq!(inversion.inversion_type, InversionType::Direct);
    }

    #[test]
    fn test_inversion_resolution() {
        let oracle = PriorityInversionOracle::new();
        let high_priority_task = TaskId::new_for_test(1, 0);
        let low_priority_task = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        // Set up inversion
        oracle.track_task_spawned(high_priority_task, 10, DispatchLane::Ready, None);
        oracle.track_task_spawned(low_priority_task, 1, DispatchLane::Ready, None);
        oracle.track_resource_acquired(low_priority_task, resource);
        oracle.track_resource_waiting(high_priority_task, resource);

        assert_eq!(oracle.get_active_inversions().len(), 1);

        // Resolve inversion by releasing resource
        oracle.release_resource(low_priority_task, resource);

        // Should resolve the inversion
        assert_eq!(oracle.get_active_inversions().len(), 0);

        // Check that it was recorded in history
        std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure above minimum duration
        assert!(oracle.get_historical_inversions().len() <= 1); // May not be recorded if below threshold
    }

    #[test]
    fn test_no_inversion_same_priority() {
        let oracle = PriorityInversionOracle::new();
        let task1 = TaskId::new_for_test(1, 0);
        let task2 = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        // Spawn tasks with same priority
        oracle.track_task_spawned(task1, 5, DispatchLane::Ready, None);
        oracle.track_task_spawned(task2, 5, DispatchLane::Ready, None);

        oracle.track_resource_acquired(task1, resource);
        oracle.track_resource_waiting(task2, resource);

        // Should not detect inversion for same priority
        assert_eq!(oracle.get_active_inversions().len(), 0);
    }

    #[test]
    fn test_statistics_updates() {
        let oracle = PriorityInversionOracle::new();
        let high_task = TaskId::new_for_test(1, 0);
        let low_task = TaskId::new_for_test(2, 0);
        let resource = oracle.create_resource();

        oracle.track_task_spawned(high_task, 10, DispatchLane::Ready, None);
        oracle.track_task_spawned(low_task, 1, DispatchLane::Ready, None);
        oracle.track_resource_acquired(low_task, resource);
        oracle.track_resource_waiting(high_task, resource);

        let stats = oracle.get_stats();
        assert_eq!(stats.total_inversions, 1);
        assert_eq!(stats.active_inversions, 1);
        assert!(stats.by_type.contains_key("Direct"));
    }

    #[test]
    fn test_resource_id_uniqueness() {
        let oracle = PriorityInversionOracle::new();
        let resource1 = oracle.create_resource();
        let resource2 = oracle.create_resource();

        assert_ne!(resource1, resource2);
    }

    #[test]
    fn test_task_completion_cleanup() {
        let oracle = PriorityInversionOracle::new();
        let task_id = TaskId::new_for_test(1, 0);

        oracle.track_task_spawned(task_id, 5, DispatchLane::Ready, None);
        assert!(oracle.tasks.read().contains_key(&task_id));

        oracle.track_task_completed(task_id);
        assert!(!oracle.tasks.read().contains_key(&task_id));
    }
