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
    fn test_invariant_monitor_basic_operations() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(42, 0);

        // Test basic enqueue/dequeue
        monitor.record_task_enqueue(task_id, "ready_queue", 1, now);
        assert_eq!(monitor.task_states.len(), 1);
        assert!(monitor.violations.is_empty());

        monitor.record_task_dequeue(task_id, "ready_queue", now);
        assert!(monitor.violations.is_empty());

        monitor.record_task_complete(task_id, 0, now);
        assert!(monitor.violations.is_empty());
    }

    #[test]
    fn test_invariant_violations_detected() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(42, 0);

        // Test double enqueue violation
        monitor.record_task_enqueue(task_id, "ready_queue", 1, now);
        monitor.record_task_enqueue(task_id, "timed_queue", 1, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::TaskInMultipleQueues {
                task_id: tid,
                queue_count,
            } => {
                assert_eq!(*tid, task_id);
                assert_eq!(*queue_count, 2);
            }
            _ => panic!("Expected TaskInMultipleQueues violation"),
        }
    }

    #[test]
    fn test_priority_ordering_violations() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        // Test priority violation (higher number = higher priority)
        monitor.verify_priority_ordering(
            TaskId::new_for_test(1, 0),
            3,
            TaskId::new_for_test(2, 0),
            5,
            now,
        );

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::PriorityOrderViolation {
                high_priority_task,
                high_priority,
                low_priority_task,
                low_priority,
            } => {
                assert_eq!(*high_priority_task, TaskId::new_for_test(2, 0));
                assert_eq!(*high_priority, 5);
                assert_eq!(*low_priority_task, TaskId::new_for_test(1, 0));
                assert_eq!(*low_priority, 3);
            }
            _ => panic!("Expected PriorityOrderViolation"),
        }
    }

    #[test]
    fn test_queue_consistency_verification() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        let snapshot = QueueSnapshot {
            name: "test_queue".to_string(),
            reported_depth: 5,
            actual_tasks: vec![
                TaskId::new_for_test(1, 0),
                TaskId::new_for_test(2, 0),
                TaskId::new_for_test(3, 0),
            ],
            priority_range: Some((1, 3)),
            time_range: Some((Time::from_nanos(500), now)),
        };

        monitor.verify_queue_consistency(&snapshot, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::QueueDepthMismatch {
                queue_name,
                reported_depth,
                actual_depth,
            } => {
                assert_eq!(queue_name, "test_queue");
                assert_eq!(*reported_depth, 5);
                assert_eq!(*actual_depth, 3);
            }
            _ => panic!("Expected QueueDepthMismatch violation"), // ubs:ignore - test logic
        }
    }

    #[test]
    fn test_load_balance_verification() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        let worker_loads = vec![
            WorkerLoadSnapshot {
                worker_id: 0,
                local_queue_depth: 10,
                executing_count: 2,
                recent_task_count: 100,
                avg_execution_time_ms: 5.0,
            },
            WorkerLoadSnapshot {
                worker_id: 1,
                local_queue_depth: 2,
                executing_count: 1,
                recent_task_count: 20,
                avg_execution_time_ms: 4.0,
            },
        ];

        monitor.verify_load_balance(&worker_loads, now);

        assert_eq!(monitor.violations.len(), 1);
        match &monitor.violations[0].invariant {
            SchedulerInvariant::LoadImbalance {
                overloaded_worker,
                underloaded_worker,
                load_ratio,
            } => {
                assert_eq!(*overloaded_worker, 0);
                assert_eq!(*underloaded_worker, 1);
                assert!((*load_ratio - 5.0).abs() < 0.1);
            }
            _ => panic!("Expected LoadImbalance violation"),
        }
    }

    #[test]
    fn test_statistics_tracking() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let now = Time::from_nanos(1000);

        // Generate some violations
        monitor.verify_priority_ordering(
            TaskId::new_for_test(1, 0),
            3,
            TaskId::new_for_test(2, 0),
            5,
            now,
        );
        monitor.verify_priority_ordering(
            TaskId::new_for_test(3, 0),
            2,
            TaskId::new_for_test(4, 0),
            7,
            now,
        );

        let stats = monitor.stats();
        assert_eq!(
            stats.violations_by_category[&InvariantCategory::PriorityOrdering],
            2
        );
        assert_eq!(stats.violations_by_severity[2], 2); // High severity
        assert_eq!(stats.last_violation_time, Some(now));
    }

    #[test]
    fn test_cleanup_old_data() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let old_time = Time::from_nanos(1000);
        let new_time = Time::from_nanos(5000);

        // Add old task state
        monitor.record_task_enqueue(TaskId::new_for_test(1, 0), "queue", 1, old_time);

        // Add old violation
        monitor.verify_priority_ordering(
            TaskId::new_for_test(2, 0),
            3,
            TaskId::new_for_test(3, 0),
            5,
            old_time,
        );

        assert_eq!(monitor.task_states.len(), 1);
        assert_eq!(monitor.violations.len(), 1);

        // Clean up data older than 2000ns
        monitor.cleanup_old_data(new_time, Duration::from_nanos(2000));

        assert_eq!(monitor.task_states.len(), 0);
        assert_eq!(monitor.violations.len(), 0);
    }

    #[test]
    fn test_tracked_task_snapshots_expose_internal_state() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let enqueue_time = Time::from_nanos(1000);
        let task_id = TaskId::new_for_test(7, 0);

        monitor.record_task_enqueue(task_id, "ready_queue", 3, enqueue_time);
        if let Some(state) = monitor.task_states.get_mut(&task_id) {
            state.owner_worker = Some(2);
        }
        monitor.record_task_cancel(task_id, Time::from_nanos(1500));

        let snapshots = monitor.tracked_tasks();
        assert_eq!(snapshots.len(), 1);

        let snapshot = &snapshots[0];
        assert_eq!(snapshot.task_id, task_id);
        assert_eq!(snapshot.queues, vec!["ready_queue".to_string()]);
        assert_eq!(snapshot.priority, 3);
        assert_eq!(snapshot.enqueue_time, enqueue_time);
        assert_eq!(snapshot.last_update, Time::from_nanos(1500));
        assert_eq!(snapshot.lifecycle_state, "cancelled");
        assert_eq!(snapshot.owner_worker, Some(2));
        assert!(snapshot.is_cancelled);
    }

    #[test]
    fn test_reenqueue_same_queue_does_not_trigger_multiple_queue_violation() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let task_id = TaskId::new_for_test(9, 0);

        monitor.record_task_enqueue(task_id, "ready_queue", 10, Time::from_nanos(1_000));
        monitor.record_task_enqueue(task_id, "ready_queue", 10, Time::from_nanos(1_200));

        assert!(
            monitor.violations.is_empty(),
            "re-observing the same queue must not look like a multiple-queue violation"
        );
    }

    #[test]
    fn test_requeue_replaces_previous_queue_without_multiple_queue_violation() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let task_id = TaskId::new_for_test(11, 0);

        monitor.record_task_enqueue(task_id, "ready_queue", 10, Time::from_nanos(1_000));
        monitor.record_task_requeue(task_id, "cancel_queue", 50, Time::from_nanos(1_200));

        assert!(
            monitor.violations.is_empty(),
            "intentional queue moves must not look like multiple-queue corruption"
        );
        let snapshots = monitor.tracked_tasks();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].queues, vec!["cancel_queue".to_string()]);
        assert_eq!(snapshots[0].priority, 50);
    }

    #[test]
    fn test_dispatch_removes_task_from_tracking() {
        let mut monitor = SchedulerInvariantMonitor::with_defaults();
        let task_id = TaskId::new_for_test(12, 0);

        monitor.record_task_enqueue(task_id, "ready_queue", 10, Time::from_nanos(1_000));
        monitor.record_task_dispatch(task_id, Time::from_nanos(1_500));

        assert!(
            monitor.tracked_tasks().is_empty(),
            "dispatched task should no longer appear as queued"
        );
        assert!(monitor.violations.is_empty());
    }

    #[test]
    fn test_cancelled_task_leak_requires_cancelled_task_state() {
        let task_id = TaskId::new_for_test(10, 0);

        let mut uncancelled = SchedulerInvariantMonitor::with_defaults();
        uncancelled.record_task_enqueue(task_id, "ready_queue", 10, Time::from_nanos(1_000));
        uncancelled.record_task_complete(task_id, 0, Time::from_nanos(2_000));
        assert!(
            uncancelled.violations.is_empty(),
            "non-cancelled tasks must not be reported as cancelled leaks"
        );

        let mut cancelled = SchedulerInvariantMonitor::with_defaults();
        cancelled.record_task_enqueue(task_id, "ready_queue", 10, Time::from_nanos(1_000));
        cancelled.record_task_cancel(task_id, Time::from_nanos(1_500));
        cancelled.record_task_complete(task_id, 0, Time::from_nanos(3_500));

        assert_eq!(cancelled.violations.len(), 1);
        match &cancelled.violations[0].invariant {
            SchedulerInvariant::CancelledTaskLeak {
                task_id: leaked_task,
                queue_name,
                time_since_cancel_ms,
            } => {
                assert_eq!(*leaked_task, task_id);
                assert_eq!(queue_name, "ready_queue");
                assert_eq!(*time_since_cancel_ms, 0);
            }
            other => panic!("Expected CancelledTaskLeak, got {other:?}"), // ubs:ignore - test logic
        }
    }
