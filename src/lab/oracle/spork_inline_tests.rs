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

    fn task(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn actor(index: u32) -> ActorId {
        ActorId::from_task(task(index))
    }

    fn region(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    // ReplyLinearityOracle tests

    #[test]
    fn reply_linearity_pass_when_all_resolved() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.on_reply_sent(actor(1), task(1));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn reply_linearity_fail_on_dropped_reply() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        // No send or abort.
        let err = oracle.check().unwrap_err();
        assert!(err.dropped);
    }

    #[test]
    fn reply_linearity_pass_on_aborted_reply() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.on_reply_aborted(actor(1), task(1));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn reply_linearity_fail_on_double_resolution() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.on_reply_sent(actor(1), task(1));
        oracle.on_reply_aborted(actor(1), task(1));
        let err = oracle.check().unwrap_err();
        assert!(!err.dropped);
    }

    #[test]
    fn reply_linearity_reset_clears_state() {
        let mut oracle = ReplyLinearityOracle::new();
        oracle.on_reply_created(actor(1), task(1), Time::ZERO);
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.created_count(), 0);
    }

    // RegistryLeaseOracle tests

    #[test]
    fn registry_lease_pass_when_all_resolved() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("svc", task(1), region(0), Time::ZERO);
        oracle.on_lease_released("svc");
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn registry_lease_fail_on_unreleased_lease() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("leaked_svc", task(1), region(0), Time::ZERO);
        let err = oracle.check().unwrap_err();
        assert_eq!(err.name, "leaked_svc");
    }

    #[test]
    fn registry_lease_pass_on_aborted_lease() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("temp", task(1), region(0), Time::ZERO);
        oracle.on_lease_aborted("temp");
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn registry_lease_reset_clears_state() {
        let mut oracle = RegistryLeaseOracle::new();
        oracle.on_lease_acquired("name", task(1), region(0), Time::ZERO);
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.acquired_count(), 0);
    }

    // DownOrderOracle tests

    #[test]
    fn down_order_pass_when_sorted() {
        let mut oracle = DownOrderOracle::new();
        // Deliver DOWNs in sorted order.
        oracle.on_down_delivered(task(10), task(1));
        oracle.on_down_delivered(task(10), task(2));
        oracle.on_down_delivered(task(10), task(3));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn down_order_fail_when_unsorted() {
        let mut oracle = DownOrderOracle::new();
        // Deliver DOWNs in wrong order.
        oracle.on_down_delivered(task(10), task(3));
        oracle.on_down_delivered(task(10), task(1));
        let err = oracle.check().unwrap_err();
        assert_eq!(err.monitor, task(10));
    }

    #[test]
    fn timed_downs_must_not_go_back_in_completion_time() {
        // Exits in time order pass, whatever the task indexes; completions at
        // the same time keep their completion order.
        let mut oracle = DownOrderOracle::new();
        oracle.on_down_delivered_at(task(10), task(3), Time::from_millis(1));
        oracle.on_down_delivered_at(task(10), task(2), Time::from_millis(2));
        oracle.on_down_delivered_at(task(10), task(1), Time::from_millis(2));
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.down_count(), 3);

        // Planted negative: an earlier exit delivered after a later one.
        let mut oracle = DownOrderOracle::new();
        oracle.on_down_delivered_at(task(10), task(1), Time::from_millis(2));
        oracle.on_down_delivered_at(task(10), task(2), Time::from_millis(1));
        let err = oracle.check().unwrap_err();
        assert_eq!(err.monitor, task(10));
        assert_eq!(err.actual, vec![task(1), task(2)]);
        assert_eq!(err.expected, vec![task(2), task(1)]);

        // Each monitor is checked on its own.
        let mut oracle = DownOrderOracle::new();
        oracle.on_down_delivered_at(task(10), task(1), Time::from_millis(2));
        oracle.on_down_delivered_at(task(11), task(2), Time::from_millis(1));
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn down_order_pass_with_empty() {
        let oracle = DownOrderOracle::new();
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn down_order_reset_clears_state() {
        let mut oracle = DownOrderOracle::new();
        oracle.on_down_delivered(task(10), task(3));
        oracle.on_down_delivered(task(10), task(1));
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.down_count(), 0);
    }

    // SupervisorQuiescenceOracle tests

    #[test]
    fn supervisor_quiescence_pass_when_all_completed() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        oracle.on_child_added(task(1), task(3));
        oracle.on_task_completed(task(2), Time::ZERO);
        oracle.on_task_completed(task(3), Time::ZERO);
        oracle.on_region_closed(region(0), Time::ZERO);
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn supervisor_quiescence_fail_with_active_child() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        // task(2) never completes.
        oracle.on_region_closed(region(0), Time::ZERO);
        let err = oracle.check().unwrap_err();
        assert_eq!(err.active_children, vec![task(2)]);
    }

    #[test]
    fn supervisor_quiescence_pass_when_region_not_closed() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        // Region NOT closed — should pass (only checks closed regions).
        assert!(oracle.check().is_ok());
    }

    #[test]
    fn supervisor_quiescence_fail_when_child_completes_after_close() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        oracle.on_region_closed(region(0), Time::from_nanos(100));
        oracle.on_task_completed(task(2), Time::from_nanos(101));
        let err = oracle.check().unwrap_err();
        assert_eq!(err.active_children, vec![task(2)]);
        assert_eq!(err.close_time, Time::from_nanos(100));
    }

    #[test]
    fn supervisor_quiescence_reset_clears_state() {
        let mut oracle = SupervisorQuiescenceOracle::new();
        oracle.on_supervisor_created(task(1), region(0));
        oracle.on_child_added(task(1), task(2));
        oracle.on_region_closed(region(0), Time::ZERO);
        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.supervisor_count(), 0);
    }
