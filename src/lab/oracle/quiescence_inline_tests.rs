    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::oracle::Oracle;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn finalizer(n: u64) -> FinalizerId {
        FinalizerId(n)
    }

    fn obligation(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn snapshot_report(oracle: &QuiescenceOracle) -> String {
        serde_json::to_string_pretty(&oracle.report_entry())
            .expect("quiescence report should serialize")
    }

    #[derive(Clone, Copy)]
    enum CleanupAction {
        CompleteTask(u32),
        CloseRegion(u32, u64),
    }

    fn parent_violation_after_partial_drain(actions: &[CleanupAction]) -> QuiescenceViolation {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(0)));
        oracle.on_spawn(task(1), region(0));
        oracle.on_spawn(task(2), region(0));
        oracle.on_spawn(task(3), region(0));

        for action in actions {
            match action {
                CleanupAction::CompleteTask(task_id) => oracle.on_task_complete(task(*task_id)),
                CleanupAction::CloseRegion(region_id, nanos) => {
                    oracle.on_region_close(region(*region_id), t(*nanos));
                }
            }
        }

        oracle.on_region_close(region(0), t(100));
        oracle
            .check()
            .expect_err("parent should still have one live child and one live task")
    }

    #[test]
    fn empty_region_passes() {
        init_test("empty_region_passes");
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("empty_region_passes");
    }

    #[test]
    fn all_tasks_complete_passes() {
        init_test("all_tasks_complete_passes");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_spawn(task(2), region(0));

        oracle.on_task_complete(task(1));
        oracle.on_task_complete(task(2));
        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("all_tasks_complete_passes");
    }

    #[test]
    fn live_task_fails() {
        init_test("live_task_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        // Task not completed
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.live_tasks == vec![task(1)],
            "live_tasks",
            vec![task(1)],
            violation.live_tasks
        );
        let empty = violation.live_children.is_empty();
        crate::assert_with_log!(empty, "live_children empty", true, empty);
        crate::test_complete!("live_task_fails");
    }

    #[test]
    fn live_child_region_fails() {
        init_test("live_child_region_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));

        // Parent closes but child does not
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.live_children == vec![region(1)],
            "live_children",
            vec![region(1)],
            violation.live_children
        );
        crate::test_complete!("live_child_region_fails");
    }

    #[test]
    fn unrun_finalizer_fails() {
        init_test("unrun_finalizer_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_finalizer_register(finalizer(7), region(0));
        oracle.on_region_close(region(0), t(100));

        let violation = oracle
            .check()
            .expect_err("close with unrun finalizer should fail");
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![finalizer(7)],
            "unrun_finalizers",
            vec![finalizer(7)],
            violation.unrun_finalizers
        );
        let no_tasks = violation.live_tasks.is_empty();
        crate::assert_with_log!(no_tasks, "no live tasks", true, no_tasks);
        let no_children = violation.live_children.is_empty();
        crate::assert_with_log!(no_children, "no live children", true, no_children);
        let no_obligations = violation.leaked_obligations.is_empty();
        crate::assert_with_log!(
            no_obligations,
            "no leaked obligations",
            true,
            no_obligations
        );
        crate::test_complete!("unrun_finalizer_fails");
    }

    #[test]
    fn pending_obligation_fails() {
        init_test("pending_obligation_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_obligation_create(obligation(9), region(0));
        oracle.on_region_close(region(0), t(100));

        let violation = oracle
            .check()
            .expect_err("close with pending obligation should fail");
        crate::assert_with_log!(
            violation.leaked_obligations == vec![obligation(9)],
            "leaked_obligations",
            vec![obligation(9)],
            violation.leaked_obligations
        );
        let no_tasks = violation.live_tasks.is_empty();
        crate::assert_with_log!(no_tasks, "no live tasks", true, no_tasks);
        let no_children = violation.live_children.is_empty();
        crate::assert_with_log!(no_children, "no live children", true, no_children);
        let no_finalizers = violation.unrun_finalizers.is_empty();
        crate::assert_with_log!(no_finalizers, "no unrun finalizers", true, no_finalizers);
        crate::test_complete!("pending_obligation_fails");
    }

    #[test]
    fn nested_regions_pass_when_properly_closed() {
        init_test("nested_regions_pass_when_properly_closed");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(1));

        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(1), t(50)); // Child closes first
        oracle.on_region_close(region(0), t(100)); // Parent closes after

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("nested_regions_pass_when_properly_closed");
    }

    #[test]
    fn multiple_children_all_must_close() {
        init_test("multiple_children_all_must_close");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(0)));

        // Only close one child
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.live_children == vec![region(2)],
            "live_children",
            vec![region(2)],
            violation.live_children
        );
        crate::test_complete!("multiple_children_all_must_close");
    }

    #[test]
    fn child_created_after_parent_close_is_violation() {
        init_test("child_created_after_parent_close_is_violation");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        oracle.on_region_create(region(1), Some(region(0)));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.live_children == vec![region(1)],
            "live_children",
            vec![region(1)],
            violation.live_children
        );
        let tasks_empty = violation.live_tasks.is_empty();
        crate::assert_with_log!(tasks_empty, "tasks empty", true, tasks_empty);
        crate::test_complete!("child_created_after_parent_close_is_violation");
    }

    #[test]
    fn task_spawned_after_region_close_is_violation_even_if_it_completes_later() {
        init_test("task_spawned_after_region_close_is_violation_even_if_it_completes_later");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        oracle.on_spawn(task(1), region(0));
        oracle.on_task_complete(task(1));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.live_tasks == vec![task(1)],
            "live_tasks",
            vec![task(1)],
            violation.live_tasks
        );
        let children_empty = violation.live_children.is_empty();
        crate::assert_with_log!(children_empty, "children empty", true, children_empty);
        crate::test_complete!(
            "task_spawned_after_region_close_is_violation_even_if_it_completes_later"
        );
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(100));

        // This would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let region_count = oracle.region_count();
        crate::assert_with_log!(region_count == 0, "region_count", 0, region_count);
        let closed_count = oracle.closed_count();
        crate::assert_with_log!(closed_count == 0, "closed_count", 0, closed_count);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = QuiescenceViolation {
            region: region(0),
            live_children: vec![region(1)],
            live_tasks: vec![task(1), task(2)],
            unrun_finalizers: Vec::new(),
            leaked_obligations: Vec::new(),
            close_time: t(100),
        };

        let s = violation.to_string();
        let has_without = s.contains("without quiescence");
        crate::assert_with_log!(has_without, "without quiescence", true, has_without);
        let has_children = s.contains("1 live children");
        crate::assert_with_log!(has_children, "children text", true, has_children);
        let has_tasks = s.contains("2 live tasks");
        crate::assert_with_log!(has_tasks, "tasks text", true, has_tasks);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn quiescence_clean_close_report_snapshot() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(0), t(100));

        insta::assert_snapshot!("quiescence_clean_close_report", snapshot_report(&oracle));
    }

    #[test]
    fn quiescence_leak_detected_report_snapshot() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(50));

        insta::assert_snapshot!("quiescence_leak_detected_report", snapshot_report(&oracle));
    }

    #[test]
    fn quiescence_cancel_during_drain_report_snapshot() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(75));
        oracle.on_task_complete(task(1));

        insta::assert_snapshot!(
            "quiescence_cancel_during_drain_report",
            snapshot_report(&oracle)
        );
    }

    #[test]
    fn deeply_nested_regions() {
        init_test("deeply_nested_regions");
        let mut oracle = QuiescenceOracle::new();

        // Create a chain: r0 -> r1 -> r2
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(1)));
        oracle.on_spawn(task(1), region(2));

        // Close in correct order (innermost first)
        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(2), t(30));
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("deeply_nested_regions");
    }

    #[test]
    fn both_tasks_and_children_must_complete() {
        init_test("both_tasks_and_children_must_complete");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(0));

        // Close child but not task
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        let children_empty = violation.live_children.is_empty();
        crate::assert_with_log!(children_empty, "children empty", true, children_empty);
        crate::assert_with_log!(
            violation.live_tasks == vec![task(1)],
            "live_tasks",
            vec![task(1)],
            violation.live_tasks
        );
        crate::test_complete!("both_tasks_and_children_must_complete");
    }

    #[test]
    fn mr_cleanup_permutation_preserves_residual_violation() {
        init_test("mr_cleanup_permutation_preserves_residual_violation");
        let violation_a = parent_violation_after_partial_drain(&[
            CleanupAction::CompleteTask(1),
            CleanupAction::CloseRegion(1, 40),
            CleanupAction::CompleteTask(2),
        ]);
        let violation_b = parent_violation_after_partial_drain(&[
            CleanupAction::CloseRegion(1, 40),
            CleanupAction::CompleteTask(2),
            CleanupAction::CompleteTask(1),
        ]);

        crate::assert_with_log!(
            violation_a.region == region(0),
            "violation_a.region",
            region(0),
            violation_a.region
        );
        crate::assert_with_log!(
            violation_a.live_children == vec![region(2)],
            "violation_a.live_children",
            vec![region(2)],
            violation_a.live_children.clone()
        );
        crate::assert_with_log!(
            violation_a.live_tasks == vec![task(3)],
            "violation_a.live_tasks",
            vec![task(3)],
            violation_a.live_tasks.clone()
        );
        crate::assert_with_log!(
            violation_b.region == violation_a.region,
            "violation_b.region",
            violation_a.region,
            violation_b.region
        );
        crate::assert_with_log!(
            violation_b.live_children == violation_a.live_children,
            "violation_b.live_children",
            violation_a.live_children.clone(),
            violation_b.live_children.clone()
        );
        crate::assert_with_log!(
            violation_b.live_tasks == violation_a.live_tasks,
            "violation_b.live_tasks",
            violation_a.live_tasks.clone(),
            violation_b.live_tasks.clone()
        );
        crate::assert_with_log!(
            violation_b.close_time == violation_a.close_time,
            "violation_b.close_time",
            violation_a.close_time,
            violation_b.close_time
        );
        crate::test_complete!("mr_cleanup_permutation_preserves_residual_violation");
    }

    #[test]
    fn quiescence_violation_debug_clone() {
        let v = QuiescenceViolation {
            region: region(1),
            live_children: vec![region(2), region(3)],
            live_tasks: vec![task(10)],
            unrun_finalizers: Vec::new(),
            leaked_obligations: Vec::new(),
            close_time: t(500),
        };
        let cloned = v.clone();
        assert_eq!(cloned.region, v.region);
        assert_eq!(cloned.live_children.len(), 2);
        assert_eq!(cloned.live_tasks.len(), 1);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("QuiescenceViolation"));
    }

    #[test]
    fn quiescence_oracle_debug_default() {
        let oracle = QuiescenceOracle::default();
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("QuiescenceOracle"));
        let oracle2 = QuiescenceOracle::new();
        let dbg2 = format!("{oracle2:?}");
        assert_eq!(dbg, dbg2);
    }
