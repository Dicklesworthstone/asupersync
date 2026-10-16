    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn scrub_task_leak_display(output: &str) -> String {
        output
            .replace("RegionId(0:0)", "[REGION_ID]")
            .replace("TaskId(1:0)", "[TASK_ID_1]")
            .replace("TaskId(2:0)", "[TASK_ID_2]")
    }

    #[test]
    fn no_tasks_passes() {
        init_test("no_tasks_passes");
        let oracle = TaskLeakOracle::new();
        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("no_tasks_passes");
    }

    #[test]
    fn all_tasks_complete_passes() {
        init_test("all_tasks_complete_passes");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(2), region(0), t(20));

        oracle.on_complete(task(1), t(50));
        oracle.on_complete(task(2), t(60));

        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("all_tasks_complete_passes");
    }

    #[test]
    fn leaked_task_fails() {
        init_test("leaked_task_fails");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(2), region(0), t(20));

        // Only task 1 completes
        oracle.on_complete(task(1), t(50));

        oracle.on_region_close(region(0), t(100));

        let result = oracle.check(t(100));
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
            violation.leaked_tasks == vec![task(2)],
            "leaked_tasks",
            vec![task(2)],
            violation.leaked_tasks
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "close_time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("leaked_task_fails");
    }

    #[test]
    fn no_tasks_complete_all_leak() {
        init_test("no_tasks_complete_all_leak");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(2), region(0), t(20));

        // No tasks complete
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        let len = violation.leaked_tasks.len();
        crate::assert_with_log!(len == 2, "leaked_tasks len", 2, len);
        crate::test_complete!("no_tasks_complete_all_leak");
    }

    #[test]
    fn multiple_regions_independent() {
        init_test("multiple_regions_independent");
        let mut oracle = TaskLeakOracle::new();

        // Region 0: task completes
        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_complete(task(1), t(50));
        oracle.on_region_close(region(0), t(100));

        // Region 1: task does NOT complete
        oracle.on_spawn(task(2), region(1), t(20));
        oracle.on_region_close(region(1), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(1),
            "region",
            region(1),
            violation.region
        );
        crate::assert_with_log!(
            violation.leaked_tasks == vec![task(2)],
            "leaked_tasks",
            vec![task(2)],
            violation.leaked_tasks
        );
        crate::test_complete!("multiple_regions_independent");
    }

    #[test]
    fn region_without_close_not_checked() {
        init_test("region_without_close_not_checked");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        // task 1 never completes, but region never closes either

        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("region_without_close_not_checked");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_region_close(region(0), t(100));

        // Would fail
        let err = oracle.check(t(100)).is_err();
        crate::assert_with_log!(err, "err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let task_count = oracle.task_count();
        crate::assert_with_log!(task_count == 0, "task_count", 0, task_count);
        let completed_count = oracle.completed_count();
        crate::assert_with_log!(completed_count == 0, "completed_count", 0, completed_count);
        let closed_count = oracle.closed_region_count();
        crate::assert_with_log!(closed_count == 0, "closed_count", 0, closed_count);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = TaskLeakViolation {
            region: region(0),
            leaked_tasks: vec![task(1), task(2)],
            region_close_time: t(100),
        };

        let s = violation.to_string();
        let has_leaked = s.contains("leaked");
        crate::assert_with_log!(has_leaked, "leaked text", true, has_leaked);
        let has_two = s.contains('2');
        crate::assert_with_log!(has_two, "contains 2", true, has_two);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn violation_display_snapshot_scrubbed() {
        let violation = TaskLeakViolation {
            region: region(0),
            leaked_tasks: vec![task(1), task(2)],
            region_close_time: t(100),
        };

        insta::assert_snapshot!(
            "task_leak_violation_display_scrubbed",
            scrub_task_leak_display(&violation.to_string())
        );
    }

    #[test]
    fn task_in_multiple_regions_ok() {
        init_test("task_in_multiple_regions_ok");
        // This tests the oracle's behavior - tasks should only be in one region
        // but if a bug causes them to be recorded in multiple, we check per-region
        let mut oracle = TaskLeakOracle::new();

        // Spawn same task in different regions (shouldn't happen in practice)
        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_spawn(task(1), region(1), t(20));

        oracle.on_complete(task(1), t(50));

        oracle.on_region_close(region(0), t(100));
        oracle.on_region_close(region(1), t(100));

        // Should pass because task 1 is marked complete
        let ok = oracle.check(t(100)).is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("task_in_multiple_regions_ok");
    }

    #[test]
    fn many_tasks_some_leaked() {
        init_test("many_tasks_some_leaked");
        let mut oracle = TaskLeakOracle::new();

        // Spawn 5 tasks
        for i in 1..=5 {
            oracle.on_spawn(task(i), region(0), t(u64::from(i) * 10));
        }

        // Complete only odd tasks
        oracle.on_complete(task(1), t(60));
        oracle.on_complete(task(3), t(70));
        oracle.on_complete(task(5), t(80));

        oracle.on_region_close(region(0), t(100));

        let result = oracle.check(t(100));
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        // Tasks 2 and 4 should be leaked
        let len = violation.leaked_tasks.len();
        crate::assert_with_log!(len == 2, "leaked_tasks len", 2, len);
        let has_two = violation.leaked_tasks.contains(&task(2));
        crate::assert_with_log!(has_two, "contains task2", true, has_two);
        let has_four = violation.leaked_tasks.contains(&task(4));
        crate::assert_with_log!(has_four, "contains task4", true, has_four);
        crate::test_complete!("many_tasks_some_leaked");
    }

    #[test]
    fn completion_after_close_still_violates() {
        init_test("completion_after_close_still_violates");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_region_close(region(0), t(100));
        oracle.on_complete(task(1), t(110));

        let violation = oracle
            .check(t(110))
            .expect_err("task completion after close must not erase the violation");
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.leaked_tasks == vec![task(1)],
            "leaked_tasks",
            vec![task(1)],
            violation.leaked_tasks
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "close_time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("completion_after_close_still_violates");
    }

    #[test]
    fn task_spawned_after_region_close_is_violation_even_if_it_completes_later() {
        init_test("task_spawned_after_region_close_is_violation_even_if_it_completes_later");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_region_close(region(0), t(100));
        oracle.on_spawn(task(1), region(0), t(110));
        oracle.on_complete(task(1), t(120));

        let violation = oracle
            .check(t(120))
            .expect_err("task spawned after region close must be reported as a leak");
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.leaked_tasks == vec![task(1)],
            "leaked_tasks",
            vec![task(1)],
            violation.leaked_tasks
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "close_time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!(
            "task_spawned_after_region_close_is_violation_even_if_it_completes_later"
        );
    }

    #[test]
    fn post_close_spawns_merge_into_existing_region_violation() {
        init_test("post_close_spawns_merge_into_existing_region_violation");
        let mut oracle = TaskLeakOracle::new();

        oracle.on_spawn(task(1), region(0), t(10));
        oracle.on_region_close(region(0), t(100));
        oracle.on_spawn(task(2), region(0), t(110));
        oracle.on_complete(task(2), t(120));

        let violation = oracle
            .check(t(120))
            .expect_err("post-close spawns should be merged into the region's leak record");
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.leaked_tasks == vec![task(1), task(2)],
            "leaked_tasks",
            vec![task(1), task(2)],
            violation.leaked_tasks
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "close_time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("post_close_spawns_merge_into_existing_region_violation");
    }

    #[test]
    fn task_leak_violation_debug_clone() {
        let v = TaskLeakViolation {
            region: region(5),
            leaked_tasks: vec![task(1), task(2)],
            region_close_time: t(999),
        };
        let cloned = v.clone();
        assert_eq!(cloned.region, v.region);
        assert_eq!(cloned.leaked_tasks.len(), 2);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("TaskLeakViolation"));
    }

    #[test]
    fn task_leak_oracle_debug_default() {
        let oracle = TaskLeakOracle::default();
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("TaskLeakOracle"));
        let oracle2 = TaskLeakOracle::new();
        let dbg2 = format!("{oracle2:?}");
        assert_eq!(dbg, dbg2);
    }
