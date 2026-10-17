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

    #[test]
    fn no_finalizers_passes() {
        init_test("no_finalizers_passes");
        let oracle = FinalizerOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("no_finalizers_passes");
    }

    #[test]
    fn all_finalizers_run_passes() {
        init_test("all_finalizers_run_passes");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        let f2 = oracle.generate_id();

        oracle.on_register(f1, region(0), t(10));
        oracle.on_register(f2, region(0), t(20));

        oracle.on_run(f1, t(50));
        oracle.on_run(f2, t(60));

        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("all_finalizers_run_passes");
    }

    #[test]
    fn unrun_finalizer_fails() {
        init_test("unrun_finalizer_fails");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        let f2 = oracle.generate_id();

        oracle.on_register(f1, region(0), t(10));
        oracle.on_register(f2, region(0), t(20));

        // Only f1 runs
        oracle.on_run(f1, t(50));

        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "violation region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![f2],
            "unrun finalizers",
            vec![f2],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "region close time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("unrun_finalizer_fails");
    }

    #[test]
    fn no_finalizers_run_all_fail() {
        init_test("no_finalizers_run_all_fail");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        let f2 = oracle.generate_id();

        oracle.on_register(f1, region(0), t(10));
        oracle.on_register(f2, region(0), t(20));

        // No finalizers run
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        let count = violation.unrun_finalizers.len();
        crate::assert_with_log!(count == 2, "unrun finalizers", 2, count);
        crate::test_complete!("no_finalizers_run_all_fail");
    }

    #[test]
    fn multiple_regions_independent() {
        init_test("multiple_regions_independent");
        let mut oracle = FinalizerOracle::new();

        // Region 0: finalizer runs
        let f1 = oracle.generate_id();
        oracle.on_register(f1, region(0), t(10));
        oracle.on_run(f1, t(50));
        oracle.on_region_close(region(0), t(100));

        // Region 1: finalizer does NOT run
        let f2 = oracle.generate_id();
        oracle.on_register(f2, region(1), t(20));
        oracle.on_region_close(region(1), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(1),
            "violation region",
            region(1),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![f2],
            "unrun finalizers",
            vec![f2],
            violation.unrun_finalizers
        );
        crate::test_complete!("multiple_regions_independent");
    }

    #[test]
    fn check_reports_regions_and_finalizers_in_stable_order() {
        init_test("check_reports_regions_and_finalizers_in_stable_order");
        let mut oracle = FinalizerOracle::new();

        let region0_f1 = oracle.generate_id();
        let region0_f0 = oracle.generate_id();
        let region1_f0 = oracle.generate_id();

        oracle.on_register(region1_f0, region(1), t(10));
        oracle.on_region_close(region(1), t(200));

        oracle.on_register(region0_f1, region(0), t(20));
        oracle.on_register(region0_f0, region(0), t(30));
        oracle.on_region_close(region(0), t(100));

        let violation = oracle
            .check()
            .expect_err("lower region id should be reported first");
        crate::assert_with_log!(
            violation.region == region(0),
            "violation region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![region0_f1, region0_f0],
            "sorted unrun finalizers",
            vec![region0_f1, region0_f0],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "region close time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("check_reports_regions_and_finalizers_in_stable_order");
    }

    #[test]
    fn finalizer_run_after_close_still_violates() {
        init_test("finalizer_run_after_close_still_violates");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_region_close(region(0), t(100));
        oracle.on_run(finalizer, t(110));

        let violation = oracle
            .check()
            .expect_err("running a finalizer after close must not erase the violation");
        crate::assert_with_log!(
            violation.region == region(0),
            "violation region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![finalizer],
            "unrun finalizers",
            vec![finalizer],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "region close time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("finalizer_run_after_close_still_violates");
    }

    #[test]
    fn reregistered_finalizer_moves_out_of_previous_region() {
        init_test("reregistered_finalizer_moves_out_of_previous_region");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_register(finalizer, region(1), t(20));

        oracle.on_region_close(region(0), t(30));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("reregistered_finalizer_moves_out_of_previous_region");
    }

    #[test]
    fn reregistered_finalizer_requires_a_fresh_run() {
        init_test("reregistered_finalizer_requires_a_fresh_run");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_run(finalizer, t(20));

        oracle.on_register(finalizer, region(1), t(30));
        oracle.on_region_close(region(1), t(40));

        let violation = oracle
            .check()
            .expect_err("re-registering a finalizer must require a new run");
        crate::assert_with_log!(
            violation.region == region(1),
            "violation region",
            region(1),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![finalizer],
            "unrun finalizers",
            vec![finalizer],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(40),
            "region close time",
            t(40),
            violation.region_close_time
        );
        crate::test_complete!("reregistered_finalizer_requires_a_fresh_run");
    }

    #[test]
    fn exact_duplicate_registration_preserves_completed_state() {
        init_test("exact_duplicate_registration_preserves_completed_state");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_run(finalizer, t(20));

        // Duplicate event for the same registration should be idempotent.
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_region_close(region(0), t(30));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let ran = oracle.ran_count();
        crate::assert_with_log!(ran == 1, "ran count", 1, ran);
        crate::test_complete!("exact_duplicate_registration_preserves_completed_state");
    }

    #[test]
    fn region_without_close_not_checked() {
        init_test("region_without_close_not_checked");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        oracle.on_register(f1, region(0), t(10));
        // f1 never runs, but region never closes either

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("region_without_close_not_checked");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        oracle.on_register(f1, region(0), t(10));
        oracle.on_region_close(region(0), t(100));

        // Would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "oracle err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let registered = oracle.registered_count();
        crate::assert_with_log!(registered == 0, "registered count", 0, registered);
        let ran = oracle.ran_count();
        crate::assert_with_log!(ran == 0, "ran count", 0, ran);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = FinalizerViolation {
            region: region(0),
            unrun_finalizers: vec![FinalizerId(1), FinalizerId(2)],
            region_close_time: t(100),
        };

        let s = violation.to_string();
        let has_region = s.contains("Region");
        crate::assert_with_log!(has_region, "contains Region", true, has_region);
        let has_unrun = s.contains("unrun finalizer");
        crate::assert_with_log!(has_unrun, "contains unrun", true, has_unrun);
        let has_two = s.contains('2');
        crate::assert_with_log!(has_two, "contains 2", true, has_two);
        crate::test_complete!("violation_display");
    }

    // --- wave 76 trait coverage ---

    #[test]
    fn finalizer_id_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let id = FinalizerId(42);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, FinalizerId(99));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"));
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&id2));
    }

    #[test]
    fn finalizer_violation_debug_clone() {
        let v = FinalizerViolation {
            region: region(0),
            unrun_finalizers: vec![FinalizerId(1), FinalizerId(2)],
            region_close_time: t(100),
        };
        let v2 = v.clone();
        assert_eq!(v.region, v2.region);
        assert_eq!(v.unrun_finalizers, v2.unrun_finalizers);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("FinalizerViolation"));
    }
