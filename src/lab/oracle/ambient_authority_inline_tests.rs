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

    #[test]
    fn empty_oracle_passes() {
        init_test("empty_oracle_passes");
        let oracle = AmbientAuthorityOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("empty_oracle_passes");
    }

    #[test]
    fn root_task_has_full_capabilities() {
        init_test("root_task_has_full_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));

        // Root task should have all capabilities
        let has_spawn = oracle.task_has_capability(task(1), CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "has spawn", true, has_spawn);
        let has_time = oracle.task_has_capability(task(1), CapabilityKind::Time);
        crate::assert_with_log!(has_time, "has time", true, has_time);
        let has_trace = oracle.task_has_capability(task(1), CapabilityKind::Trace);
        crate::assert_with_log!(has_trace, "has trace", true, has_trace);
        let has_region = oracle.task_has_capability(task(1), CapabilityKind::Region);
        crate::assert_with_log!(has_region, "has region", true, has_region);
        let has_obligation = oracle.task_has_capability(task(1), CapabilityKind::Obligation);
        crate::assert_with_log!(has_obligation, "has obligation", true, has_obligation);
        crate::test_complete!("root_task_has_full_capabilities");
    }

    #[test]
    fn child_inherits_parent_capabilities() {
        init_test("child_inherits_parent_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));

        // Child should inherit parent's full capabilities
        let has_spawn = oracle.task_has_capability(task(2), CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "child has spawn", true, has_spawn);
        let has_time = oracle.task_has_capability(task(2), CapabilityKind::Time);
        crate::assert_with_log!(has_time, "child has time", true, has_time);
        crate::test_complete!("child_inherits_parent_capabilities");
    }

    #[test]
    fn child_with_missing_parent_has_no_capabilities() {
        init_test("child_with_missing_parent_has_no_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        // Parent task(99) was never created.
        oracle.on_task_created(task(2), region(0), Some(task(99)), t(10));

        let has_spawn = oracle.task_has_capability(task(2), CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "child spawn denied", false, has_spawn);
        let has_time = oracle.task_has_capability(task(2), CapabilityKind::Time);
        crate::assert_with_log!(!has_time, "child time denied", false, has_time);

        // Attempting an effect must be flagged as unauthorized.
        oracle.on_spawn_effect(task(2), task(3), t(20));
        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(2),
            "violation task",
            task(2),
            violation.task
        );
        let empty = violation.granted_capabilities.is_empty();
        crate::assert_with_log!(empty, "capabilities empty", true, empty);
        crate::test_complete!("child_with_missing_parent_has_no_capabilities");
    }

    #[test]
    fn authorized_spawn_passes() {
        init_test("authorized_spawn_passes");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("authorized_spawn_passes");
    }

    #[test]
    fn unauthorized_spawn_fails() {
        init_test("unauthorized_spawn_fails");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));

        // Now task 1 tries to spawn without capability
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(1),
            "violation task",
            task(1),
            violation.task
        );
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Spawn,
            "required capability",
            CapabilityKind::Spawn,
            violation.required_capability
        );
        crate::test_complete!("unauthorized_spawn_fails");
    }

    #[test]
    fn unauthorized_time_access_fails() {
        init_test("unauthorized_time_access_fails");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Time, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));

        oracle.on_time_access(task(1), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Time,
            "required capability",
            CapabilityKind::Time,
            violation.required_capability
        );
        crate::test_complete!("unauthorized_time_access_fails");
    }

    #[test]
    fn regranting_capability_passes() {
        init_test("regranting_capability_passes");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(8));

        oracle.on_spawn_effect(task(1), task(2), t(10));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("regranting_capability_passes");
    }

    #[test]
    fn later_grant_does_not_retroactively_authorize_effect() {
        init_test("later_grant_does_not_retroactively_authorize_effect");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(20));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.time == t(10),
            "violation time",
            t(10),
            violation.time
        );
        crate::test_complete!("later_grant_does_not_retroactively_authorize_effect");
    }

    #[test]
    fn later_revoke_does_not_retroactively_invalidate_effect() {
        init_test("later_revoke_does_not_retroactively_invalidate_effect");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(20));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("later_revoke_does_not_retroactively_invalidate_effect");
    }

    #[test]
    fn capability_lookup_uses_latest_timestamp_not_insertion_order() {
        init_test("capability_lookup_uses_latest_timestamp_not_insertion_order");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(8));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("capability_lookup_uses_latest_timestamp_not_insertion_order");
    }

    #[test]
    fn child_inheritance_uses_parent_capabilities_at_child_creation_time() {
        init_test("child_inheritance_uses_parent_capabilities_at_child_creation_time");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(20));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));
        oracle.on_spawn_effect(task(2), task(3), t(15));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("child_inheritance_uses_parent_capabilities_at_child_creation_time");
    }

    #[test]
    fn later_parent_grant_does_not_retroactively_authorize_child_inheritance() {
        init_test("later_parent_grant_does_not_retroactively_authorize_child_inheritance");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_granted(task(1), CapabilityKind::Spawn, t(20));
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));
        oracle.on_spawn_effect(task(2), task(3), t(15));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(2),
            "violation task",
            task(2),
            violation.task
        );
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Spawn,
            "required capability",
            CapabilityKind::Spawn,
            violation.required_capability
        );
        crate::test_complete!(
            "later_parent_grant_does_not_retroactively_authorize_child_inheritance"
        );
    }

    #[test]
    fn unknown_task_fails() {
        init_test("unknown_task_fails");
        let mut oracle = AmbientAuthorityOracle::new();

        // Task 1 never created, tries to spawn
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(1),
            "violation task",
            task(1),
            violation.task
        );
        let empty = violation.granted_capabilities.is_empty();
        crate::assert_with_log!(empty, "capabilities empty", true, empty);
        crate::test_complete!("unknown_task_fails");
    }

    #[test]
    fn multiple_effects_all_authorized() {
        init_test("multiple_effects_all_authorized");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));

        oracle.on_spawn_effect(task(1), task(2), t(10));
        oracle.on_time_access(task(1), t(20));
        oracle.on_trace(task(1), "hello", t(30));
        oracle.on_region_create(task(1), region(1), t(40));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let count = oracle.effect_count();
        crate::assert_with_log!(count == 4, "effect count", 4, count);
        crate::test_complete!("multiple_effects_all_authorized");
    }

    #[test]
    fn child_with_narrowed_capabilities() {
        init_test("child_with_narrowed_capabilities");
        let mut oracle = AmbientAuthorityOracle::new();

        // Parent with full capabilities
        oracle.on_task_created(task(1), region(0), None, t(0));

        // Child inherits, then narrows
        oracle.on_task_created(task(2), region(0), Some(task(1)), t(10));
        oracle.on_capability_revoked(task(2), CapabilityKind::Spawn, t(15));
        oracle.on_capability_revoked(task(2), CapabilityKind::Full, t(15));

        // Child tries to spawn - should fail
        oracle.on_spawn_effect(task(2), task(3), t(20));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);
        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.task == task(2),
            "violation task",
            task(2),
            violation.task
        );
        crate::test_complete!("child_with_narrowed_capabilities");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));
        oracle.on_capability_revoked(task(1), CapabilityKind::Full, t(5));
        oracle.on_spawn_effect(task(1), task(2), t(10));

        // Would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "oracle err", true, err);

        oracle.reset();

        // After reset, no violations (no effects tracked)
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let effect_count = oracle.effect_count();
        crate::assert_with_log!(effect_count == 0, "effect count", 0, effect_count);
        let task_count = oracle.task_count();
        crate::assert_with_log!(task_count == 0, "task count", 0, task_count);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn capability_set_full_implies_all() {
        init_test("capability_set_full_implies_all");
        let full = CapabilitySet::full();

        let has_spawn = full.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "has spawn", true, has_spawn);
        let has_time = full.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "has time", true, has_time);
        let has_trace = full.has(CapabilityKind::Trace);
        crate::assert_with_log!(has_trace, "has trace", true, has_trace);
        let has_region = full.has(CapabilityKind::Region);
        crate::assert_with_log!(has_region, "has region", true, has_region);
        let has_obligation = full.has(CapabilityKind::Obligation);
        crate::assert_with_log!(has_obligation, "has obligation", true, has_obligation);
        let has_full = full.has(CapabilityKind::Full);
        crate::assert_with_log!(has_full, "has full", true, has_full);
        crate::test_complete!("capability_set_full_implies_all");
    }

    #[test]
    fn capability_set_individual_grants() {
        init_test("capability_set_individual_grants");
        let mut caps = CapabilitySet::empty();

        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "spawn missing", false, has_spawn);

        caps.grant(CapabilityKind::Spawn);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "spawn granted", true, has_spawn);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(!has_time, "time missing", false, has_time);

        caps.grant(CapabilityKind::Time);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time granted", true, has_time);

        caps.revoke(CapabilityKind::Spawn);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "spawn revoked", false, has_spawn);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time still", true, has_time);
        crate::test_complete!("capability_set_individual_grants");
    }

    #[test]
    fn revoke_clears_full_meta_capability() {
        init_test("revoke_clears_full_meta_capability");
        let mut caps = CapabilitySet::full();

        // Full set implies Spawn
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "spawn via full", true, has_spawn);

        // Revoke Spawn — should also clear Full
        caps.revoke(CapabilityKind::Spawn);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(!has_spawn, "spawn revoked", false, has_spawn);
        let has_full = caps.has(CapabilityKind::Full);
        crate::assert_with_log!(!has_full, "full cleared", false, has_full);

        // Other individual capabilities remain
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time remains", true, has_time);
        let has_trace = caps.has(CapabilityKind::Trace);
        crate::assert_with_log!(has_trace, "trace remains", true, has_trace);
        let has_region = caps.has(CapabilityKind::Region);
        crate::assert_with_log!(has_region, "region remains", true, has_region);
        let has_obligation = caps.has(CapabilityKind::Obligation);
        crate::assert_with_log!(has_obligation, "obligation remains", true, has_obligation);
        crate::test_complete!("revoke_clears_full_meta_capability");
    }

    #[test]
    fn revoke_full_directly_leaves_individual_caps() {
        init_test("revoke_full_directly_leaves_individual_caps");
        let mut caps = CapabilitySet::full();

        // Revoke Full directly — individual caps still present
        caps.revoke(CapabilityKind::Full);
        let has_full = caps.has(CapabilityKind::Full);
        crate::assert_with_log!(!has_full, "full revoked", false, has_full);
        let has_spawn = caps.has(CapabilityKind::Spawn);
        crate::assert_with_log!(has_spawn, "spawn remains", true, has_spawn);
        let has_time = caps.has(CapabilityKind::Time);
        crate::assert_with_log!(has_time, "time remains", true, has_time);
        crate::test_complete!("revoke_full_directly_leaves_individual_caps");
    }

    #[test]
    fn revoke_from_full_then_oracle_detects_violation() {
        init_test("revoke_from_full_then_oracle_detects_violation");
        let mut oracle = AmbientAuthorityOracle::new();

        // Root task with full capabilities
        oracle.on_task_created(task(1), region(0), None, t(0));

        // Revoke only Spawn (Full should also be cleared internally)
        oracle.on_capability_revoked(task(1), CapabilityKind::Spawn, t(5));

        // Attempt spawn — should fail
        oracle.on_spawn_effect(task(1), task(2), t(10));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "violation detected", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.required_capability == CapabilityKind::Spawn,
            "required spawn",
            CapabilityKind::Spawn,
            violation.required_capability
        );
        crate::test_complete!("revoke_from_full_then_oracle_detects_violation");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = AmbientAuthorityViolation {
            task: task(1),
            required_capability: CapabilityKind::Spawn,
            effect_description: "spawn child task".to_string(),
            granted_capabilities: vec![CapabilityKind::Time, CapabilityKind::Trace],
            time: t(100),
        };

        let s = violation.to_string();
        let has_spawn = s.contains("spawn");
        crate::assert_with_log!(has_spawn, "contains spawn", true, has_spawn);
        let has_time = s.contains("Time");
        crate::assert_with_log!(has_time, "contains Time", true, has_time);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn generic_effect_tracking() {
        init_test("generic_effect_tracking");
        let mut oracle = AmbientAuthorityOracle::new();

        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_effect(
            task(1),
            CapabilityKind::Time,
            "custom time operation",
            t(10),
        );

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let count = oracle.effect_count();
        crate::assert_with_log!(count == 1, "effect count", 1, count);
        crate::test_complete!("generic_effect_tracking");
    }

    #[test]
    fn multiple_tasks_independent() {
        init_test("multiple_tasks_independent");
        let mut oracle = AmbientAuthorityOracle::new();

        // Task 1: full capabilities
        oracle.on_task_created(task(1), region(0), None, t(0));
        oracle.on_spawn_effect(task(1), task(3), t(10));

        // Task 2: no spawn capability
        oracle.on_task_created(task(2), region(0), None, t(5));
        oracle.on_capability_revoked(task(2), CapabilityKind::Spawn, t(6));
        oracle.on_capability_revoked(task(2), CapabilityKind::Full, t(6));
        // Task 2 does NOT spawn, so no violation

        // Task 2 does access time (which it still has)
        oracle.on_time_access(task(2), t(15));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("multiple_tasks_independent");
    }
