    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationKind;
    use crate::types::{CancelReason, Time};

    // === Helper constructors ===

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn handoff_dependencies_preserve_both_owners_regions_and_terminal_order() {
        let id = ObligationId::new_for_test(3, 1);
        let handoff = super::super::event::ObligationHandoff {
            id,
            source_ticket: 3,
            destination_ticket: 4,
            source_holder: tid(1),
            destination_holder: tid(2),
            source_region: rid(1),
            destination_region: rid(2),
        };
        let event = TraceEvent::obligation_handoff(1, Time::ZERO, &handoff);
        let related = [
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(3, Time::ZERO, tid(2), rid(2)),
            TraceEvent::new(
                4,
                Time::ZERO,
                TraceEventKind::RegionCloseComplete,
                TraceData::Region {
                    region: rid(1),
                    parent: None,
                },
            ),
            TraceEvent::new(
                5,
                Time::ZERO,
                TraceEventKind::RegionCloseBegin,
                TraceData::Region {
                    region: rid(2),
                    parent: None,
                },
            ),
            TraceEvent::obligation_commit(
                6,
                Time::ZERO,
                id,
                tid(2),
                rid(2),
                ObligationKind::Lease,
                1,
            ),
        ];
        for other in &related {
            assert!(!independent(&event, other));
            assert!(!independent(other, &event));
        }
        let unrelated = TraceEvent::complete(7, Time::ZERO, tid(9), rid(9));
        assert!(independent(&event, &unrelated));
        assert!(independent(&unrelated, &event));
        let malformed = TraceEvent::user_trace(8, Time::ZERO, "obligation_handoff_v1 {}");
        let ordinary = TraceEvent::user_trace(9, Time::ZERO, "ordinary annotation");
        for other in related.iter().chain([&unrelated, &ordinary, &event]) {
            assert!(!independent(&malformed, other));
            assert!(!independent(other, &malformed));
        }
        assert!(independent(&event, &ordinary));
    }

    fn oid(n: u32) -> ObligationId {
        ObligationId::new_for_test(n, 0)
    }

    // === Irreflexivity ===

    #[test]
    fn irreflexive_spawn() {
        let e = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&e, &e));
    }

    #[test]
    fn irreflexive_user_trace() {
        let e = TraceEvent::user_trace(1, Time::ZERO, "hello");
        assert!(!independent(&e, &e));
    }

    // === Symmetry ===

    #[test]
    fn symmetry_dependent() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::complete(2, Time::ZERO, tid(1), rid(1));
        assert_eq!(independent(&a, &b), independent(&b, &a));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn symmetry_independent() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        assert_eq!(independent(&a, &b), independent(&b, &a));
        assert!(independent(&a, &b));
    }

    // === Task events ===

    #[test]
    fn same_task_events_are_dependent() {
        let a = TraceEvent::schedule(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::complete(2, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn different_tasks_different_regions_are_independent() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        assert!(independent(&a, &b));
    }

    #[test]
    fn different_tasks_same_region_are_independent() {
        // Both only read the region, so no conflict.
        let a = TraceEvent::schedule(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::schedule(2, Time::ZERO, tid(2), rid(1));
        assert!(independent(&a, &b));
    }

    // === Cancel events ===

    #[test]
    fn cancel_request_conflicts_with_task_in_same_region() {
        // CancelRequest writes region, Spawn reads region -> conflict.
        let a =
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), CancelReason::user("test"));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(1));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn cancel_request_independent_of_different_region() {
        let a =
            TraceEvent::cancel_request(1, Time::ZERO, tid(1), rid(1), CancelReason::user("test"));
        let b = TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2));
        assert!(independent(&a, &b));
    }

    // === Region events ===

    #[test]
    fn region_create_conflicts_with_spawn_in_same_region() {
        // RegionCreated writes R1, Spawn reads R1 -> conflict.
        let a = TraceEvent::region_created(1, Time::ZERO, rid(1), None);
        let b = TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&a, &b));
    }

    #[test]
    fn region_create_independent_of_different_region_task() {
        let a = TraceEvent::region_created(1, Time::ZERO, rid(1), None);
        let b = TraceEvent::spawn(2, Time::ZERO, tid(1), rid(2));
        assert!(independent(&a, &b));
    }

    #[test]
    fn child_region_create_depends_on_parent_region_events() {
        // Child region reads parent; region cancel writes parent -> conflict.
        let a = TraceEvent::region_created(1, Time::ZERO, rid(2), Some(rid(1)));
        let b = TraceEvent::region_cancelled(2, Time::ZERO, rid(1), CancelReason::user("test"));
        assert!(!independent(&a, &b));
    }

    // === Obligation events ===

    #[test]
    fn same_obligation_events_are_dependent() {
        let a = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        );
        let b = TraceEvent::obligation_commit(
            2,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
            1000,
        );
        assert!(!independent(&a, &b));
    }

    #[test]
    fn different_obligation_events_are_independent() {
        let a = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        );
        let b = TraceEvent::obligation_reserve(
            2,
            Time::ZERO,
            oid(2),
            tid(2),
            rid(2),
            ObligationKind::Ack,
        );
        assert!(independent(&a, &b));
    }

    #[test]
    fn obligation_conflicts_with_task_write_on_same_task() {
        // Obligation reads task; task event writes task -> conflict.
        let a = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::SendPermit,
        );
        let b = TraceEvent::complete(2, Time::ZERO, tid(1), rid(1));
        assert!(!independent(&a, &b));
    }

    // === Timer events ===

    #[test]
    fn time_advance_conflicts_with_timer() {
        let a = TraceEvent::time_advance(1, Time::ZERO, Time::ZERO, Time::from_nanos(1000));
        let b = TraceEvent::timer_fired(2, Time::ZERO, 42);
        assert!(!independent(&a, &b));
    }

    #[test]
    fn different_timers_are_independent() {
        let a = TraceEvent::timer_scheduled(1, Time::ZERO, 1, Time::from_nanos(1000));
        let b = TraceEvent::timer_scheduled(2, Time::ZERO, 2, Time::from_nanos(2000));
        assert!(independent(&a, &b));
    }

    #[test]
    fn same_timer_events_are_dependent() {
        let a = TraceEvent::timer_scheduled(1, Time::ZERO, 42, Time::from_nanos(1000));
        let b = TraceEvent::timer_fired(2, Time::ZERO, 42);
        assert!(!independent(&a, &b));
    }

    // === I/O events ===

    #[test]
    fn different_io_tokens_are_independent() {
        let a = TraceEvent::io_ready(1, Time::ZERO, 10, 0x01);
        let b = TraceEvent::io_ready(2, Time::ZERO, 20, 0x02);
        assert!(independent(&a, &b));
    }

    #[test]
    fn same_io_token_events_are_dependent() {
        let a = TraceEvent::io_requested(1, Time::ZERO, 10, 0x01);
        let b = TraceEvent::io_result(2, Time::ZERO, 10, 512);
        assert!(!independent(&a, &b));
    }

    // === RNG events ===

    #[test]
    fn rng_events_are_dependent() {
        let a = TraceEvent::rng_seed(1, Time::ZERO, 0xDEAD);
        let b = TraceEvent::rng_value(2, Time::ZERO, 42);
        assert!(!independent(&a, &b));
    }

    #[test]
    fn rng_independent_of_task_events() {
        let a = TraceEvent::rng_value(1, Time::ZERO, 42);
        let b = TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1));
        assert!(independent(&a, &b));
    }

    // === UserTrace ===

    #[test]
    fn user_trace_independent_of_everything() {
        let u = TraceEvent::user_trace(1, Time::ZERO, "annotation");
        let events = [
            TraceEvent::spawn(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::time_advance(3, Time::ZERO, Time::ZERO, Time::from_nanos(1)),
            TraceEvent::rng_value(4, Time::ZERO, 42),
            TraceEvent::io_ready(5, Time::ZERO, 1, 0x01),
            TraceEvent::timer_fired(6, Time::ZERO, 1),
            TraceEvent::checkpoint(7, Time::ZERO, 1, 10, 5),
        ];
        for e in &events {
            assert!(
                independent(&u, e),
                "UserTrace should be independent of {:?}",
                e.kind
            );
            assert!(
                independent(e, &u),
                "Symmetry: {:?} should be independent of UserTrace",
                e.kind
            );
        }
    }

    // === Checkpoint ===

    #[test]
    fn checkpoints_are_independent_of_each_other() {
        // Both read GlobalState — no conflict.
        let a = TraceEvent::checkpoint(1, Time::ZERO, 1, 10, 5);
        let b = TraceEvent::checkpoint(2, Time::ZERO, 2, 12, 6);
        assert!(independent(&a, &b));
    }

    #[test]
    fn checkpoint_conflicts_with_chaos_injection() {
        // Checkpoint reads GlobalState, ChaosInjection writes GlobalState.
        let a = TraceEvent::checkpoint(1, Time::ZERO, 1, 10, 5);
        let b = TraceEvent::new(
            2,
            Time::ZERO,
            TraceEventKind::ChaosInjection,
            TraceData::Chaos {
                kind: "delay".into(),
                task: None,
                detail: "test".into(),
            },
        );
        assert!(!independent(&a, &b));
    }

    // === Cross-category independence ===

    #[test]
    fn task_event_independent_of_unrelated_io() {
        let a = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let b = TraceEvent::io_ready(2, Time::ZERO, 99, 0x01);
        assert!(independent(&a, &b));
    }

    #[test]
    fn timer_independent_of_obligation() {
        let a = TraceEvent::timer_fired(1, Time::ZERO, 1);
        let b = TraceEvent::obligation_reserve(
            2,
            Time::ZERO,
            oid(1),
            tid(1),
            rid(1),
            ObligationKind::Lease,
        );
        assert!(independent(&a, &b));
    }

    // === Resource footprint ===

    #[test]
    fn spawn_footprint() {
        let e = TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1));
        let fp = resource_footprint(&e);
        assert_eq!(fp.len(), 2);
        assert_eq!(fp[0], ResourceAccess::write(Resource::Task(tid(1))));
        assert_eq!(fp[1], ResourceAccess::read(Resource::Region(rid(1))));
    }

    #[test]
    fn user_trace_empty_footprint() {
        let e = TraceEvent::user_trace(1, Time::ZERO, "no resources");
        let fp = resource_footprint(&e);
        assert!(fp.is_empty());
    }

    #[test]
    fn obligation_footprint_has_three_accesses() {
        let e = TraceEvent::obligation_reserve(
            1,
            Time::ZERO,
            oid(5),
            tid(3),
            rid(2),
            ObligationKind::Lease,
        );
        let fp = resource_footprint(&e);
        assert_eq!(fp.len(), 3);
        assert_eq!(fp[0], ResourceAccess::write(Resource::Obligation(oid(5))));
        assert_eq!(fp[1], ResourceAccess::read(Resource::Task(tid(3))));
        assert_eq!(fp[2], ResourceAccess::read(Resource::Region(rid(2))));
    }

    // === Conflict function ===

    #[test]
    fn two_reads_do_not_conflict() {
        let a = ResourceAccess::read(Resource::Task(tid(1)));
        let b = ResourceAccess::read(Resource::Task(tid(1)));
        assert!(!accesses_conflict(&a, &b));
    }

    #[test]
    fn read_write_conflict() {
        let a = ResourceAccess::read(Resource::Task(tid(1)));
        let b = ResourceAccess::write(Resource::Task(tid(1)));
        assert!(accesses_conflict(&a, &b));
    }

    #[test]
    fn write_write_conflict() {
        let a = ResourceAccess::write(Resource::Task(tid(1)));
        let b = ResourceAccess::write(Resource::Task(tid(1)));
        assert!(accesses_conflict(&a, &b));
    }

    #[test]
    fn different_resources_no_conflict() {
        let a = ResourceAccess::write(Resource::Task(tid(1)));
        let b = ResourceAccess::write(Resource::Task(tid(2)));
        assert!(!accesses_conflict(&a, &b));
    }

    #[test]
    fn access_mode_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = AccessMode::Read;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, AccessMode::Write);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Read"));
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }
