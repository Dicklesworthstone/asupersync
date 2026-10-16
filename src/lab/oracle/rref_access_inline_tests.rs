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

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn rref(region_n: u32, alloc: u32) -> RRefId {
        RRefId::new(region(region_n), alloc)
    }

    // ================================================================
    // Positive tests (no violations)
    // ================================================================

    #[test]
    fn same_region_access_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_rref_access(rref(0, 0), tid, t(10));

        assert!(oracle.check().is_ok());
        assert_eq!(oracle.violation_count(), 0);
    }

    #[test]
    fn access_before_close_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_rref_access(rref(0, 0), tid, t(10));
        oracle.on_region_close(r, t(100));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn witness_matching_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_rref_access_with_witness(rref(0, 0), tid, r, t(10));

        assert!(oracle.check().is_ok());
    }

    #[test]
    fn multiple_rrefs_same_region_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_rref_create(rref(0, 1), r);
        oracle.on_rref_create(rref(0, 2), r);
        oracle.on_task_spawn(tid, r);

        oracle.on_rref_access(rref(0, 0), tid, t(10));
        oracle.on_rref_access(rref(0, 1), tid, t(20));
        oracle.on_rref_access(rref(0, 2), tid, t(30));

        assert!(oracle.check().is_ok());
    }

    // ================================================================
    // Cross-region violation tests
    // ================================================================

    #[test]
    fn cross_region_access_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r_a = region(0);
        let r_b = region(1);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r_a);
        oracle.on_task_spawn(tid, r_b); // Task is in region B
        oracle.on_rref_access(rref(0, 0), tid, t(10)); // Accessing region A's RRef

        let err = oracle.check().unwrap_err();
        assert_eq!(
            err.kind,
            RRefAccessViolationKind::CrossRegionAccess {
                rref_region: r_a,
                task_region: r_b,
            }
        );
    }

    // ================================================================
    // Post-close violation tests
    // ================================================================

    #[test]
    fn post_close_access_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(50));
        oracle.on_rref_access(rref(0, 0), tid, t(100)); // After close

        let err = oracle.check().unwrap_err();
        assert_eq!(
            err.kind,
            RRefAccessViolationKind::PostCloseAccess {
                region: r,
                close_time: t(50),
                access_time: t(100),
            }
        );
    }

    #[test]
    fn access_at_close_time_no_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(50));
        oracle.on_rref_access(rref(0, 0), tid, t(50)); // Exactly at close time

        // br-asupersync-wq22bt: Access at close_time should be legal.
        // In virtual time scenarios, multiple events can share the same tick.
        // The runtime synchronizes this boundary with locks, so concurrent
        // access at close_time is legitimate.
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.violation_count(), 0);
    }

    // ================================================================
    // Witness mismatch tests
    // ================================================================

    #[test]
    fn witness_mismatch_detected() {
        let mut oracle = RRefAccessOracle::new();
        let r_a = region(0);
        let r_b = region(1);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r_a);
        oracle.on_task_spawn(tid, r_a);
        // Witness from region B used with region A's RRef
        oracle.on_rref_access_with_witness(rref(0, 0), tid, r_b, t(10));

        let violations = oracle.all_violations();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v.kind, RRefAccessViolationKind::WitnessMismatch { .. }))
        );
    }

    // ================================================================
    // Multiple violation tests
    // ================================================================

    #[test]
    fn multiple_violations_all_recorded() {
        let mut oracle = RRefAccessOracle::new();
        let r_a = region(0);
        let r_b = region(1);
        let t1 = task(1);
        let t2 = task(2);

        oracle.on_rref_create(rref(0, 0), r_a);
        oracle.on_rref_create(rref(1, 0), r_b);
        oracle.on_task_spawn(t1, r_a);
        oracle.on_task_spawn(t2, r_b);

        // Cross-region: t2 accesses region A's rref
        oracle.on_rref_access(rref(0, 0), t2, t(10));
        // Post-close: close region B, then t1 accesses it
        oracle.on_region_close(r_b, t(20));
        oracle.on_rref_access(rref(1, 0), t1, t(30));

        let violations = oracle.all_violations();
        // 3 violations: cross-region (t2→rref in r_a), cross-region (t1→rref in r_b),
        // and post-close (r_b closed before t1 access)
        assert_eq!(violations.len(), 3);
    }

    // ================================================================
    // Reset and stats tests
    // ================================================================

    #[test]
    fn reset_clears_all_state() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(10));
        oracle.on_rref_access(rref(0, 0), tid, t(20));

        assert!(oracle.check().is_err());

        oracle.reset();
        assert!(oracle.check().is_ok());
        assert_eq!(oracle.rref_count(), 0);
        assert_eq!(oracle.task_count(), 0);
        assert_eq!(oracle.closed_region_count(), 0);
        assert_eq!(oracle.violation_count(), 0);
    }

    #[test]
    fn stats_track_entities() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);

        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_rref_create(rref(0, 1), r);
        oracle.on_task_spawn(task(1), r);
        oracle.on_task_spawn(task(2), r);
        oracle.on_task_spawn(task(3), r);
        oracle.on_region_close(r, t(100));

        assert_eq!(oracle.rref_count(), 2);
        assert_eq!(oracle.task_count(), 3);
        assert_eq!(oracle.closed_region_count(), 1);
    }

    #[test]
    fn violation_display_formats() {
        let r_a = region(0);
        let r_b = region(1);
        let tid = task(1);

        let violations = vec![
            RRefAccessViolation {
                rref: rref(0, 0),
                task: tid,
                time: t(10),
                kind: RRefAccessViolationKind::CrossRegionAccess {
                    rref_region: r_a,
                    task_region: r_b,
                },
            },
            RRefAccessViolation {
                rref: rref(0, 0),
                task: tid,
                time: t(100),
                kind: RRefAccessViolationKind::PostCloseAccess {
                    region: r_a,
                    close_time: t(50),
                    access_time: t(100),
                },
            },
            RRefAccessViolation {
                rref: rref(0, 0),
                task: tid,
                time: t(10),
                kind: RRefAccessViolationKind::WitnessMismatch {
                    rref_region: r_a,
                    witness_region: r_b,
                },
            },
        ];

        for v in &violations {
            let msg = format!("{v}");
            assert!(!msg.is_empty(), "violation display should not be empty");
        }
    }

    // --- wave 76 trait coverage ---

    #[test]
    fn rref_id_debug_clone_copy_eq_ord_hash() {
        use std::collections::HashSet;
        let id = rref(0, 5);
        let id2 = id; // Copy
        let id3 = id; // Copy (RRefId is Copy)
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, rref(0, 6));
        assert!(id < rref(0, 6));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("RRefId"));
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&id2));
    }

    #[test]
    fn rref_access_violation_kind_debug_clone_eq() {
        let r_a = region(0);
        let r_b = region(1);
        let k = RRefAccessViolationKind::CrossRegionAccess {
            rref_region: r_a,
            task_region: r_b,
        };
        let k2 = k.clone();
        assert_eq!(k, k2);
        assert_ne!(
            k,
            RRefAccessViolationKind::WitnessMismatch {
                rref_region: r_a,
                witness_region: r_b,
            }
        );
        let dbg = format!("{k:?}");
        assert!(dbg.contains("CrossRegionAccess"));
    }

    #[test]
    fn rref_access_violation_debug_clone() {
        let v = RRefAccessViolation {
            rref: rref(0, 1),
            task: task(2),
            time: t(100),
            kind: RRefAccessViolationKind::PostCloseAccess {
                region: region(0),
                close_time: t(50),
                access_time: t(100),
            },
        };
        let v2 = v.clone();
        assert_eq!(v.rref, v2.rref);
        assert_eq!(v.task, v2.task);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("RRefAccessViolation"));
    }

    // ================================================================
    // br-asupersync-1j14du: at-boundary access (time == close_time)
    // is now legal — strict `>` instead of `>=`.
    // ================================================================

    #[test]
    fn _1j14du_access_at_close_time_is_not_a_violation() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);
        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(50));
        // Access stamped exactly at close_time: legal (immediately
        // before close, or simultaneously, both resolved by the
        // runtime's lock).
        oracle.on_rref_access(rref(0, 0), tid, t(50));
        assert!(oracle.check().is_ok(), "at-boundary access must not fire");
        assert_eq!(oracle.violation_count(), 0);
    }

    #[test]
    fn _1j14du_access_strictly_after_close_still_fires() {
        let mut oracle = RRefAccessOracle::new();
        let r = region(0);
        let tid = task(1);
        oracle.on_rref_create(rref(0, 0), r);
        oracle.on_task_spawn(tid, r);
        oracle.on_region_close(r, t(50));
        // Access strictly after close: violation must fire.
        oracle.on_rref_access(rref(0, 0), tid, t(51));
        assert_eq!(oracle.violation_count(), 1);
    }
