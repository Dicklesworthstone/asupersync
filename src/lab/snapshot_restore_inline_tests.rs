    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::state::IdSnapshot;
    use crate::runtime::state::{
        BudgetSnapshot, ObligationKindSnapshot, ObligationSnapshot, RegionSnapshot,
    };

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn snap_id(index: u32, generation: u32) -> IdSnapshot {
        IdSnapshot { index, generation }
    }

    fn make_region(id: u32, parent: Option<u32>, state: RegionStateSnapshot) -> RegionSnapshot {
        RegionSnapshot {
            id: snap_id(id, 0),
            parent_id: parent.map(|p| snap_id(p, 0)),
            state,
            budget: BudgetSnapshot {
                deadline: None,
                poll_quota: 1000,
                cost_quota: None,
                priority: 100,
            },
            child_count: 0,
            task_count: 0,
            name: None,
        }
    }

    fn make_task(id: u32, region_id: u32, state: TaskStateSnapshot) -> TaskSnapshot {
        TaskSnapshot {
            id: snap_id(id, 0),
            region_id: snap_id(region_id, 0),
            state,
            name: None,
            poll_count: 0,
            created_at: 0,
            obligations: Vec::new(),
        }
    }

    fn make_obligation(
        id: u32,
        task_id: u32,
        state: ObligationStateSnapshot,
    ) -> ObligationSnapshot {
        make_obligation_in_region(id, task_id, 0, state)
    }

    fn make_obligation_in_region(
        id: u32,
        task_id: u32,
        owning_region: u32,
        state: ObligationStateSnapshot,
    ) -> ObligationSnapshot {
        ObligationSnapshot {
            id: snap_id(id, 0),
            kind: ObligationKindSnapshot::SendPermit,
            state,
            holder_task: snap_id(task_id, 0),
            owning_region: snap_id(owning_region, 0),
            created_at: 0,
        }
    }

    fn make_snapshot(
        regions: Vec<RegionSnapshot>,
        tasks: Vec<TaskSnapshot>,
        obligations: Vec<ObligationSnapshot>,
    ) -> RestorableSnapshot {
        RestorableSnapshot::new(RuntimeSnapshot {
            timestamp: 1000,
            regions,
            tasks,
            obligations,
            recent_events: Vec::new(),
            finalizer_history: Vec::new(),
            loser_drain_history: Vec::new(),
        })
    }

    #[test]
    fn empty_snapshot_is_valid() {
        init_test("empty_snapshot_is_valid");
        let snapshot = make_snapshot(Vec::new(), Vec::new(), Vec::new());
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        let errors_empty = result.errors.is_empty();
        crate::assert_with_log!(errors_empty, "errors empty", true, errors_empty);
        crate::test_complete!("empty_snapshot_is_valid");
    }

    #[test]
    fn single_region_is_valid() {
        init_test("single_region_is_valid");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.region_count == 1,
            "region_count",
            1,
            result.stats.region_count
        );
        crate::test_complete!("single_region_is_valid");
    }

    #[test]
    fn task_with_valid_region_is_valid() {
        init_test("task_with_valid_region_is_valid");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.task_count == 1,
            "task_count",
            1,
            result.stats.task_count
        );
        crate::test_complete!("task_with_valid_region_is_valid");
    }

    #[test]
    fn orphan_task_detected() {
        init_test("orphan_task_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 99, TaskStateSnapshot::Running)], // region 99 doesn't exist
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::OrphanTask { .. }));
        crate::assert_with_log!(has_error, "has OrphanTask error", true, has_error);
        crate::test_complete!("orphan_task_detected");
    }

    #[test]
    fn task_with_stale_region_generation_is_orphaned() {
        init_test("task_with_stale_region_generation_is_orphaned");
        let mut snapshot = make_snapshot(
            vec![make_region(7, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 7, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        snapshot.snapshot.regions[0].id = snap_id(7, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::OrphanTask {
                    task_id: 0,
                    region_id: 7,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields OrphanTask",
            true,
            has_error
        );
        crate::test_complete!("task_with_stale_region_generation_is_orphaned");
    }

    #[test]
    fn orphan_obligation_detected() {
        init_test("orphan_obligation_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 99, ObligationStateSnapshot::Reserved)], // task 99 doesn't exist
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::OrphanObligation { .. }));
        crate::assert_with_log!(has_error, "has OrphanObligation error", true, has_error);
        crate::test_complete!("orphan_obligation_detected");
    }

    #[test]
    fn obligation_with_stale_holder_generation_is_orphaned() {
        init_test("obligation_with_stale_holder_generation_is_orphaned");
        let mut snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(5, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 5, ObligationStateSnapshot::Reserved)],
        );
        snapshot.snapshot.tasks[0].id = snap_id(5, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::OrphanObligation {
                    obligation_id: 0,
                    task_id: 5,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields OrphanObligation",
            true,
            has_error
        );
        crate::test_complete!("obligation_with_stale_holder_generation_is_orphaned");
    }

    #[test]
    fn orphan_obligation_region_detected() {
        init_test("orphan_obligation_region_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation_in_region(
                0,
                0,
                99,
                ObligationStateSnapshot::Reserved,
            )],
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::OrphanObligationRegion { .. }));
        crate::assert_with_log!(
            has_error,
            "has OrphanObligationRegion error",
            true,
            has_error
        );
        crate::test_complete!("orphan_obligation_region_detected");
    }

    #[test]
    fn obligation_with_stale_owning_region_generation_is_orphaned() {
        init_test("obligation_with_stale_owning_region_generation_is_orphaned");
        let mut snapshot = make_snapshot(
            vec![make_region(3, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 3, TaskStateSnapshot::Running)],
            vec![make_obligation_in_region(
                0,
                0,
                3,
                ObligationStateSnapshot::Reserved,
            )],
        );
        snapshot.snapshot.regions[0].id = snap_id(3, 1);
        snapshot.snapshot.tasks[0].region_id = snap_id(3, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::OrphanObligationRegion {
                    obligation_id: 0,
                    region_id: 3,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields OrphanObligationRegion",
            true,
            has_error
        );
        crate::test_complete!("obligation_with_stale_owning_region_generation_is_orphaned");
    }

    #[test]
    fn obligation_region_mismatch_detected() {
        init_test("obligation_region_mismatch_detected");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, None, RegionStateSnapshot::Open),
            ],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation_in_region(
                0,
                0,
                1,
                ObligationStateSnapshot::Reserved,
            )],
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::ObligationRegionMismatch { .. }));
        crate::assert_with_log!(
            has_error,
            "has ObligationRegionMismatch error",
            true,
            has_error
        );
        crate::test_complete!("obligation_region_mismatch_detected");
    }

    #[test]
    fn invalid_parent_detected() {
        init_test("invalid_parent_detected");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, Some(99), RegionStateSnapshot::Open), // parent 99 doesn't exist
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::InvalidParent { .. }));
        crate::assert_with_log!(has_error, "has InvalidParent error", true, has_error);
        crate::test_complete!("invalid_parent_detected");
    }

    #[test]
    fn parent_generation_mismatch_detected() {
        init_test("parent_generation_mismatch_detected");
        let mut snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, Some(0), RegionStateSnapshot::Open),
            ],
            Vec::new(),
            Vec::new(),
        );
        snapshot.snapshot.regions[0].id = snap_id(0, 1);

        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::InvalidParent {
                    region_id: 1,
                    parent_id: 0,
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "generation mismatch yields InvalidParent",
            true,
            has_error
        );
        crate::test_complete!("parent_generation_mismatch_detected");
    }

    #[test]
    fn closed_region_with_live_task_detected() {
        init_test("closed_region_with_live_task_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Closed)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)], // task still running in closed region
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::NonQuiescentClosure { .. }));
        crate::assert_with_log!(has_error, "has NonQuiescentClosure error", true, has_error);
        crate::test_complete!("closed_region_with_live_task_detected");
    }

    #[test]
    fn nested_regions_valid() {
        init_test("nested_regions_valid");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(1, Some(0), RegionStateSnapshot::Open),
                make_region(2, Some(1), RegionStateSnapshot::Open),
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.max_depth == 3,
            "max_depth",
            3,
            result.stats.max_depth
        );
        crate::test_complete!("nested_regions_valid");
    }

    #[test]
    fn terminal_task_stats_computed() {
        init_test("terminal_task_stats_computed");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![
                make_task(0, 0, TaskStateSnapshot::Running),
                make_task(
                    1,
                    0,
                    TaskStateSnapshot::Completed {
                        outcome: crate::runtime::state::OutcomeSnapshot::Ok,
                    },
                ),
            ],
            Vec::new(),
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.terminal_task_count == 1,
            "terminal_task_count",
            1,
            result.stats.terminal_task_count
        );
        crate::test_complete!("terminal_task_stats_computed");
    }

    #[test]
    fn content_hash_deterministic() {
        init_test("content_hash_deterministic");
        let snapshot1 = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        let snapshot2 = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );

        crate::assert_with_log!(
            snapshot1.content_hash == snapshot2.content_hash,
            "hashes equal",
            snapshot1.content_hash,
            snapshot2.content_hash
        );
        crate::test_complete!("content_hash_deterministic");
    }

    #[test]
    fn integrity_verification_works() {
        init_test("integrity_verification_works");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            Vec::new(),
            Vec::new(),
        );

        let valid = snapshot.verify_integrity();
        crate::assert_with_log!(valid, "integrity valid", true, valid);

        // Tamper with hash
        let mut tampered = snapshot;
        tampered.content_hash ^= 1;
        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "tampered invalid", true, invalid);

        crate::test_complete!("integrity_verification_works");
    }

    #[test]
    fn integrity_verification_detects_semantic_tampering() {
        init_test("integrity_verification_detects_semantic_tampering");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 0, ObligationStateSnapshot::Reserved)],
        );

        let mut tampered = snapshot;
        tampered.snapshot.tasks[0].state = TaskStateSnapshot::Completed {
            outcome: crate::runtime::state::OutcomeSnapshot::Ok,
        };

        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "semantic tamper invalid", true, invalid);

        crate::test_complete!("integrity_verification_detects_semantic_tampering");
    }

    #[test]
    fn integrity_verification_detects_schema_version_tampering() {
        init_test("integrity_verification_detects_schema_version_tampering");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );

        let mut tampered = snapshot;
        tampered.schema_version = tampered.schema_version.saturating_add(1);

        let invalid = !tampered.verify_integrity();
        crate::assert_with_log!(invalid, "schema version tamper invalid", true, invalid);

        crate::test_complete!("integrity_verification_detects_schema_version_tampering");
    }

    #[test]
    fn duplicate_region_id_detected() {
        init_test("duplicate_region_id_detected");
        let snapshot = make_snapshot(
            vec![
                make_region(0, None, RegionStateSnapshot::Open),
                make_region(0, None, RegionStateSnapshot::Open), // duplicate
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::DuplicateId { kind: "region", .. }));
        crate::assert_with_log!(has_error, "has DuplicateId error", true, has_error);
        crate::test_complete!("duplicate_region_id_detected");
    }

    #[test]
    fn duplicate_obligation_id_detected() {
        init_test("duplicate_obligation_id_detected");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![
                make_obligation(7, 0, ObligationStateSnapshot::Reserved),
                make_obligation(7, 0, ObligationStateSnapshot::Committed), // duplicate
            ],
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::DuplicateId {
                    kind: "obligation",
                    ..
                }
            )
        });
        crate::assert_with_log!(
            has_error,
            "has obligation DuplicateId error",
            true,
            has_error
        );
        crate::test_complete!("duplicate_obligation_id_detected");
    }

    #[test]
    fn cyclic_region_tree_detected_without_depth_hang() {
        init_test("cyclic_region_tree_detected_without_depth_hang");
        let snapshot = make_snapshot(
            vec![
                make_region(0, Some(1), RegionStateSnapshot::Open),
                make_region(1, Some(0), RegionStateSnapshot::Open),
            ],
            Vec::new(),
            Vec::new(),
        );
        let result = snapshot.validate();

        let not_valid = !result.is_valid;
        crate::assert_with_log!(not_valid, "not valid", true, not_valid);
        let has_cycle = result
            .errors
            .iter()
            .any(|e| matches!(e, RestoreError::CyclicRegionTree { .. }));
        crate::assert_with_log!(has_cycle, "has CyclicRegionTree error", true, has_cycle);
        crate::assert_with_log!(
            result.stats.max_depth == 2,
            "max_depth bounded with cycle",
            2,
            result.stats.max_depth
        );
        crate::test_complete!("cyclic_region_tree_detected_without_depth_hang");
    }

    #[test]
    fn resolved_obligation_stats_computed() {
        init_test("resolved_obligation_stats_computed");
        let snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![
                make_obligation(0, 0, ObligationStateSnapshot::Reserved),
                make_obligation(1, 0, ObligationStateSnapshot::Committed),
                make_obligation(2, 0, ObligationStateSnapshot::Aborted),
            ],
        );
        let result = snapshot.validate();

        crate::assert_with_log!(result.is_valid, "is_valid", true, result.is_valid);
        crate::assert_with_log!(
            result.stats.resolved_obligation_count == 2,
            "resolved_obligation_count",
            2,
            result.stats.resolved_obligation_count
        );
        crate::test_complete!("resolved_obligation_stats_computed");
    }

    #[test]
    fn task_timestamp_after_snapshot_detected() {
        init_test("task_timestamp_after_snapshot_detected");
        let mut snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            Vec::new(),
        );
        snapshot.snapshot.tasks[0].created_at = snapshot.snapshot.timestamp + 1;

        let result = snapshot.validate();
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::InvalidTimestamp {
                    entity, ..
                } if entity.contains("task 0 created_at")
            )
        });
        crate::assert_with_log!(
            has_error,
            "task invalid timestamp detected",
            true,
            has_error
        );
        crate::test_complete!("task_timestamp_after_snapshot_detected");
    }

    #[test]
    fn obligation_timestamp_after_snapshot_detected() {
        init_test("obligation_timestamp_after_snapshot_detected");
        let mut snapshot = make_snapshot(
            vec![make_region(0, None, RegionStateSnapshot::Open)],
            vec![make_task(0, 0, TaskStateSnapshot::Running)],
            vec![make_obligation(0, 0, ObligationStateSnapshot::Reserved)],
        );
        snapshot.snapshot.obligations[0].created_at = snapshot.snapshot.timestamp + 1;

        let result = snapshot.validate();
        let has_error = result.errors.iter().any(|e| {
            matches!(
                e,
                RestoreError::InvalidTimestamp {
                    entity, ..
                } if entity.contains("obligation 0 created_at")
            )
        });
        crate::assert_with_log!(
            has_error,
            "obligation invalid timestamp detected",
            true,
            has_error
        );
        crate::test_complete!("obligation_timestamp_after_snapshot_detected");
    }

    // ── derive-trait coverage (wave 73) ──────────────────────────────────

    #[test]
    fn restore_error_debug_clone_eq() {
        let e1 = RestoreError::OrphanTask {
            task_id: 5,
            region_id: 99,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
        let dbg = format!("{e1:?}");
        assert!(dbg.contains("OrphanTask"));

        let e3 = RestoreError::CyclicRegionTree {
            cycle: vec![1, 2, 3],
        };
        let e4 = e3.clone();
        assert_eq!(e3, e4);
        assert_ne!(e1, e3);
    }

    #[test]
    fn snapshot_stats_debug_clone_default() {
        let s = SnapshotStats::default();
        assert_eq!(s.region_count, 0);
        assert_eq!(s.task_count, 0);
        assert_eq!(s.obligation_count, 0);
        assert_eq!(s.max_depth, 0);
        assert_eq!(s.terminal_task_count, 0);
        assert_eq!(s.resolved_obligation_count, 0);
        assert_eq!(s.closed_region_count, 0);

        let s2 = s;
        let dbg = format!("{s2:?}");
        assert!(dbg.contains("SnapshotStats"));
    }

    #[test]
    fn validation_result_debug_clone() {
        let vr = ValidationResult {
            is_valid: true,
            errors: vec![],
            stats: SnapshotStats::default(),
        };
        let vr2 = vr;
        assert!(vr2.is_valid);
        assert!(vr2.errors.is_empty());
        let dbg = format!("{vr2:?}");
        assert!(dbg.contains("ValidationResult"));
    }
