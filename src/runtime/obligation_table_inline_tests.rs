    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::record::ObligationState;

    fn make_obligation(
        table: &mut ObligationTable,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
    ) -> ObligationId {
        table.create(ObligationCreateArgs {
            kind,
            holder,
            region,
            now: Time::ZERO,
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        })
    }

    fn test_task_id(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn test_task_id_with_generation(n: u32, generation: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, generation))
    }

    fn test_region_id(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    // br-asupersync-fu6cr0: resolved records were never
    // reclaimed, so every mpsc send, permit or lease grew the table forever.

    #[test]
    fn resolved_records_past_the_retention_are_reclaimed() {
        let mut table = ObligationTable::new();
        let region = test_region_id(1);
        let mut ids = Vec::new();
        for n in 0..RESOLVED_RETENTION + 100 {
            let holder = test_task_id((n % 7) as u32);
            let id = make_obligation(&mut table, ObligationKind::SendPermit, holder, region);
            if n % 2 == 0 {
                table.commit(id, Time::from_nanos(1)).unwrap();
            } else {
                table
                    .abort(id, Time::from_nanos(1), ObligationAbortReason::Cancel)
                    .unwrap();
            }
            ids.push(id);
        }
        assert_eq!(table.len(), RESOLVED_RETENTION);
        assert!(table.get(ids[0].arena_index()).is_none());
        assert!(table.get(ids[99].arena_index()).is_none());
        let newest = table.get(ids[ids.len() - 1].arena_index()).unwrap();
        assert_eq!(newest.state, ObligationState::Aborted);
        let indexed: usize = (0..7)
            .map(|n| table.ids_for_holder(test_task_id(n)).len())
            .sum();
        assert_eq!(
            indexed, RESOLVED_RETENTION,
            "the holder index forgets reclaimed ids"
        );
        let error = table.commit(ids[0], Time::from_nanos(2)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ObligationAlreadyResolved);
    }

    #[test]
    fn holder_buckets_stay_bounded_across_task_slot_reuse() {
        let mut table = ObligationTable::new();
        let region = test_region_id(1);
        for generation in 0..(RESOLVED_RETENTION + 100) as u32 {
            let holder = test_task_id_with_generation(0, generation);
            let id = make_obligation(&mut table, ObligationKind::Ack, holder, region);
            table.commit(id, Time::from_nanos(1)).unwrap();
        }
        assert_eq!(table.by_holder[0].len(), RESOLVED_RETENTION);
    }

    #[test]
    fn leaked_and_pending_records_are_never_reclaimed() {
        let mut table = ObligationTable::new();
        let region = test_region_id(1);
        let pending = make_obligation(&mut table, ObligationKind::Lease, test_task_id(1), region);
        let leaked = make_obligation(&mut table, ObligationKind::IoOp, test_task_id(2), region);
        table.mark_leaked(leaked, Time::from_nanos(1)).unwrap();
        for _ in 0..RESOLVED_RETENTION + 10 {
            let id = make_obligation(
                &mut table,
                ObligationKind::SendPermit,
                test_task_id(3),
                region,
            );
            table.commit(id, Time::from_nanos(1)).unwrap();
        }
        assert!(table.get(pending.arena_index()).unwrap().is_pending());
        assert_eq!(table.pending_count(), 1);
        assert_eq!(
            table.get(leaked.arena_index()).unwrap().state,
            ObligationState::Leaked
        );
    }

    #[test]
    fn the_finalized_region_fence_is_bounded_and_keeps_recent_regions() {
        let mut table = ObligationTable::new();
        let total = (FINALIZED_FENCE_RETENTION + 10) as u32;
        let recent = test_region_id(total - 1);
        let pending = make_obligation(&mut table, ObligationKind::Ack, test_task_id(1), recent);
        for n in 0..total {
            table.mark_region_finalized(test_region_id(n));
        }
        assert_eq!(table.finalized_regions.len(), FINALIZED_FENCE_RETENTION);
        assert!(!table.is_region_finalized(test_region_id(0)));
        assert!(table.is_region_finalized(recent));
        let error = table.commit(pending, Time::from_nanos(1)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RegionFinalized);
    }

    #[test]
    fn create_and_query_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        assert_eq!(table.len(), 1);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.kind, ObligationKind::SendPermit);
        assert_eq!(record.holder, task);
        assert_eq!(record.region, region);
        assert!(record.is_pending());
    }

    #[test]
    fn commit_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::Ack, task, region);
        let info = table.commit(id, Time::from_nanos(1000)).unwrap();

        assert_eq!(info.id, id);
        assert_eq!(info.holder, task);
        assert_eq!(info.region, region);
        assert_eq!(info.kind, ObligationKind::Ack);
        assert_eq!(info.duration, 1000);

        let record = table.get(id.arena_index()).unwrap();
        assert!(!record.is_pending());
        assert_eq!(record.state, ObligationState::Committed);
    }

    #[test]
    fn abort_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(2);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::Lease, task, region);
        let info = table
            .abort(id, Time::from_nanos(500), ObligationAbortReason::Cancel)
            .unwrap();

        assert_eq!(info.id, id);
        assert_eq!(info.reason, ObligationAbortReason::Cancel);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.state, ObligationState::Aborted);
    }

    #[test]
    fn mark_leaked_obligation() {
        let mut table = ObligationTable::new();
        let task = test_task_id(3);
        let region = test_region_id(1);

        let id = make_obligation(&mut table, ObligationKind::IoOp, task, region);
        let info = table.mark_leaked(id, Time::from_nanos(2000)).unwrap();

        assert_eq!(info.id, id);
        assert_eq!(info.kind, ObligationKind::IoOp);

        let record = table.get(id.arena_index()).unwrap();
        assert_eq!(record.state, ObligationState::Leaked);
    }

    #[test]
    fn double_commit_fails() {
        let mut table = ObligationTable::new();
        let id = make_obligation(
            &mut table,
            ObligationKind::SendPermit,
            test_task_id(1),
            test_region_id(1),
        );

        assert!(table.commit(id, Time::from_nanos(100)).is_ok());
        assert!(table.commit(id, Time::from_nanos(200)).is_err());
    }

    #[test]
    fn nonexistent_obligation_fails() {
        let mut table = ObligationTable::new();
        let unknown_obligation = ObligationId::from_arena(ArenaIndex::new(99, 0));

        assert!(
            table
                .commit(unknown_obligation, Time::from_nanos(100))
                .is_err()
        );
        assert!(
            table
                .abort(
                    unknown_obligation,
                    Time::from_nanos(100),
                    ObligationAbortReason::Cancel
                )
                .is_err()
        );
        assert!(
            table
                .mark_leaked(unknown_obligation, Time::from_nanos(100))
                .is_err()
        );
    }

    #[test]
    fn query_by_task_and_region() {
        let mut table = ObligationTable::new();
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let region1 = test_region_id(1);
        let region2 = test_region_id(2);

        make_obligation(&mut table, ObligationKind::SendPermit, task1, region1);
        make_obligation(&mut table, ObligationKind::Ack, task1, region2);
        make_obligation(&mut table, ObligationKind::Lease, task2, region1);

        assert_eq!(table.for_task(task1).count(), 2);
        assert_eq!(table.for_task(task2).count(), 1);
        assert_eq!(table.for_region(region1).count(), 2);
        assert_eq!(table.for_region(region2).count(), 1);
    }

    #[test]
    fn audit_counts_and_state_queries_are_deterministic() {
        let mut table = ObligationTable::new();
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let region1 = test_region_id(1);
        let region2 = test_region_id(2);

        let pending = make_obligation(&mut table, ObligationKind::SendPermit, task1, region1);
        let committed = make_obligation(&mut table, ObligationKind::Ack, task1, region1);
        let aborted = make_obligation(&mut table, ObligationKind::Lease, task2, region2);
        let leaked = make_obligation(&mut table, ObligationKind::IoOp, task1, region1);

        table.commit(committed, Time::from_nanos(50)).unwrap();
        table
            .abort(aborted, Time::from_nanos(60), ObligationAbortReason::Cancel)
            .unwrap();
        table.mark_leaked(leaked, Time::from_nanos(70)).unwrap();

        let region_counts = table.counts_for_region(region1);
        assert_eq!(region_counts.pending, 1);
        assert_eq!(region_counts.committed, 1);
        assert_eq!(region_counts.leaked, 1);
        assert_eq!(
            table
                .counts_for_region_and_kind(region1, ObligationKind::SendPermit)
                .pending,
            1
        );
        assert_eq!(table.counts_for_task(task1).total(), 3);
        assert_eq!(table.counts_for_kind(ObligationKind::Lease).aborted, 1);
        assert_eq!(
            table.obligation_state(aborted),
            Some(ObligationState::Aborted)
        );

        let audit = table.audit_region(region1, Time::from_nanos(100));
        let audit_ids: Vec<_> = audit.iter().map(|record| record.id).collect();
        assert_eq!(audit_ids, vec![pending, committed, leaked]);
        assert_eq!(audit[0].age_ns, 100);
        assert_eq!(audit[1].resolved_at, Some(Time::from_nanos(50)));
        assert_eq!(audit[2].state, ObligationState::Leaked);
    }

    #[test]
    fn pending_count_decreases_on_resolve() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(1);

        let id1 = make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        let id2 = make_obligation(&mut table, ObligationKind::Ack, task, region);
        let _id3 = make_obligation(&mut table, ObligationKind::Lease, task, region);

        assert_eq!(table.pending_count(), 3);

        table.commit(id1, Time::from_nanos(100)).unwrap();
        assert_eq!(table.pending_count(), 2);

        table
            .abort(id2, Time::from_nanos(200), ObligationAbortReason::Cancel)
            .unwrap();
        assert_eq!(table.pending_count(), 1);
    }

    #[test]
    fn pending_obligation_ids_for_task() {
        let mut table = ObligationTable::new();
        let task1 = test_task_id(1);
        let task2 = test_task_id(2);
        let region = test_region_id(1);

        let id1 = make_obligation(&mut table, ObligationKind::SendPermit, task1, region);
        let _id2 = make_obligation(&mut table, ObligationKind::Ack, task2, region);
        let id3 = make_obligation(&mut table, ObligationKind::Lease, task1, region);

        table.commit(id1, Time::from_nanos(100)).unwrap();

        let pending = table.pending_obligation_ids_for_task(task1);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], id3);
    }

    #[test]
    fn holder_index_preserves_same_slot_task_generations() {
        let mut table = ObligationTable::new();
        let older = test_task_id_with_generation(9, 0);
        let newer = test_task_id_with_generation(9, 1);
        let region = test_region_id(1);

        let older_id = make_obligation(&mut table, ObligationKind::SendPermit, older, region);
        let newer_id = make_obligation(&mut table, ObligationKind::Ack, newer, region);

        assert_eq!(table.ids_for_holder(older), &[older_id]);
        assert_eq!(table.ids_for_holder(newer), &[newer_id]);
        assert_eq!(
            table.sorted_pending_ids_for_holder(older).as_slice(),
            &[older_id]
        );
        assert_eq!(table.pending_obligation_ids_for_task(newer), vec![newer_id]);
    }

    #[test]
    fn pending_obligation_ids_for_task_is_sorted_after_slot_reuse() {
        let mut table = ObligationTable::new();
        let task = test_task_id(7);
        let region = test_region_id(1);

        let id0 = make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        let id1 = make_obligation(&mut table, ObligationKind::Ack, task, region);
        let id2 = make_obligation(&mut table, ObligationKind::Lease, task, region);

        // Reuse a hole at id1's arena slot so insertion order diverges from ID order.
        let _removed = table.remove(id1.arena_index()).expect("obligation exists");
        let id1_reused = make_obligation(&mut table, ObligationKind::IoOp, task, region);

        let pending = table.pending_obligation_ids_for_task(task);
        assert_eq!(pending.len(), 3);

        let mut expected = vec![id0, id2, id1_reused];
        expected.sort_unstable();
        assert_eq!(pending, expected, "pending IDs should be canonicalized");
    }

    #[test]
    fn holder_index_100_obligations_10_tasks() {
        let mut table = ObligationTable::new();
        let region = test_region_id(1);
        let kinds = [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
        ];

        // Create 100 obligations across 10 tasks (10 per task)
        for task_n in 0..10 {
            let task = test_task_id(task_n);
            for i in 0..10 {
                let kind = kinds[(task_n as usize * 10 + i) % kinds.len()];
                let id = make_obligation(&mut table, kind, task, region);
                let _ = id;
            }
        }
        assert_eq!(table.len(), 100);

        // Verify index returns correct counts
        for task_n in 0..10 {
            let task = test_task_id(task_n);
            assert_eq!(table.ids_for_holder(task).len(), 10);
            assert_eq!(table.sorted_pending_ids_for_holder(task).len(), 10);
        }

        // Commit half the obligations for task 0
        let task0 = test_task_id(0);
        let task0_ids: Vec<_> = table.ids_for_holder(task0).to_vec();
        for id in &task0_ids[..5] {
            table.commit(*id, Time::from_nanos(100)).unwrap();
        }
        // Index still has all 10, but pending only 5
        assert_eq!(table.ids_for_holder(task0).len(), 10);
        assert_eq!(table.sorted_pending_ids_for_holder(task0).len(), 5);

        // Abort remaining for task 0
        for id in &task0_ids[5..] {
            table
                .abort(*id, Time::from_nanos(200), ObligationAbortReason::Cancel)
                .unwrap();
        }
        assert_eq!(table.sorted_pending_ids_for_holder(task0).len(), 0);

        // Other tasks unaffected
        for task_n in 1..10 {
            let task = test_task_id(task_n);
            assert_eq!(table.sorted_pending_ids_for_holder(task).len(), 10);
        }

        // Remove one obligation via arena remove
        let task5 = test_task_id(5);
        let task5_first_id = table.ids_for_holder(task5)[0];
        table.remove(task5_first_id.arena_index());
        assert_eq!(table.ids_for_holder(task5).len(), 9);

        // sorted_pending_ids_for_holder is sorted by ObligationId
        let task3 = test_task_id(3);
        let sorted = table.sorted_pending_ids_for_holder(task3);
        for window in sorted.windows(2) {
            assert!(window[0] < window[1], "should be sorted");
        }
    }

    #[test]
    fn insert_normalizes_record_id_to_assigned_slot() {
        let mut table = ObligationTable::new();
        let task = test_task_id(11);
        let region = test_region_id(4);
        let stale_id = ObligationId::from_arena(ArenaIndex::new(99, 0));

        let idx = table.insert(ObligationRecord::new(
            stale_id,
            ObligationKind::SendPermit,
            task,
            region,
            Time::ZERO,
        ));
        let canonical = ObligationId::from_arena(idx);
        let record = table.get(idx).expect("obligation exists");

        assert_eq!(record.id, canonical);
        assert_ne!(record.id, stale_id);
        assert_eq!(table.ids_for_holder(task), &[canonical]);
    }

    #[test]
    fn insert_with_normalizes_record_id_to_assigned_slot() {
        let mut table = ObligationTable::new();
        let task = test_task_id(12);
        let region = test_region_id(5);
        let stale_id = ObligationId::from_arena(ArenaIndex::new(77, 1));

        let idx = table.insert_with(|_| {
            ObligationRecord::new(stale_id, ObligationKind::Ack, task, region, Time::ZERO)
        });
        let canonical = ObligationId::from_arena(idx);
        let record = table.get(idx).expect("obligation exists");

        assert_eq!(record.id, canonical);
        assert_ne!(record.id, stale_id);
        assert_eq!(table.pending_obligation_ids_for_task(task), vec![canonical]);
    }

    #[test]
    fn metamorphic_resolution_reordering_preserves_table_invariants() {
        #[derive(Clone, Copy)]
        enum Resolution {
            Commit(ObligationId, Time),
            Abort(ObligationId, Time, ObligationAbortReason),
            Leak(ObligationId, Time),
        }

        fn apply_resolutions(table: &mut ObligationTable, resolutions: &[Resolution]) {
            for resolution in resolutions {
                match *resolution {
                    Resolution::Commit(id, now) => {
                        table.commit(id, now).expect("commit should succeed");
                    }
                    Resolution::Abort(id, now, reason) => {
                        table.abort(id, now, reason).expect("abort should succeed");
                    }
                    Resolution::Leak(id, now) => {
                        table.mark_leaked(id, now).expect("leak should succeed");
                    }
                }
            }
        }

        fn build_table() -> (
            ObligationTable,
            [ObligationId; 5],
            TaskId,
            TaskId,
            RegionId,
            RegionId,
        ) {
            let mut table = ObligationTable::new();
            let task_a = test_task_id(21);
            let task_b = test_task_id(22);
            let region_x = test_region_id(7);
            let region_y = test_region_id(8);

            let ids = [
                make_obligation(&mut table, ObligationKind::SendPermit, task_a, region_x),
                make_obligation(&mut table, ObligationKind::Ack, task_a, region_y),
                make_obligation(&mut table, ObligationKind::Lease, task_b, region_x),
                make_obligation(&mut table, ObligationKind::IoOp, task_b, region_y),
                make_obligation(&mut table, ObligationKind::SendPermit, task_b, region_y),
            ];

            (table, ids, task_a, task_b, region_x, region_y)
        }

        let (mut baseline, ids, task_a, task_b, region_x, region_y) = build_table();
        let resolutions = [
            Resolution::Commit(ids[0], Time::from_nanos(100)),
            Resolution::Abort(ids[2], Time::from_nanos(200), ObligationAbortReason::Cancel),
            Resolution::Leak(ids[4], Time::from_nanos(300)),
        ];
        apply_resolutions(&mut baseline, &resolutions);

        let (mut reordered, reordered_ids, _, _, _, _) = build_table();
        let reversed = [
            Resolution::Leak(reordered_ids[4], Time::from_nanos(300)),
            Resolution::Abort(
                reordered_ids[2],
                Time::from_nanos(200),
                ObligationAbortReason::Cancel,
            ),
            Resolution::Commit(reordered_ids[0], Time::from_nanos(100)),
        ];
        apply_resolutions(&mut reordered, &reversed);

        assert_eq!(baseline.pending_count(), reordered.pending_count());
        assert_eq!(
            baseline.pending_obligation_ids_for_task(task_a),
            reordered.pending_obligation_ids_for_task(task_a)
        );
        assert_eq!(
            baseline.pending_obligation_ids_for_task(task_b),
            reordered.pending_obligation_ids_for_task(task_b)
        );
        assert_eq!(
            baseline.pending_obligation_ids_for_region(region_x),
            reordered.pending_obligation_ids_for_region(region_x)
        );
        assert_eq!(
            baseline.pending_obligation_ids_for_region(region_y),
            reordered.pending_obligation_ids_for_region(region_y)
        );
        assert_eq!(
            baseline.ids_for_holder(task_a),
            reordered.ids_for_holder(task_a)
        );
        assert_eq!(
            baseline.ids_for_holder(task_b),
            reordered.ids_for_holder(task_b)
        );

        for id in ids {
            let baseline_record = baseline.get(id.arena_index()).expect("record exists");
            let reordered_record = reordered.get(id.arena_index()).expect("record exists");
            assert_eq!(baseline_record.state, reordered_record.state);
            assert_eq!(baseline_record.holder, reordered_record.holder);
            assert_eq!(baseline_record.region, reordered_record.region);
            assert_eq!(baseline_record.kind, reordered_record.kind);
        }
    }

    // Pure data-type tests (wave 34 – CyanBarn)

    #[test]
    fn obligation_commit_info_debug_clone() {
        let info = ObligationCommitInfo {
            id: ObligationId::from_arena(ArenaIndex::new(0, 0)),
            holder: test_task_id(1),
            region: test_region_id(1),
            kind: ObligationKind::SendPermit,
            duration: 42,
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObligationCommitInfo"));
        let cloned = info;
        assert_eq!(cloned.duration, 42);
        assert_eq!(cloned.kind, ObligationKind::SendPermit);
    }

    #[test]
    fn obligation_abort_info_debug_clone() {
        let info = ObligationAbortInfo {
            id: ObligationId::from_arena(ArenaIndex::new(0, 0)),
            holder: test_task_id(2),
            region: test_region_id(1),
            kind: ObligationKind::Ack,
            duration: 500,
            reason: ObligationAbortReason::Cancel,
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObligationAbortInfo"));
        let cloned = info;
        assert_eq!(cloned.duration, 500);
        assert_eq!(cloned.reason, ObligationAbortReason::Cancel);
    }

    #[test]
    fn obligation_leak_info_debug_clone() {
        let info = ObligationLeakInfo {
            id: ObligationId::from_arena(ArenaIndex::new(0, 0)),
            holder: test_task_id(3),
            region: test_region_id(1),
            kind: ObligationKind::IoOp,
            duration: 2000,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
            description: Some("test leak".into()),
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ObligationLeakInfo"));
        let cloned = info;
        assert_eq!(cloned.duration, 2000);
        assert_eq!(cloned.description.as_deref(), Some("test leak"));
    }

    #[test]
    fn obligation_create_args_debug_clone() {
        let args = ObligationCreateArgs {
            kind: ObligationKind::Lease,
            holder: test_task_id(5),
            region: test_region_id(2),
            now: Time::ZERO,
            description: Some("test create".into()),
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("ObligationCreateArgs"));
        let cloned = args;
        assert_eq!(cloned.kind, ObligationKind::Lease);
        assert_eq!(cloned.description.as_deref(), Some("test create"));
    }

    #[test]
    fn obligation_table_debug() {
        let table = ObligationTable::new();
        let dbg = format!("{table:?}");
        assert!(dbg.contains("ObligationTable"));
    }

    #[test]
    fn obligation_table_default() {
        let table = ObligationTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn obligation_table_new_empty() {
        let table = ObligationTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.pending_count(), 0);
    }

    /// Regression for br-asupersync-xxcss5: per-kind pending counters and the
    /// running reserved_at sum stay consistent with the arena across
    /// create/commit/abort/leak/remove, so the Lyapunov governor can read
    /// them directly instead of scanning obligations on every snapshot.
    #[test]
    fn incremental_counters_track_all_mutations() {
        let mut table = ObligationTable::new();
        let task_a = test_task_id(10);
        let task_b = test_task_id(11);
        let region = test_region_id(3);

        let send = table.create(ObligationCreateArgs {
            kind: ObligationKind::SendPermit,
            holder: task_a,
            region,
            now: Time::from_nanos(100),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
        let ack = table.create(ObligationCreateArgs {
            kind: ObligationKind::Ack,
            holder: task_a,
            region,
            now: Time::from_nanos(150),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
        let lease = table.create(ObligationCreateArgs {
            kind: ObligationKind::Lease,
            holder: task_b,
            region,
            now: Time::from_nanos(200),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });
        let sem = table.create(ObligationCreateArgs {
            kind: ObligationKind::SemaphorePermit,
            holder: task_b,
            region,
            now: Time::from_nanos(250),
            description: None,
            acquired_at: SourceLocation::unknown(),
            acquire_backtrace: None,
        });

        assert_eq!(table.pending_count(), 4);
        assert_eq!(table.pending_count_for_kind(ObligationKind::SendPermit), 1);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Ack), 1);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Lease), 1);
        assert_eq!(
            table.pending_count_for_kind(ObligationKind::SemaphorePermit),
            1
        );
        assert_eq!(table.pending_count_for_kind(ObligationKind::IoOp), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 100 + 150 + 200 + 250);

        // Commit → pending count & kind bucket decrement, and reserved_at sum
        // loses exactly the committed obligation's nanos.
        table.commit(send, Time::from_nanos(300)).unwrap();
        assert_eq!(table.pending_count(), 3);
        assert_eq!(table.pending_count_for_kind(ObligationKind::SendPermit), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 150 + 200 + 250);

        // Abort decrements the Ack bucket.
        table
            .abort(ack, Time::from_nanos(400), ObligationAbortReason::Cancel)
            .unwrap();
        assert_eq!(table.pending_count(), 2);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Ack), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 200 + 250);

        // Mark-leaked decrements the Lease bucket.
        table.mark_leaked(lease, Time::from_nanos(500)).unwrap();
        assert_eq!(table.pending_count(), 1);
        assert_eq!(table.pending_count_for_kind(ObligationKind::Lease), 0);
        assert_eq!(table.pending_reserved_at_sum_ns(), 250);

        // Removing a still-pending obligation must also decrement.
        let removed = table.remove(sem.arena_index()).unwrap();
        assert_eq!(removed.kind, ObligationKind::SemaphorePermit);
        assert_eq!(table.pending_count(), 0);
        assert_eq!(
            table.pending_count_for_kind(ObligationKind::SemaphorePermit),
            0
        );
        assert_eq!(table.pending_reserved_at_sum_ns(), 0);

        // Per-kind counters must bottom out at zero on normal lifecycle paths.
        for kind in [
            ObligationKind::SendPermit,
            ObligationKind::Ack,
            ObligationKind::Lease,
            ObligationKind::IoOp,
            ObligationKind::SemaphorePermit,
        ] {
            assert_eq!(table.pending_count_for_kind(kind), 0);
        }
    }

    #[test]
    #[should_panic(expected = "pending counter underflow")]
    fn pending_counter_underflow_is_not_silent() {
        let mut table = ObligationTable::new();
        table.note_pending_removed(ObligationKind::Ack, Time::ZERO);
    }

    #[test]
    #[should_panic(expected = "per-kind pending counter underflow")]
    fn pending_counter_per_kind_underflow_is_not_silent() {
        let mut table = ObligationTable::new();
        table.cached_pending = 1;
        table.pending_by_kind[kind_index(ObligationKind::Lease)] = 1;

        table.note_pending_removed(ObligationKind::Ack, Time::ZERO);
    }

    #[test]
    #[should_panic(expected = "pending reserved-at sum underflow")]
    fn pending_reserved_at_sum_underflow_is_not_silent() {
        let mut table = ObligationTable::new();
        table.cached_pending = 1;
        table.pending_by_kind[kind_index(ObligationKind::Ack)] = 1;

        table.note_pending_removed(ObligationKind::Ack, Time::from_nanos(1));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "pending counter drift")]
    fn pending_counter_scan_catches_cached_count_drift_in_debug() {
        let mut table = ObligationTable::new();
        let task = test_task_id(12);
        let region = test_region_id(4);

        make_obligation(&mut table, ObligationKind::SendPermit, task, region);
        table.cached_pending = 0;

        table.debug_assert_pending_counters_match();
    }

    #[test]
    fn region_finalization_fence_prevents_commit_after_finalization() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(42);

        // Create an obligation
        let obligation_id = make_obligation(&mut table, ObligationKind::SendPermit, task, region);

        // Should be able to commit before finalization
        assert!(!table.is_region_finalized(region));

        // Finalize the region
        table.mark_region_finalized(region);
        assert!(table.is_region_finalized(region));

        // Attempt to commit after finalization should fail
        let result = table.commit(obligation_id, Time::from_nanos(100));
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.kind(), ErrorKind::RegionFinalized);
            assert!(
                error
                    .message()
                    .unwrap()
                    .contains("cannot commit obligation: region has been finalized")
            );
        }

        // Obligation should still be pending since commit failed
        let record = table.get(obligation_id.arena_index()).unwrap();
        assert!(record.is_pending());
    }

    #[test]
    fn region_finalization_fence_prevents_abort_after_finalization() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let region = test_region_id(42);

        // Create an obligation
        let obligation_id = make_obligation(&mut table, ObligationKind::Ack, task, region);

        // Finalize the region
        table.mark_region_finalized(region);

        // Attempt to abort after finalization should fail
        let result = table.abort(
            obligation_id,
            Time::from_nanos(100),
            ObligationAbortReason::Cancel,
        );
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.kind(), ErrorKind::RegionFinalized);
            assert!(
                error
                    .message()
                    .unwrap()
                    .contains("cannot abort obligation: region has been finalized")
            );
        }

        // Obligation should still be pending since abort failed
        let record = table.get(obligation_id.arena_index()).unwrap();
        assert!(record.is_pending());
    }

    #[test]
    fn region_finalization_fence_allows_operations_on_non_finalized_regions() {
        let mut table = ObligationTable::new();
        let task = test_task_id(1);
        let finalized_region = test_region_id(42);
        let active_region = test_region_id(99);

        // Create obligations in both regions
        let finalized_obligation = make_obligation(
            &mut table,
            ObligationKind::SendPermit,
            task,
            finalized_region,
        );
        let active_obligation =
            make_obligation(&mut table, ObligationKind::Ack, task, active_region);

        // Finalize only one region
        table.mark_region_finalized(finalized_region);

        // Operations on finalized region should fail
        assert!(
            table
                .commit(finalized_obligation, Time::from_nanos(100))
                .is_err()
        );

        // Operations on non-finalized region should succeed
        assert!(
            table
                .commit(active_obligation, Time::from_nanos(100))
                .is_ok()
        );
    }

    #[test]
    fn region_finalization_is_idempotent() {
        let mut table = ObligationTable::new();
        let region = test_region_id(42);

        // Mark region finalized multiple times
        table.mark_region_finalized(region);
        assert!(table.is_region_finalized(region));

        table.mark_region_finalized(region);
        assert!(table.is_region_finalized(region));

        table.mark_region_finalized(region);
        assert!(table.is_region_finalized(region));
    }
