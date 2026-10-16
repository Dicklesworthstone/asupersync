    use super::*;

    fn symbol(object: u64, sbn: u8, esi: u32, kind: SymbolKind) -> Symbol {
        Symbol::new(
            SymbolId::new_for_test(object, sbn, esi),
            vec![esi as u8],
            kind,
        )
    }

    #[test]
    fn multiple_donors_feed_one_unified_symbol_set() {
        let mut set = BondedReceiverSymbolSet::new();

        for esi in [0, 2, 4] {
            assert!(matches!(
                set.record_symbol(0, &symbol(7, 0, esi, SymbolKind::Source)),
                BondedSymbolDisposition::Accepted(_)
            ));
        }
        for esi in [1, 3, 5] {
            assert!(matches!(
                set.record_symbol(1, &symbol(7, 0, esi, SymbolKind::Repair)),
                BondedSymbolDisposition::Accepted(_)
            ));
        }

        assert_eq!(set.len(), 6);
        assert!(set.contains(BondedSymbolKey::new(ObjectId::new_for_test(7), 0, 5)));

        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.donor_count, 2);
        assert_eq!(aggregate.symbols_received, 6);
        assert_eq!(aggregate.symbols_accepted, 6);
        assert_eq!(aggregate.duplicate_symbols, 0);
        assert_eq!(aggregate.source_symbols_accepted, 3);
        assert_eq!(aggregate.repair_symbols_accepted, 3);

        let donor0 = set.donor_stats(0).expect("donor 0 stats");
        let donor1 = set.donor_stats(1).expect("donor 1 stats");
        assert_eq!(donor0.symbols_accepted, 3);
        assert_eq!(donor1.symbols_accepted, 3);
    }

    #[test]
    fn auth_rejection_counter_is_saturating_and_separate_from_authenticated_ingress() {
        let mut set = BondedReceiverSymbolSet::new();

        assert_eq!(set.auth_rejected_symbols(7), 0);
        assert_eq!(set.record_auth_rejection(7), 1);
        assert_eq!(set.record_auth_rejection(7), 2);
        assert_eq!(set.auth_rejected_symbols(7), 2);
        assert!(set.is_empty());
        assert_eq!(set.aggregate_stats(), BondedReceiverIngressStats::default());
        assert_eq!(set.donor_stats(7), None);
        assert!(set.donor_targets().is_empty());

        set.auth_rejections_by_donor.insert(7, u64::MAX - 1);
        assert_eq!(set.record_auth_rejection(7), u64::MAX);
        assert_eq!(set.record_auth_rejection(7), u64::MAX);
        assert_eq!(set.auth_rejected_symbols(7), u64::MAX);
        assert_eq!(set.aggregate_stats(), BondedReceiverIngressStats::default());
        assert!(set.donor_targets().is_empty());
    }

    #[test]
    fn cross_donor_duplicate_esi_is_dropped_before_decode() {
        let mut set = BondedReceiverSymbolSet::new();
        let first = symbol(9, 2, 42, SymbolKind::Repair);
        let duplicate = symbol(9, 2, 42, SymbolKind::Repair);

        assert_eq!(
            set.record_symbol(0, &first),
            BondedSymbolDisposition::Accepted(BondedSymbolKey::from_symbol_id(first.id()))
        );
        assert_eq!(
            set.record_symbol(1, &duplicate),
            BondedSymbolDisposition::Duplicate(BondedSymbolKey::from_symbol_id(duplicate.id()))
        );

        assert_eq!(set.len(), 1);
        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.donor_count, 2);
        assert_eq!(aggregate.symbols_received, 2);
        assert_eq!(aggregate.symbols_accepted, 1);
        assert_eq!(aggregate.duplicate_symbols, 1);
        assert_eq!(aggregate.duplicate_rate_ppm(), 500_000);

        assert_eq!(
            set.donor_stats(1).expect("donor 1 stats").duplicate_symbols,
            1
        );
    }

    #[test]
    fn duplicate_symbols_do_not_inflate_accepted_kind_counters() {
        let mut set = BondedReceiverSymbolSet::new();
        let source = symbol(11, 0, 3, SymbolKind::Source);
        let repair = symbol(11, 0, 9, SymbolKind::Repair);

        assert!(matches!(
            set.record_symbol(0, &source),
            BondedSymbolDisposition::Accepted(_)
        ));
        assert!(matches!(
            set.record_symbol(0, &repair),
            BondedSymbolDisposition::Accepted(_)
        ));
        assert!(matches!(
            set.record_symbol(1, &source),
            BondedSymbolDisposition::Duplicate(_)
        ));
        assert!(matches!(
            set.record_symbol(1, &repair),
            BondedSymbolDisposition::Duplicate(_)
        ));

        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.symbols_received, 4);
        assert_eq!(aggregate.symbols_accepted, 2);
        assert_eq!(aggregate.duplicate_symbols, 2);
        assert_eq!(aggregate.source_symbols_accepted, 1);
        assert_eq!(aggregate.repair_symbols_accepted, 1);
        assert_eq!(aggregate.duplicate_rate_ppm(), 500_000);

        let donor1 = set.donor_stats(1).expect("donor 1 stats");
        assert_eq!(donor1.symbols_received, 2);
        assert_eq!(donor1.symbols_accepted, 0);
        assert_eq!(donor1.duplicate_symbols, 2);
        assert_eq!(donor1.source_symbols_accepted, 0);
        assert_eq!(donor1.repair_symbols_accepted, 0);
    }

    #[test]
    fn retention_policy_rejects_novel_symbols_after_block_cap_without_growing_set() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(12);
        let retention = BondedReceiverRetentionPolicy::bounded(2, 16);

        assert!(matches!(
            set.record_key_with_retention(
                0,
                BondedSymbolKey::new(object_id, 0, 0),
                SymbolKind::Source,
                retention,
            ),
            BondedSymbolDisposition::Accepted(_)
        ));
        assert!(matches!(
            set.record_key_with_retention(
                1,
                BondedSymbolKey::new(object_id, 0, 2),
                SymbolKind::Repair,
                retention,
            ),
            BondedSymbolDisposition::Accepted(_)
        ));

        assert_eq!(
            set.record_key_with_retention(
                2,
                BondedSymbolKey::new(object_id, 0, 3),
                SymbolKind::Repair,
                retention,
            ),
            BondedSymbolDisposition::RejectedByRetention {
                key: BondedSymbolKey::new(object_id, 0, 3),
                reason: BondedReceiverRetentionRejectReason::BlockSymbolCap,
            }
        );
        assert_eq!(
            set.record_key_with_retention(
                3,
                BondedSymbolKey::new(object_id, 0, 2),
                SymbolKind::Repair,
                retention,
            ),
            BondedSymbolDisposition::Duplicate(BondedSymbolKey::new(object_id, 0, 2))
        );

        assert_eq!(set.len(), 2);
        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.symbols_received, 4);
        assert_eq!(aggregate.symbols_accepted, 2);
        assert_eq!(aggregate.duplicate_symbols, 1);
        assert_eq!(aggregate.symbols_rejected_by_retention, 1);
        assert_eq!(
            set.donor_stats(2)
                .expect("donor 2 stats")
                .symbols_rejected_by_retention,
            1
        );
    }

    /// The per-block retention count is a lookup kept in step with `seen`; it
    /// must agree with a scan of the retained keys after any interleaving of
    /// accepts, duplicates and retention rejects across blocks and objects.
    #[test]
    fn block_symbol_count_matches_a_scan_of_retained_keys() {
        let mut set = BondedReceiverSymbolSet::new();
        let retention = BondedReceiverRetentionPolicy::bounded(3, 7);
        let objects = [ObjectId::new_for_test(1), ObjectId::new_for_test(2)];
        let mut donor = 0;
        for round in 0..3u32 {
            for (object_index, object_id) in objects.iter().enumerate() {
                let object_offset = u32::try_from(object_index).expect("two objects");
                for sbn in 0..3u8 {
                    for esi in 0..4u32 {
                        let kind = if esi % 2 == 0 {
                            SymbolKind::Source
                        } else {
                            SymbolKind::Repair
                        };
                        // Keys repeat across rounds for the first object, so
                        // duplicates interleave with novel and rejected ones.
                        let key =
                            BondedSymbolKey::new(*object_id, sbn, esi + round * object_offset);
                        let _ = set.record_key_with_retention(donor % 4, key, kind, retention);
                        donor += 1;
                    }
                }
            }
        }

        for object_id in objects {
            for sbn in 0..4u8 {
                let scanned = set
                    .seen
                    .iter()
                    .filter(|key| key.object_id == object_id && key.sbn == sbn)
                    .count();
                assert_eq!(
                    usize::try_from(set.block_symbol_count(object_id, sbn)).expect("count fits"),
                    scanned,
                    "object {object_id:?} sbn {sbn}"
                );
                assert!(scanned <= 3, "block cap holds for {object_id:?} sbn {sbn}");
            }
        }
        assert!(set.len() <= 7, "transfer cap holds");
        assert_eq!(set.len(), set.seen.len());
    }

    #[test]
    fn retention_policy_rejects_novel_symbols_after_transfer_cap() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(14);
        let retention = BondedReceiverRetentionPolicy::bounded(8, 2);

        set.record_key_with_retention(
            0,
            BondedSymbolKey::new(object_id, 0, 0),
            SymbolKind::Source,
            retention,
        );
        set.record_key_with_retention(
            1,
            BondedSymbolKey::new(object_id, 1, 0),
            SymbolKind::Source,
            retention,
        );

        assert_eq!(
            set.record_key_with_retention(
                2,
                BondedSymbolKey::new(object_id, 2, 0),
                SymbolKind::Source,
                retention,
            ),
            BondedSymbolDisposition::RejectedByRetention {
                key: BondedSymbolKey::new(object_id, 2, 0),
                reason: BondedReceiverRetentionRejectReason::TransferSymbolCap,
            }
        );
        assert_eq!(set.len(), 2);
        assert_eq!(set.aggregate_stats().symbols_rejected_by_retention, 1);
    }

    #[test]
    fn eight_donor_spray_holds_the_retention_bound_at_every_step() {
        // C4 (z01bbr.3.4): N donors spraying simultaneously must never grow
        // receiver retention past the policy. The bound is asserted after
        // EVERY ingest — a transient balloon (the bad-regime 261 MB class)
        // cannot hide inside an end-state-only check. Donor ESI windows
        // overlap heavily and ingests interleave round-robin, so the set
        // absorbs 8× inbound pressure through dedup + retention rejection
        // rather than memory growth.
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(21);
        const BLOCKS: u8 = 4;
        const PER_BLOCK_CAP: u32 = 16;
        // Below BLOCKS × PER_BLOCK_CAP so BOTH cap kinds engage.
        const TRANSFER_CAP: usize = 48;
        let retention = BondedReceiverRetentionPolicy::bounded(PER_BLOCK_CAP, TRANSFER_CAP);

        let mut received = 0u64;
        for esi_step in 0..40u32 {
            for donor in 0..8u32 {
                for block in 0..BLOCKS {
                    // Each donor's window starts 4 ESIs later: ~90 %
                    // cross-donor collision once windows overlap.
                    let esi = donor * 4 + esi_step;
                    let kind = if esi % 3 == 0 {
                        SymbolKind::Source
                    } else {
                        SymbolKind::Repair
                    };
                    let _ = set.record_key_with_retention(
                        donor,
                        BondedSymbolKey::new(object_id, block, esi),
                        kind,
                        retention,
                    );
                    received += 1;
                    assert!(
                        set.len() <= TRANSFER_CAP,
                        "retention bound violated: len={} after {received} ingests",
                        set.len()
                    );
                }
            }
        }

        let aggregate = set.aggregate_stats();
        assert_eq!(aggregate.donor_count, 8);
        assert_eq!(aggregate.symbols_received, received);
        // Accounting closes: every ingest is exactly one of
        // accepted / duplicate / retention-rejected.
        assert_eq!(
            aggregate.symbols_accepted
                + aggregate.duplicate_symbols
                + aggregate.symbols_rejected_by_retention,
            received
        );
        assert_eq!(aggregate.symbols_accepted as usize, set.len());
        // The pressure saturated the transfer-wide cap exactly.
        assert_eq!(set.len(), TRANSFER_CAP);
        // The 8× amplification was absorbed by dedup AND retention.
        assert!(aggregate.duplicate_symbols > 0);
        assert!(aggregate.symbols_rejected_by_retention > 0);
    }

    #[test]
    fn block_coverage_counts_deduplicated_symbols_across_donors() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(13);

        for (donor, esi) in [(0, 0), (1, 1), (2, 2), (3, 2)] {
            set.record_key(
                donor,
                BondedSymbolKey::new(object_id, 0, esi),
                SymbolKind::Repair,
            );
        }

        let coverage = set.block_coverage(object_id, 0, 4);

        assert_eq!(
            coverage,
            BondedBlockCoverage {
                object_id,
                sbn: 0,
                target_symbols: 4,
                accepted_symbols: 3,
                deficit_symbols: 1,
            }
        );
        assert!(!coverage.is_complete());

        set.record_key(4, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        assert!(set.block_coverage(object_id, 0, 4).is_complete());
    }

    #[test]
    fn blocks_needing_more_reports_only_incomplete_blocks() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(17);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 2), SymbolKind::Repair);

        let needs_more = set.blocks_needing_more([(object_id, 0, 2), (object_id, 1, 2)]);

        assert_eq!(
            needs_more,
            vec![BondedBlockCoverage {
                object_id,
                sbn: 0,
                target_symbols: 2,
                accepted_symbols: 1,
                deficit_symbols: 1,
            }]
        );
    }

    #[test]
    fn progress_snapshot_summarizes_block_completion_and_deficit() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(19);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 2), SymbolKind::Repair);
        set.record_key(2, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);
        set.record_key(3, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let snapshot = set.progress_snapshot([(object_id, 0, 2), (object_id, 1, 3)]);

        assert_eq!(snapshot.aggregate.symbols_received, 4);
        assert_eq!(snapshot.aggregate.symbols_accepted, 3);
        assert_eq!(snapshot.aggregate.duplicate_symbols, 1);
        assert_eq!(snapshot.duplicate_rate_ppm(), 250_000);
        assert_eq!(snapshot.total_blocks, 2);
        assert_eq!(snapshot.complete_blocks, 1);
        assert_eq!(snapshot.incomplete_blocks, 1);
        assert_eq!(snapshot.total_deficit_symbols, 2);
        assert!(!snapshot.is_complete());
    }

    #[test]
    fn progress_snapshot_with_no_blocks_is_complete() {
        let set = BondedReceiverSymbolSet::new();
        let snapshot = set.progress_snapshot(std::iter::empty::<(ObjectId, u8, u32)>());

        assert_eq!(snapshot.total_blocks, 0);
        assert_eq!(snapshot.complete_blocks, 0);
        assert_eq!(snapshot.incomplete_blocks, 0);
        assert_eq!(snapshot.total_deficit_symbols, 0);
        assert!(snapshot.is_complete());
    }

    #[test]
    fn live_progress_metrics_reports_donors_blocks_paths_and_feedback_counts() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(21);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        set.record_key(3, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let metrics = set.live_progress_metrics([(object_id, 0, 3), (object_id, 1, 2)], false);

        assert_eq!(metrics.aggregate.symbols_received, 5);
        assert_eq!(metrics.aggregate.symbols_accepted, 4);
        assert_eq!(metrics.aggregate.duplicate_symbols, 1);
        assert_eq!(metrics.aggregate.source_symbols_accepted, 3);
        assert_eq!(metrics.aggregate.repair_symbols_accepted, 1);
        assert_eq!(
            metrics
                .donors
                .iter()
                .map(|donor| donor.donor_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(metrics.donors[3].stats.duplicate_symbols, 1);
        assert_eq!(metrics.donors[3].duplicate_rate_ppm, 1_000_000);

        assert_eq!(metrics.blocks.len(), 2);
        assert_eq!(metrics.blocks[0].accepted_symbols, 3);
        assert_eq!(metrics.blocks[0].deficit_symbols, 0);
        assert_eq!(metrics.blocks[0].missing_source_esis, vec![2]);
        assert_eq!(
            metrics.blocks[0].completion_path,
            BondedBlockCompletionPath::RepairDecode
        );
        assert_eq!(metrics.blocks[1].accepted_symbols, 1);
        assert_eq!(metrics.blocks[1].deficit_symbols, 1);
        assert_eq!(metrics.blocks[1].missing_source_esis, vec![1]);
        assert_eq!(
            metrics.blocks[1].completion_path,
            BondedBlockCompletionPath::Incomplete
        );

        assert_eq!(metrics.source_memcpy_blocks, 0);
        assert_eq!(metrics.repair_decode_blocks, 1);
        assert_eq!(metrics.incomplete_blocks, 1);
        assert_eq!(metrics.total_deficit_symbols, 1);
        assert_eq!(metrics.total_missing_source_symbols, 2);
        assert_eq!(metrics.feedback_action_count, 12);
        assert_eq!(metrics.need_more_action_count, 12);
        assert_eq!(metrics.close_action_count, 0);
    }

    #[test]
    fn completion_paths_have_stable_trace_tokens() {
        assert_eq!(BondedBlockCompletionPath::Incomplete.as_str(), "incomplete");
        assert_eq!(
            BondedBlockCompletionPath::SourceMemcpy.as_str(),
            "source_memcpy"
        );
        assert_eq!(
            BondedBlockCompletionPath::RepairDecode.as_str(),
            "repair_decode"
        );
    }

    #[test]
    fn live_progress_metrics_trace_lines_cover_aggregate_donors_blocks_and_feedback() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(22);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        set.record_key(3, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let metrics = set.live_progress_metrics([(object_id, 0, 3), (object_id, 1, 2)], false);
        let lines = metrics.trace_lines("need_more");

        assert!(lines[0].contains("receiver phase=need_more donors=4 blocks=2 accepted=4/5"));
        assert!(lines[0].contains("duplicate_rate_ppm=200000"));
        assert!(lines[0].contains("need_more_actions=12"));
        assert!(lines[0].contains("close_actions=0"));
        assert!(lines.iter().any(|line| line.contains("donor=3")
            && line.contains("duplicates=1")
            && line.contains("duplicate_rate_ppm=1000000")));
        assert!(lines.iter().any(|line| line.contains("block object=")
            && line.contains("sbn=0")
            && line.contains("missing_source=1")
            && line.contains("completion_path=repair_decode")));
        assert!(lines.iter().any(|line| line.contains("block object=")
            && line.contains("sbn=1")
            && line.contains("deficit=1")
            && line.contains("completion_path=incomplete")));
    }

    #[test]
    fn feedback_plan_broadcasts_aggregate_need_more_to_all_donors() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(23);

        set.record_key(2, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 2), SymbolKind::Repair);
        set.record_key(1, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 2), (object_id, 1, 3)], false);

        assert_eq!(plan.donor_targets, vec![0, 1, 2]);
        assert_eq!(
            plan.source_first_need_more,
            vec![
                BondedBlockSourceHoles {
                    object_id,
                    sbn: 0,
                    source_symbols: 2,
                    missing_source_esis: vec![1],
                },
                BondedBlockSourceHoles {
                    object_id,
                    sbn: 1,
                    source_symbols: 3,
                    missing_source_esis: vec![1, 2],
                },
            ]
        );
        assert_eq!(
            plan.need_more,
            vec![BondedBlockCoverage {
                object_id,
                sbn: 1,
                target_symbols: 3,
                accepted_symbols: 1,
                deficit_symbols: 2,
            }]
        );
        assert!(!plan.close);
        assert!(plan.should_broadcast_need_more());
        assert!(plan.should_broadcast_source_first_need_more());
        assert!(plan.should_broadcast_repair_need_more());
        assert!(!plan.should_broadcast_close());
        assert_eq!(plan.progress.total_deficit_symbols, 2);
    }

    #[test]
    fn feedback_plan_materializes_need_more_actions_for_every_donor() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(24);

        set.record_key(2, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 3)], false);
        let source_holes = BondedBlockSourceHoles {
            object_id,
            sbn: 0,
            source_symbols: 3,
            missing_source_esis: vec![1, 2],
        };
        let repair_deficit = BondedBlockCoverage {
            object_id,
            sbn: 0,
            target_symbols: 3,
            accepted_symbols: 2,
            deficit_symbols: 1,
        };

        assert_eq!(
            plan.broadcast_actions(),
            vec![
                BondedReceiverFeedbackAction::SourceFirstNeedMore {
                    donor_index: 0,
                    holes: source_holes.clone(),
                },
                BondedReceiverFeedbackAction::RepairNeedMore {
                    donor_index: 0,
                    coverage: repair_deficit,
                },
                BondedReceiverFeedbackAction::SourceFirstNeedMore {
                    donor_index: 2,
                    holes: source_holes,
                },
                BondedReceiverFeedbackAction::RepairNeedMore {
                    donor_index: 2,
                    coverage: repair_deficit,
                },
            ]
        );
    }

    #[test]
    fn feedback_plan_prefers_source_holes_even_when_repairs_meet_target() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(27);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 4), SymbolKind::Repair);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 3)], false);

        assert_eq!(plan.donor_targets, vec![0, 1, 2]);
        assert_eq!(
            plan.source_first_need_more,
            vec![BondedBlockSourceHoles {
                object_id,
                sbn: 0,
                source_symbols: 3,
                missing_source_esis: vec![1, 2],
            }]
        );
        assert!(plan.need_more.is_empty());
        assert!(plan.progress.is_complete());
        assert!(plan.should_broadcast_need_more());
        assert!(plan.should_broadcast_source_first_need_more());
        assert!(!plan.should_broadcast_repair_need_more());
        assert!(!plan.is_idle());
    }

    #[test]
    fn feedback_plan_close_suppresses_stale_need_more() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(29);

        set.record_key(1, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 0, 4), SymbolKind::Repair);

        let plan = set.feedback_broadcast_plan([(object_id, 0, 4)], true);

        assert_eq!(plan.donor_targets, vec![0, 1]);
        assert!(plan.source_first_need_more.is_empty());
        assert!(plan.need_more.is_empty());
        assert!(plan.close);
        assert!(!plan.should_broadcast_need_more());
        assert!(!plan.should_broadcast_source_first_need_more());
        assert!(!plan.should_broadcast_repair_need_more());
        assert!(plan.should_broadcast_close());
        assert_eq!(plan.progress.total_deficit_symbols, 2);
        assert_eq!(
            plan.broadcast_actions(),
            vec![
                BondedReceiverFeedbackAction::Close { donor_index: 0 },
                BondedReceiverFeedbackAction::Close { donor_index: 1 },
            ]
        );

        let metrics = set.live_progress_metrics([(object_id, 0, 4)], true);
        assert_eq!(metrics.feedback_action_count, 2);
        assert_eq!(metrics.need_more_action_count, 0);
        assert_eq!(metrics.close_action_count, 2);
    }

    #[test]
    fn feedback_plan_without_donor_targets_is_not_broadcastable() {
        let set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(31);
        let plan = set.feedback_broadcast_plan([(object_id, 0, 1)], false);

        assert!(plan.donor_targets.is_empty());
        assert_eq!(plan.source_first_need_more.len(), 1);
        assert_eq!(plan.need_more.len(), 1);
        assert!(!plan.should_broadcast_need_more());
        assert!(!plan.should_broadcast_source_first_need_more());
        assert!(!plan.should_broadcast_repair_need_more());
        assert!(!plan.should_broadcast_close());
        assert_eq!(plan.progress.total_deficit_symbols, 1);
    }

    #[test]
    fn duplicate_scope_is_object_block_and_esi_not_just_esi() {
        let mut set = BondedReceiverSymbolSet::new();

        for symbol in [
            symbol(1, 0, 7, SymbolKind::Source),
            symbol(1, 1, 7, SymbolKind::Source),
            symbol(2, 0, 7, SymbolKind::Source),
        ] {
            assert!(matches!(
                set.record_symbol(0, &symbol),
                BondedSymbolDisposition::Accepted(_)
            ));
        }

        assert_eq!(set.len(), 3);
        assert_eq!(set.aggregate_stats().duplicate_symbols, 0);
    }

    #[test]
    fn source_holes_ignore_repair_symbols_and_duplicates() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(37);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(2, BondedSymbolKey::new(object_id, 0, 3), SymbolKind::Repair);

        let holes = set.block_source_holes(object_id, 0, 3);

        assert_eq!(
            holes,
            BondedBlockSourceHoles {
                object_id,
                sbn: 0,
                source_symbols: 3,
                missing_source_esis: vec![1, 2],
            }
        );
        assert!(!holes.is_source_complete());
        assert_eq!(holes.missing_source_count(), 2);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 2), SymbolKind::Source);

        assert!(set.block_source_holes(object_id, 0, 3).is_source_complete());
    }

    #[test]
    fn blocks_with_source_holes_filters_complete_blocks() {
        let mut set = BondedReceiverSymbolSet::new();
        let object_id = ObjectId::new_for_test(41);

        set.record_key(0, BondedSymbolKey::new(object_id, 0, 0), SymbolKind::Source);
        set.record_key(1, BondedSymbolKey::new(object_id, 0, 1), SymbolKind::Source);
        set.record_key(0, BondedSymbolKey::new(object_id, 1, 0), SymbolKind::Source);

        let holes = set.blocks_with_source_holes([(object_id, 0, 2), (object_id, 1, 2)]);

        assert_eq!(
            holes,
            vec![BondedBlockSourceHoles {
                object_id,
                sbn: 1,
                source_symbols: 2,
                missing_source_esis: vec![1],
            }]
        );
    }

    #[test]
    fn empty_set_reports_zero_duplicate_rate() {
        let set = BondedReceiverSymbolSet::new();

        assert!(set.is_empty());
        assert_eq!(set.aggregate_stats().duplicate_rate_ppm(), 0);
        assert_eq!(set.donor_stats(0), None);
    }
