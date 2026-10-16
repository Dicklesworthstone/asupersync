    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::remote::NodeId;
    use crate::types::ObligationId;
    use proptest::prelude::*;

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    #[derive(Clone, Copy, Debug)]
    struct TraceOp {
        id_index: u8,
        action: u8,
    }

    fn apply_trace(ledger: &mut CrdtObligationLedger, ops: &[TraceOp]) {
        for op in ops {
            let id = oid(u32::from(op.id_index % 6) + 1);
            match op.action % 7 {
                0 => {
                    let kind = match op.id_index % 4 {
                        0 => ObligationKind::SendPermit,
                        1 => ObligationKind::Ack,
                        2 => ObligationKind::Lease,
                        _ => ObligationKind::IoOp,
                    };
                    let _ = ledger.record_acquire(id, kind);
                }
                1 => {
                    let _ = ledger.record_commit(id);
                }
                2 => {
                    let _ = ledger.record_abort(id);
                }
                3 => {
                    let _ = ledger.record_acquire(id, ObligationKind::SendPermit);
                }
                4 => {
                    let _ = ledger.record_acquire(id, ObligationKind::Lease);
                }
                5 => {
                    ledger.force_abort_repair(id);
                }
                _ => {
                    let _ = ledger.record_acquire(id, ObligationKind::Ack);
                    let _ = ledger.record_commit(id);
                }
            }
        }
    }

    fn ledger_signature(
        ledger: &CrdtObligationLedger,
    ) -> Vec<(
        ObligationId,
        LatticeState,
        Option<ObligationKind>,
        BTreeMap<NodeId, LatticeState>,
        BTreeSet<NodeId>,
        BTreeMap<NodeId, u64>,
        BTreeMap<NodeId, u64>,
    )> {
        ledger
            .entries
            .iter()
            .map(|(id, entry)| {
                (
                    *id,
                    entry.state,
                    entry.kind,
                    entry.witnesses.clone(),
                    entry.repair_nodes.clone(),
                    entry.acquire_counts.clone(),
                    entry.resolve_counts.clone(),
                )
            })
            .collect()
    }

    // ── Basic operations ────────────────────────────────────────────────

    #[test]
    fn acquire_sets_reserved() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let state = ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        assert_eq!(state, LatticeState::Reserved);
        assert_eq!(ledger.get(&oid(1)), LatticeState::Reserved);
    }

    #[test]
    fn commit_sets_committed() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::Ack);
        let state = ledger.record_commit(oid(1));
        assert_eq!(state, LatticeState::Committed);
    }

    #[test]
    fn abort_sets_aborted() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::Lease);
        let state = ledger.record_abort(oid(1));
        assert_eq!(state, LatticeState::Aborted);
    }

    #[test]
    fn unknown_obligation_returns_unknown() {
        let ledger = CrdtObligationLedger::new(node("A"));
        assert_eq!(ledger.get(&oid(99)), LatticeState::Unknown);
    }

    // ── Linearity tracking ──────────────────────────────────────────────

    #[test]
    fn single_acquire_resolve_is_linear() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        let entry = ledger.get_entry(&oid(1)).unwrap();
        assert!(entry.is_linear());
        assert_eq!(entry.total_acquires(), 1);
        assert_eq!(entry.total_resolves(), 1);
    }

    #[test]
    fn double_acquire_on_same_node_violates_linearity() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let entry = ledger.get_entry(&oid(1)).unwrap();
        assert!(!entry.is_linear());
        assert_eq!(entry.total_acquires(), 2);
    }

    #[test]
    fn double_resolve_violates_linearity() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        ledger.record_commit(oid(1));
        let entry = ledger.get_entry(&oid(1)).unwrap();
        assert!(!entry.is_linear());
        assert_eq!(entry.total_resolves(), 2);
    }

    #[test]
    fn linearity_violations_reported() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let violations = ledger.linearity_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, oid(1));
    }

    // ── Merge semantics ─────────────────────────────────────────────────

    #[test]
    fn merge_two_replicas_converges() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(2), ObligationKind::Ack);
        b.record_abort(oid(2));

        a.merge(&b);
        assert_eq!(a.get(&oid(1)), LatticeState::Committed);
        assert_eq!(a.get(&oid(2)), LatticeState::Aborted);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn merge_is_commutative() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.get(&oid(1)), ba.get(&oid(1)));
        assert_eq!(ab.get(&oid(1)), LatticeState::Committed);
    }

    proptest! {
        #[test]
        fn metamorphic_merge_trace_commutativity(
            a_ops in prop::collection::vec((0u8..12, 0u8..7), 0..24),
            b_ops in prop::collection::vec((0u8..12, 0u8..7), 0..24),
        ) {
            let a_ops: Vec<TraceOp> = a_ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();
            let b_ops: Vec<TraceOp> = b_ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();

            let mut a = CrdtObligationLedger::new(node("A"));
            let mut b = CrdtObligationLedger::new(node("B"));
            apply_trace(&mut a, &a_ops);
            apply_trace(&mut b, &b_ops);

            let mut ab = a.clone();
            ab.merge(&b);
            let mut ba = b.clone();
            ba.merge(&a);

            prop_assert_eq!(ledger_signature(&ab), ledger_signature(&ba));
            prop_assert_eq!(ab.pending(), ba.pending());
            prop_assert_eq!(ab.conflicts().len(), ba.conflicts().len());
            prop_assert_eq!(
                ab.linearity_violations().len(),
                ba.linearity_violations().len()
            );
        }
    }

    #[test]
    fn merge_is_associative() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_commit(oid(1));

        let mut c = CrdtObligationLedger::new(node("C"));
        c.record_acquire(oid(2), ObligationKind::Lease);

        // (a ⊔ b) ⊔ c
        let mut ab_c = a.clone();
        ab_c.merge(&b);
        ab_c.merge(&c);

        // a ⊔ (b ⊔ c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        assert_eq!(ab_c.get(&oid(1)), a_bc.get(&oid(1)));
        assert_eq!(ab_c.get(&oid(2)), a_bc.get(&oid(2)));
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let before = a.clone();
        a.merge(&before);
        assert_eq!(a, before);
    }

    #[test]
    fn conflict_detected_on_commit_abort_merge() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);
        assert!(!a.is_sound());
        let conflicts = a.conflicts();
        assert_eq!(conflicts.len(), 1);
    }

    // ── Terminal state absorbing ────────────────────────────────────────

    #[test]
    fn terminal_state_absorbs_reserved() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        // Stale replica only saw the acquire
        let mut stale = CrdtObligationLedger::new(node("B"));
        stale.record_acquire(oid(1), ObligationKind::SendPermit);

        // Merge stale into committed: still committed
        a.merge(&stale);
        assert_eq!(a.get(&oid(1)), LatticeState::Committed);
    }

    // ── Compaction ──────────────────────────────────────────────────────

    #[test]
    fn compact_tombstones_terminal_linear_entries() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        // oid(2) still pending

        let compacted = ledger.compact();
        // A single-node committed entry is already in compact tombstone shape.
        assert_eq!(compacted, 0);
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.get(&oid(1)), LatticeState::Committed); // tombstoned
        assert_eq!(ledger.get(&oid(2)), LatticeState::Reserved); // kept
        let entry = ledger.get_entry(&oid(1)).expect("entry should exist");
        assert!(entry.is_terminal());
        assert!(entry.is_linear());
        assert_eq!(entry.total_acquires(), 1);
        assert_eq!(entry.total_resolves(), 1);
        assert_eq!(
            *entry.witnesses.get(&node("A")).expect("local witness"),
            LatticeState::Committed
        );
    }

    #[test]
    fn compact_preserves_conflicts() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);
        assert!(a.get(&oid(1)).is_conflict());

        let compacted = a.compact();
        assert_eq!(compacted, 0); // conflict not compacted
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn compact_preserves_linearity_violations() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));

        let compacted = ledger.compact();
        assert_eq!(compacted, 0); // violation not compacted
    }

    #[test]
    fn compact_prevents_stale_reserved_resurrection() {
        let id = oid(11);
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(id, ObligationKind::SendPermit);
        a.record_commit(id);

        let compacted = a.compact();
        // Entry is already in compact tombstone shape before compaction.
        assert_eq!(compacted, 0);
        assert_eq!(a.get(&id), LatticeState::Committed);

        // Stale replica only observed the pre-terminal reserved state.
        let mut stale = CrdtObligationLedger::new(node("B"));
        stale.record_acquire(id, ObligationKind::SendPermit);
        assert_eq!(stale.get(&id), LatticeState::Reserved);

        a.merge(&stale);

        // Terminal state must remain dominant after merge.
        assert_eq!(a.get(&id), LatticeState::Committed);
    }

    // ── Pending / snapshot ──────────────────────────────────────────────

    #[test]
    fn pending_returns_only_reserved() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        ledger.record_commit(oid(2));

        let pending = ledger.pending();
        assert_eq!(pending, vec![oid(1)]);
    }

    #[test]
    fn snapshot_reflects_state() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        ledger.record_commit(oid(2));
        ledger.record_acquire(oid(3), ObligationKind::Lease);
        ledger.record_abort(oid(3));

        let snap = ledger.snapshot();
        assert_eq!(snap.total, 3);
        assert_eq!(snap.pending, 1);
        assert_eq!(snap.committed, 1);
        assert_eq!(snap.aborted, 1);
        assert_eq!(snap.conflicts, 0);
        assert_eq!(snap.linearity_violations, 0);
    }

    #[test]
    fn is_sound_with_clean_ledger() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        assert!(ledger.is_sound());
    }

    // ── Ring gossip convergence ─────────────────────────────────────────

    #[test]
    fn three_node_ring_gossip_converges() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(2), ObligationKind::Ack);
        b.record_abort(oid(2));

        let mut c = CrdtObligationLedger::new(node("C"));
        c.record_acquire(oid(3), ObligationKind::Lease);

        // Ring gossip: a→b→c→a→b
        a.merge(&b);
        b.merge(&c);
        c.merge(&a);
        a.merge(&c);
        b.merge(&a);

        // All replicas should agree
        for id in [oid(1), oid(2), oid(3)] {
            assert_eq!(
                a.get(&id),
                b.get(&id),
                "divergence on {id:?} between A and B"
            );
            assert_eq!(
                b.get(&id),
                c.get(&id),
                "divergence on {id:?} between B and C"
            );
        }

        assert_eq!(a.get(&oid(1)), LatticeState::Committed);
        assert_eq!(a.get(&oid(2)), LatticeState::Aborted);
        assert_eq!(a.get(&oid(3)), LatticeState::Reserved);
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn snapshot_display_is_readable() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let snap = ledger.snapshot();
        let display = format!("{snap}");
        assert!(display.contains("total=1"));
        assert!(display.contains("pending=1"));
    }

    #[test]
    fn linearity_violation_display() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let violations = ledger.linearity_violations();
        let display = format!("{}", violations[0]);
        assert!(display.contains("acquires=2"));
    }

    #[test]
    fn acquire_mismatched_kind_marks_conflict() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let id = oid(42);

        ledger.record_acquire(id, ObligationKind::SendPermit);
        let state = ledger.record_acquire(id, ObligationKind::Lease);

        let entry = ledger.get_entry(&id).expect("entry should exist");
        assert_eq!(state, LatticeState::Conflict);
        assert_eq!(entry.state, LatticeState::Conflict);
        assert_eq!(entry.kind, Some(ObligationKind::SendPermit));
        assert_eq!(entry.total_acquires(), 1);
    }

    #[test]
    fn acquire_after_terminal_preserves_terminal_witness() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let id = oid(43);

        ledger.record_acquire(id, ObligationKind::Ack);
        ledger.record_commit(id);
        let before = ledger
            .get_entry(&id)
            .expect("entry should exist")
            .witnesses
            .get(&node("A"))
            .copied();

        // A late acquire observation must not downgrade witness provenance
        // on a terminal entry.
        let state = ledger.record_acquire(id, ObligationKind::Lease);
        let entry = ledger.get_entry(&id).expect("entry should exist");
        let after = entry.witnesses.get(&node("A")).copied();

        assert_eq!(state, LatticeState::Committed);
        assert_eq!(before, Some(LatticeState::Committed));
        assert_eq!(after, Some(LatticeState::Committed));
        assert_eq!(entry.total_acquires(), 1);
        assert_eq!(entry.total_resolves(), 1);
    }

    #[test]
    fn merge_mismatched_kind_marks_conflict() {
        let id = oid(44);

        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(id, ObligationKind::SendPermit);

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(id, ObligationKind::Lease);

        a.merge(&b);
        let entry = a.get_entry(&id).expect("entry should exist");
        assert_eq!(entry.state, LatticeState::Conflict);
        assert!(entry.is_conflict());
    }

    #[test]
    fn force_abort_repair_skips_healthy_pending_entry() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let id = oid(45);
        ledger.record_acquire(id, ObligationKind::Ack);

        ledger.force_abort_repair(id);

        let entry = ledger.get_entry(&id).expect("entry should exist");
        assert_eq!(entry.state, LatticeState::Reserved);
        assert_eq!(entry.total_acquires(), 1);
        assert_eq!(entry.total_resolves(), 0);
    }

    #[test]
    fn force_abort_repair_missing_id_is_noop() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let id = oid(145);

        ledger.force_abort_repair(id);

        assert!(ledger.get_entry(&id).is_none());
        assert!(ledger.is_empty());
    }

    #[test]
    fn force_abort_repair_collapses_conflict_to_linear_aborted() {
        let id = oid(46);
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(id, ObligationKind::SendPermit);
        a.record_commit(id);

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(id, ObligationKind::SendPermit);
        b.record_abort(id);

        a.merge(&b);
        let conflicted = a.get_entry(&id).expect("entry should exist");
        assert!(conflicted.is_conflict());
        assert!(!conflicted.is_linear());

        a.force_abort_repair(id);
        let repaired = a.get_entry(&id).expect("entry should exist");
        assert_eq!(repaired.state, LatticeState::Aborted);
        assert!(repaired.is_linear());
        assert_eq!(repaired.total_acquires(), 1);
        assert_eq!(repaired.total_resolves(), 1);
        assert_eq!(repaired.witnesses.len(), 1);
        assert_eq!(
            repaired.witnesses.get(&node("A")).copied(),
            Some(LatticeState::Aborted)
        );
        assert_eq!(repaired.repair_nodes.len(), 1);
        assert!(repaired.repair_nodes.contains(&node("A")));
    }

    #[test]
    fn force_abort_repair_survives_merge_with_stale_conflict() {
        let id = oid(48);
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(id, ObligationKind::SendPermit);
        a.record_commit(id);

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(id, ObligationKind::SendPermit);
        b.record_abort(id);

        a.merge(&b);
        let stale_conflict = a.clone();
        assert!(a.get(&id).is_conflict());

        a.force_abort_repair(id);
        a.merge(&stale_conflict);

        let repaired = a.get_entry(&id).expect("entry should exist");
        assert_eq!(repaired.state, LatticeState::Aborted);
        assert!(repaired.is_linear());
        assert!(!repaired.is_conflict());
        assert_eq!(repaired.total_acquires(), 1);
        assert_eq!(repaired.total_resolves(), 1);
        assert_eq!(
            repaired.witnesses.get(&node("A")).copied(),
            Some(LatticeState::Aborted)
        );
    }

    #[test]
    fn force_abort_repair_converges_after_independent_repairs() {
        let id = oid(49);
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(id, ObligationKind::SendPermit);
        a.record_commit(id);

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(id, ObligationKind::SendPermit);
        b.record_abort(id);

        a.merge(&b);
        b.merge(&a);
        assert!(a.get(&id).is_conflict());
        assert!(b.get(&id).is_conflict());

        a.force_abort_repair(id);
        b.force_abort_repair(id);
        a.merge(&b);

        let repaired = a.get_entry(&id).expect("entry should exist");
        assert_eq!(repaired.state, LatticeState::Aborted);
        assert!(repaired.is_linear());
        assert_eq!(repaired.total_acquires(), 1);
        assert_eq!(repaired.total_resolves(), 1);
        assert_eq!(repaired.witnesses.len(), 1);
        assert_eq!(repaired.repair_nodes.len(), 2);
        assert_eq!(
            repaired.witnesses.get(&node("A")).copied(),
            Some(LatticeState::Aborted)
        );
    }

    #[test]
    fn compact_rewrites_non_minimal_terminal_metadata() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let id = oid(47);
        ledger.record_acquire(id, ObligationKind::Lease);
        ledger.record_abort(id);

        let entry = ledger.entries.get_mut(&id).expect("entry should exist");
        entry.witnesses.insert(node("B"), LatticeState::Unknown);
        entry.acquire_counts.insert(node("B"), 0);
        entry.resolve_counts.insert(node("B"), 0);
        assert!(entry.is_terminal());
        assert!(entry.is_linear());

        let compacted = ledger.compact();
        assert_eq!(compacted, 1);

        let compacted_entry = ledger.get_entry(&id).expect("entry should exist");
        assert_eq!(compacted_entry.witnesses.len(), 1);
        assert_eq!(compacted_entry.total_acquires(), 1);
        assert_eq!(compacted_entry.total_resolves(), 1);
        assert_eq!(
            compacted_entry.witnesses.get(&node("A")).copied(),
            Some(LatticeState::Aborted)
        );
    }

    // ── derive-trait coverage (wave 74) ──────────────────────────────────

    #[test]
    fn crdt_obligation_entry_debug_clone_eq() {
        let mut ledger = CrdtObligationLedger::new(node("X"));
        let id = ObligationId::new_for_test(50, 0);
        ledger.record_acquire(id, ObligationKind::SendPermit);

        let entry = ledger.get_entry(&id).unwrap();
        let entry2 = entry.clone();
        assert_eq!(entry, &entry2);
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("CrdtObligationEntry"));
    }

    #[test]
    fn crdt_obligation_ledger_debug_clone_eq() {
        let ledger = CrdtObligationLedger::new(node("Y"));
        let ledger2 = ledger.clone();
        assert_eq!(ledger, ledger2);
        let dbg = format!("{ledger:?}");
        assert!(dbg.contains("CrdtObligationLedger"));
    }

    #[test]
    fn linearity_violation_debug_clone() {
        let v = LinearityViolation {
            id: ObligationId::new_for_test(1, 0),
            total_acquires: 2,
            total_resolves: 1,
            witnesses: BTreeMap::new(),
        };
        let v2 = v;
        assert_eq!(v2.total_acquires, 2);
        let dbg = format!("{v2:?}");
        assert!(dbg.contains("LinearityViolation"));
    }

    #[test]
    fn ledger_snapshot_debug_clone() {
        let s = LedgerSnapshot {
            node: node("Z"),
            total: 10,
            pending: 3,
            committed: 5,
            aborted: 1,
            conflicts: 1,
            linearity_violations: 0,
        };
        let s2 = s;
        assert_eq!(s2.total, 10);
        assert_eq!(s2.pending, 3);
        let dbg = format!("{s2:?}");
        assert!(dbg.contains("LedgerSnapshot"));
    }

    #[test]
    fn record_resolve_joins_witness_instead_of_overwriting() {
        // Regression: record_resolve used `insert` (overwrite) instead of `join`
        // for witnesses, losing provenance when a node makes conflicting resolutions.
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let id = oid(99);
        ledger.record_acquire(id, ObligationKind::Ack);

        // First resolve: commit
        ledger.record_commit(id);
        let entry = ledger.get_entry(&id).expect("entry exists");
        assert_eq!(
            *entry.witnesses.get(&node("A")).unwrap(),
            LatticeState::Committed,
        );

        // Second resolve on same obligation: abort.
        // Committed and Aborted are incomparable in the diamond lattice,
        // so their join is Conflict. With the old `insert`, witness would
        // just become Aborted (overwrite), hiding the commit provenance.
        // With `join`, Committed ⊔ Aborted = Conflict — correctly capturing
        // that this node made contradictory resolutions.
        ledger.record_abort(id);
        let entry = ledger.get_entry(&id).expect("entry exists");
        let witness = *entry.witnesses.get(&node("A")).unwrap();
        assert_eq!(witness, LatticeState::Conflict);
        // The global state should also reflect the conflict
        assert_eq!(entry.state, LatticeState::Conflict);
    }

    // =========================================================================
    // Metamorphic relations for CRDT merge: idempotence, associativity,
    // absorption, monotonicity.
    //
    // The existing metamorphic_merge_trace_commutativity covers swap-order.
    // Commutativity alone does not catch bugs in the self-join path
    // (idempotence), bugs in associative grouping (nested merges), or
    // non-growing bugs (a merge that drops entries). These MRs close the
    // semilattice law coverage: (commutativity ∧ associativity ∧
    // idempotence) is exactly the axiom set for a join-semilattice CRDT.
    // =========================================================================

    proptest! {
        /// MR — Idempotence: merge(a, a) must leave `a` signature-equal.
        /// This is the canonical CRDT self-merge law.
        #[test]
        fn metamorphic_merge_is_idempotent(
            ops in prop::collection::vec((0u8..12, 0u8..7), 0..24),
        ) {
            let ops: Vec<TraceOp> = ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();

            let mut a = CrdtObligationLedger::new(node("A"));
            apply_trace(&mut a, &ops);

            let before = ledger_signature(&a);
            let clone = a.clone();
            a.merge(&clone);
            let after = ledger_signature(&a);

            prop_assert_eq!(before, after, "merge(a, a) altered the ledger");
        }

        /// MR — Associativity: (a ⊔ b) ⊔ c ≡ a ⊔ (b ⊔ c).
        /// Equivalent via signature, not struct equality (witnesses are a
        /// BTreeMap so their iteration order is stable; signature captures
        /// the observable lattice state).
        #[test]
        fn metamorphic_merge_is_associative(
            a_ops in prop::collection::vec((0u8..12, 0u8..7), 0..16),
            b_ops in prop::collection::vec((0u8..12, 0u8..7), 0..16),
            c_ops in prop::collection::vec((0u8..12, 0u8..7), 0..16),
        ) {
            let as_ops = |v: Vec<(u8, u8)>| -> Vec<TraceOp> {
                v.into_iter()
                    .map(|(id_index, action)| TraceOp { id_index, action })
                    .collect()
            };
            let a_ops = as_ops(a_ops);
            let b_ops = as_ops(b_ops);
            let c_ops = as_ops(c_ops);

            let mut a = CrdtObligationLedger::new(node("A"));
            let mut b = CrdtObligationLedger::new(node("B"));
            let mut c = CrdtObligationLedger::new(node("C"));
            apply_trace(&mut a, &a_ops);
            apply_trace(&mut b, &b_ops);
            apply_trace(&mut c, &c_ops);

            // (a ⊔ b) ⊔ c
            let mut left = a.clone();
            left.merge(&b);
            left.merge(&c);

            // a ⊔ (b ⊔ c)
            let mut bc = b.clone();
            bc.merge(&c);
            let mut right = a.clone();
            right.merge(&bc);

            prop_assert_eq!(
                ledger_signature(&left),
                ledger_signature(&right),
                "merge is not associative",
            );
        }

        /// Compound MR — Absorption: merge(merge(a, b), b) ≡ merge(a, b).
        /// Derives from idempotence + commutativity + associativity and
        /// catches any bug in either component that preserves commutativity
        /// on its own (a stronger oracle than each individual law).
        #[test]
        fn metamorphic_merge_absorbs_repeated_merge(
            a_ops in prop::collection::vec((0u8..12, 0u8..7), 0..20),
            b_ops in prop::collection::vec((0u8..12, 0u8..7), 0..20),
        ) {
            let a_ops: Vec<TraceOp> = a_ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();
            let b_ops: Vec<TraceOp> = b_ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();

            let mut a = CrdtObligationLedger::new(node("A"));
            let mut b = CrdtObligationLedger::new(node("B"));
            apply_trace(&mut a, &a_ops);
            apply_trace(&mut b, &b_ops);

            let mut once = a.clone();
            once.merge(&b);
            let once_sig = ledger_signature(&once);

            let mut twice = a.clone();
            twice.merge(&b);
            twice.merge(&b);
            let twice_sig = ledger_signature(&twice);

            prop_assert_eq!(
                once_sig, twice_sig,
                "re-merging b did not absorb idempotently",
            );
        }

        /// MR — Monotonicity: merging never removes entries. For every id
        /// present in `a`, the merged ledger must still contain it. This
        /// catches accidental entry drops (e.g. a branch that overwrites
        /// instead of joining).
        #[test]
        fn metamorphic_merge_preserves_existing_entries(
            a_ops in prop::collection::vec((0u8..12, 0u8..7), 0..20),
            b_ops in prop::collection::vec((0u8..12, 0u8..7), 0..20),
        ) {
            let a_ops: Vec<TraceOp> = a_ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();
            let b_ops: Vec<TraceOp> = b_ops
                .into_iter()
                .map(|(id_index, action)| TraceOp { id_index, action })
                .collect();

            let mut a = CrdtObligationLedger::new(node("A"));
            let mut b = CrdtObligationLedger::new(node("B"));
            apply_trace(&mut a, &a_ops);
            apply_trace(&mut b, &b_ops);

            let a_ids_before: BTreeSet<ObligationId> = ledger_signature(&a)
                .into_iter()
                .map(|(id, ..)| id)
                .collect();

            let mut merged = a.clone();
            merged.merge(&b);

            for id in &a_ids_before {
                prop_assert!(
                    merged.get_entry(id).is_some(),
                    "merge dropped entry {:?} that was present in a",
                    id,
                );
            }
            prop_assert!(
                merged.len() >= a_ids_before.len(),
                "merge shrank ledger: {} < {}",
                merged.len(),
                a_ids_before.len(),
            );
        }
    }
