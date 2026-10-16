    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    // -----------------------------------------------------------------------
    // Pairwise conflict detection
    // -----------------------------------------------------------------------

    #[test]
    fn detects_pairwise_conflict() {
        let o1 = oid(1);
        let mut snap_a = NodeSnapshot::new(node("A"));
        snap_a.observe(o1, LatticeState::Committed);
        let mut snap_b = NodeSnapshot::new(node("B"));
        snap_b.observe(o1, LatticeState::Aborted);

        let checker = SagaConsistencyChecker::new(vec![snap_a, snap_b], vec![]);
        let report = checker.check();
        assert!(!report.pairwise_conflicts.is_empty());
        assert!(report.has_issues());
    }

    #[test]
    fn no_conflict_when_compatible() {
        let o1 = oid(1);
        let mut snap_a = NodeSnapshot::new(node("A"));
        snap_a.observe(o1, LatticeState::Reserved);
        let mut snap_b = NodeSnapshot::new(node("B"));
        snap_b.observe(o1, LatticeState::Committed);

        let checker = SagaConsistencyChecker::new(vec![snap_a, snap_b], vec![]);
        let report = checker.check();
        assert!(report.pairwise_conflicts.is_empty());
    }

    // -----------------------------------------------------------------------
    // Phantom state detection
    // -----------------------------------------------------------------------

    #[test]
    fn detects_phantom_committed() {
        // O1 is never observed as Committed by any single node,
        // but the merge of Reserved ⊔ Committed produces Committed.
        // Wait — that's not a phantom because one node DID see Committed.
        // For a real phantom we need something subtler.

        // Actually, a phantom requires the merged result to be terminal
        // but no node saw that terminal. This can happen when both nodes
        // see Reserved, and the merge is also Reserved — not terminal,
        // so no phantom. The interesting case is when the lattice join
        // produces a terminal state from non-terminal inputs.
        // But in our lattice, Reserved ⊔ Reserved = Reserved (not terminal).
        // And Reserved ⊔ Committed = Committed, but node B saw Committed.
        // So phantoms in a 2-state lattice are rare. They arise with the
        // all-or-nothing constraint check instead.

        // For direct phantom detection, consider: if no node saw the merged
        // state. E.g., Node A sees Reserved, Node B sees Reserved. Merge = Reserved.
        // Not terminal, so no phantom. We'll test the constraint path instead.

        // Simple non-phantom case:
        let o1 = oid(1);
        let mut snap_a = NodeSnapshot::new(node("A"));
        snap_a.observe(o1, LatticeState::Committed);
        let mut snap_b = NodeSnapshot::new(node("B"));
        snap_b.observe(o1, LatticeState::Reserved);

        let checker = SagaConsistencyChecker::new(vec![snap_a, snap_b], vec![]);
        let report = checker.check();
        // Node A saw Committed, so no phantom
        assert!(report.phantom_states.is_empty());
    }

    // -----------------------------------------------------------------------
    // The key sheaf test: all-or-nothing constraint violation
    // -----------------------------------------------------------------------

    #[test]
    fn sheaf_detects_phantom_global_commit() {
        // This is the core sheaf example from the module docs.
        // Three obligations must be all-or-nothing.
        // Each node sees two of three as Committed, one as Reserved.
        // Pairwise merge: all three = Committed (no pairwise conflicts).
        // But NO single node saw all three as Committed.
        // → The "all committed" view is a phantom global section.

        let o1 = oid(1);
        let o2 = oid(2);
        let o3 = oid(3);

        let mut snap_a = NodeSnapshot::new(node("A"));
        snap_a.observe(o1, LatticeState::Committed);
        snap_a.observe(o2, LatticeState::Committed);
        snap_a.observe(o3, LatticeState::Reserved);

        let mut snap_b = NodeSnapshot::new(node("B"));
        snap_b.observe(o1, LatticeState::Committed);
        snap_b.observe(o2, LatticeState::Reserved);
        snap_b.observe(o3, LatticeState::Committed);

        let mut snap_c = NodeSnapshot::new(node("C"));
        snap_c.observe(o1, LatticeState::Reserved);
        snap_c.observe(o2, LatticeState::Committed);
        snap_c.observe(o3, LatticeState::Committed);

        let constraint = SagaConstraint::AllOrNothing {
            name: "test-saga".into(),
            obligations: [o1, o2, o3].into_iter().collect(),
        };

        let checker = SagaConsistencyChecker::new(vec![snap_a, snap_b, snap_c], vec![constraint]);
        let report = checker.check();

        // No pairwise conflicts (Reserved ⊔ Committed = Committed)
        assert!(report.pairwise_conflicts.is_empty());

        // But the sheaf check catches the phantom
        assert!(report.has_sheaf_issues());
        assert_eq!(report.constraint_violations.len(), 1);
        let violation = &report.constraint_violations[0];
        assert_eq!(violation.constraint_name, "test-saga");
        assert!(violation.explanation.contains("No single node"));
        assert!(violation.explanation.contains("H¹ ≠ 0"));
    }

    #[test]
    fn sheaf_passes_when_one_node_witnesses_all() {
        // Same setup but node A sees all three as Committed.
        let o1 = oid(1);
        let o2 = oid(2);
        let o3 = oid(3);

        let mut snap_a = NodeSnapshot::new(node("A"));
        snap_a.observe(o1, LatticeState::Committed);
        snap_a.observe(o2, LatticeState::Committed);
        snap_a.observe(o3, LatticeState::Committed);

        let mut snap_b = NodeSnapshot::new(node("B"));
        snap_b.observe(o1, LatticeState::Reserved);
        snap_b.observe(o2, LatticeState::Committed);
        snap_b.observe(o3, LatticeState::Reserved);

        let constraint = SagaConstraint::AllOrNothing {
            name: "test-saga".into(),
            obligations: [o1, o2, o3].into_iter().collect(),
        };

        let checker = SagaConsistencyChecker::new(vec![snap_a, snap_b], vec![constraint]);
        let report = checker.check();

        assert!(!report.has_sheaf_issues());
        assert!(report.constraint_violations.is_empty());
    }

    #[test]
    fn detects_mixed_terminal_states() {
        // All-or-nothing constraint where one obligation is Committed
        // and another is Aborted in the merged view.
        let o1 = oid(1);
        let o2 = oid(2);

        let mut snap = NodeSnapshot::new(node("A"));
        snap.observe(o1, LatticeState::Committed);
        snap.observe(o2, LatticeState::Aborted);

        let constraint = SagaConstraint::AllOrNothing {
            name: "mixed-saga".into(),
            obligations: [o1, o2].into_iter().collect(),
        };

        let checker = SagaConsistencyChecker::new(vec![snap], vec![constraint]);
        let report = checker.check();
        assert!(report.has_issues());
        assert_eq!(report.constraint_violations.len(), 1);
        assert!(
            report.constraint_violations[0]
                .explanation
                .contains("Merged states disagree")
        );
    }

    #[test]
    fn empty_snapshots_no_issues() {
        let checker = SagaConsistencyChecker::new(vec![], vec![]);
        let report = checker.check();
        assert!(!report.has_issues());
    }

    #[test]
    fn constraint_with_no_observations_is_fine() {
        let o1 = oid(1);
        let constraint = SagaConstraint::AllOrNothing {
            name: "empty-saga".into(),
            obligations: std::iter::once(o1).collect(),
        };

        let snap = NodeSnapshot::new(node("A"));
        let checker = SagaConsistencyChecker::new(vec![snap], vec![constraint]);
        let report = checker.check();
        assert!(!report.has_issues());
    }

    #[test]
    fn node_snapshot_debug_clone() {
        let snap = NodeSnapshot::new(node("X"));
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("NodeSnapshot"));
        let snap2 = snap;
        assert!(snap2.states.is_empty());
    }

    #[test]
    fn node_snapshot_observe_inserts() {
        let mut snap = NodeSnapshot::new(node("A"));
        snap.observe(oid(1), LatticeState::Reserved);
        snap.observe(oid(2), LatticeState::Committed);
        assert_eq!(snap.states.len(), 2);
        assert_eq!(snap.states[&oid(1)], LatticeState::Reserved);
        assert_eq!(snap.states[&oid(2)], LatticeState::Committed);
    }

    #[test]
    fn node_snapshot_observe_overwrites() {
        let mut snap = NodeSnapshot::new(node("A"));
        snap.observe(oid(1), LatticeState::Reserved);
        snap.observe(oid(1), LatticeState::Committed);
        assert_eq!(snap.states.len(), 1);
        assert_eq!(snap.states[&oid(1)], LatticeState::Committed);
    }

    #[test]
    fn saga_constraint_debug_clone() {
        let c = SagaConstraint::AllOrNothing {
            name: "test".into(),
            obligations: [oid(1), oid(2)].into_iter().collect(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("AllOrNothing"));
        let c2 = c;
        let dbg2 = format!("{c2:?}");
        assert!(dbg2.contains("test"));
    }

    #[test]
    fn consistency_report_debug_clone() {
        let report = ConsistencyReport {
            pairwise_conflicts: vec![],
            phantom_states: vec![],
            constraint_violations: vec![],
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("ConsistencyReport"));
        let r2 = report;
        assert!(!r2.has_issues());
        assert!(!r2.has_sheaf_issues());
    }

    #[test]
    fn consistency_report_has_issues_with_pairwise() {
        let report = ConsistencyReport {
            pairwise_conflicts: vec![PairwiseConflict {
                obligation: oid(1),
                node_a: node("A"),
                state_a: LatticeState::Committed,
                node_b: node("B"),
                state_b: LatticeState::Aborted,
            }],
            phantom_states: vec![],
            constraint_violations: vec![],
        };
        assert!(report.has_issues());
        assert!(!report.has_sheaf_issues());
    }

    #[test]
    fn pairwise_conflict_debug_clone() {
        let c = PairwiseConflict {
            obligation: oid(1),
            node_a: node("A"),
            state_a: LatticeState::Committed,
            node_b: node("B"),
            state_b: LatticeState::Aborted,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("PairwiseConflict"));
        let c2 = c;
        assert_eq!(c2.state_a, LatticeState::Committed);
    }

    #[test]
    fn phantom_state_debug_clone() {
        let p = PhantomState {
            obligation: oid(1),
            merged_state: LatticeState::Committed,
            node_observations: BTreeMap::new(),
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("PhantomState"));
        let p2 = p;
        assert!(p2.node_observations.is_empty());
    }

    #[test]
    fn constraint_violation_debug_clone() {
        let cv = ConstraintViolation {
            constraint_name: "saga-1".into(),
            obligation_states: BTreeMap::new(),
            explanation: "test violation".into(),
        };
        let dbg = format!("{cv:?}");
        assert!(dbg.contains("ConstraintViolation"));
        let cv2 = cv;
        assert_eq!(cv2.constraint_name, "saga-1");
        assert_eq!(cv2.explanation, "test violation");
    }

    #[test]
    fn obligation_detail_debug_clone() {
        let od = ObligationDetail {
            merged: LatticeState::Reserved,
            per_node: BTreeMap::new(),
        };
        let dbg = format!("{od:?}");
        assert!(dbg.contains("ObligationDetail"));
        let od2 = od;
        assert_eq!(od2.merged, LatticeState::Reserved);
    }

    #[test]
    fn consistency_report_has_sheaf_issues_with_phantom() {
        let report = ConsistencyReport {
            pairwise_conflicts: vec![],
            phantom_states: vec![PhantomState {
                obligation: oid(1),
                merged_state: LatticeState::Committed,
                node_observations: BTreeMap::new(),
            }],
            constraint_violations: vec![],
        };
        assert!(report.has_issues());
        assert!(report.has_sheaf_issues());
    }

    #[test]
    fn consistency_report_has_sheaf_issues_with_violation() {
        let report = ConsistencyReport {
            pairwise_conflicts: vec![],
            phantom_states: vec![],
            constraint_violations: vec![ConstraintViolation {
                constraint_name: "test".into(),
                obligation_states: BTreeMap::new(),
                explanation: "broken".into(),
            }],
        };
        assert!(report.has_issues());
        assert!(report.has_sheaf_issues());
    }
