    use super::*;

    fn ev(id: u64) -> FaultEventId {
        FaultEventId::new(id)
    }

    fn set(ids: &[u64]) -> BTreeSet<FaultEventId> {
        ids.iter().copied().map(FaultEventId::new).collect()
    }

    #[test]
    fn single_shared_event_is_a_depth_one_hypothesis() {
        // AC1: one event supports every derivation -> dropping it breaks the
        // outcome; LDFI finds it at depth 1.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2)]);
        g.add_derivation([ev(1), ev(3)]);
        g.add_derivation([ev(1), ev(4)]);
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.hypotheses.contains(&set(&[1])));
        // The single-event hypothesis is minimal, so no larger superset of {1}
        // is reported.
        assert!(
            result
                .hypotheses
                .iter()
                .all(|h| !h.is_superset(&set(&[1])) || *h == set(&[1]))
        );
        assert!(result.exhausted);
        assert!(result.coverage_certificate().is_none());
    }

    #[test]
    fn disjoint_derivations_require_a_depth_two_hypothesis() {
        // No single event hits both derivations; the minimal hypothesis has size 2.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2)]);
        g.add_derivation([ev(3), ev(4)]);
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.hypotheses.iter().all(|h| h.len() == 2));
        // Every hypothesis must hit both derivations.
        for h in &result.hypotheses {
            assert!(!h.is_disjoint(&set(&[1, 2])));
            assert!(!h.is_disjoint(&set(&[3, 4])));
        }
        assert!(result.exhausted);
    }

    #[test]
    fn unbreakable_outcome_yields_coverage_certificate() {
        // AC2: a derivation with no fault-able events cannot be hit.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1)]);
        g.add_derivation(std::iter::empty());
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.is_empty());
        assert!(result.unbreakable);
        assert_eq!(result.coverage_certificate(), Some(3));
    }

    #[test]
    fn depth_budget_limits_hypothesis_size() {
        // Three pairwise-disjoint derivations need a size-3 hitting set; a
        // depth-2 budget cannot cover them, so no hypothesis and not exhausted.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2)]);
        g.add_derivation([ev(3), ev(4)]);
        g.add_derivation([ev(5), ev(6)]);
        let result = g.minimal_hitting_sets(HittingSetBudget {
            max_depth: 2,
            max_hypotheses: 64,
        });
        assert!(result.is_empty());
        assert!(!result.exhausted);
        // Not exhausted => no coverage certificate.
        assert!(result.coverage_certificate().is_none());
    }

    #[test]
    fn determinism() {
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2), ev(3)]);
        g.add_derivation([ev(2), ev(4)]);
        let a = g.minimal_hitting_sets(HittingSetBudget::default());
        let b = g.minimal_hitting_sets(HittingSetBudget::default());
        assert_eq!(a, b);
    }

    #[test]
    fn empty_support_graph_is_trivially_exhausted() {
        let g = SupportGraph::new();
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.is_empty());
        assert!(result.exhausted);
        assert!(!result.unbreakable);
    }

    #[test]
    fn causal_cone_collects_transitive_faultable_ancestry_only() {
        // 1 -> 2 -> 3 (-> 4, non-fault-able outcome). The support of 4 is the
        // fault-able cone {1,2,3}; the non-fault-able 4 propagates causality but
        // never appears in a derivation.
        let mut lineage = CausalLineage::new();
        for id in [1, 2, 3] {
            lineage.mark_faultable(ev(id));
        }
        lineage.add_happens_before(ev(1), ev(2));
        lineage.add_happens_before(ev(2), ev(3));
        lineage.add_happens_before(ev(3), ev(4)); // 4 left non-fault-able

        assert_eq!(lineage.causal_cone(ev(4)), set(&[1, 2, 3, 4]));
        assert_eq!(lineage.support_of(ev(4)), set(&[1, 2, 3]));
        assert!(!lineage.is_faultable(ev(4)));
    }

    #[test]
    fn shared_root_cone_yields_depth_one_hypothesis_end_to_end() {
        // Two independent ack paths both rooted at the single send: dropping the
        // send breaks both, so the lineage->hitting-set pipeline returns {send}.
        let mut lineage = CausalLineage::new();
        for id in [1, 2, 3] {
            lineage.mark_faultable(ev(id));
        }
        lineage.add_happens_before(ev(1), ev(2));
        lineage.add_happens_before(ev(1), ev(3));
        lineage.add_happens_before(ev(2), ev(10));
        lineage.add_happens_before(ev(3), ev(11));

        let graph = SupportGraph::from_causal_cones(&lineage, [ev(10), ev(11)]);
        assert_eq!(graph.derivations().len(), 2);
        let result = graph.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.hypotheses.contains(&set(&[1])));
        assert!(result.coverage_certificate().is_none());
    }

    #[test]
    fn outcome_with_no_faultable_support_is_unbreakable() {
        // The outcome is produced with no fault-able ancestry: its derivation is
        // empty, so it cannot be hit -> coverage certificate.
        let mut lineage = CausalLineage::new();
        lineage.add_event(ev(7), false); // a non-fault-able local outcome
        let graph = SupportGraph::from_causal_cone(&lineage, ev(7));
        let result = graph.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.unbreakable);
        assert_eq!(result.coverage_certificate(), Some(3));
    }

    #[test]
    fn add_event_can_demote_a_previously_faultable_event() {
        let mut lineage = CausalLineage::new();
        lineage.mark_faultable(ev(1));
        assert!(lineage.is_faultable(ev(1)));
        lineage.add_event(ev(1), false);
        assert!(!lineage.is_faultable(ev(1)));
        assert!(lineage.support_of(ev(1)).is_empty());
    }
