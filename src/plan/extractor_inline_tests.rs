    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::time::Duration;

    fn init_test() {
        init_test_logging();
    }

    #[test]
    fn extract_single_leaf() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(a)
            .expect("leaf extraction should succeed");

        assert_eq!(dag.nodes.len(), 1);
        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.allocations, 1);
        assert_eq!(cert.cost.critical_path, 1);
    }

    #[test]
    fn extract_join_of_leaves() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let join = eg.add_join(vec![a, b]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(join)
            .expect("join extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        // 2 leaves + 1 join = 3 allocations
        assert_eq!(cert.cost.allocations, 3);
        // Critical path is max of children = 1
        assert_eq!(cert.cost.critical_path, 1);
    }

    #[test]
    fn extract_race_adds_cancel_checkpoint() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let race = eg.add_race(vec![a, b]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(race)
            .expect("race extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.cancel_checkpoints, 1);
    }

    #[test]
    fn extract_obligation_pressure() {
        init_test();
        let mut eg = EGraph::new();
        let obl = eg.add_leaf("obl:permit");
        let plain = eg.add_leaf("compute");
        let join = eg.add_join(vec![obl, plain]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(join)
            .expect("obligation extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.obligation_pressure, 1);
    }

    #[test]
    fn extract_nested_critical_path() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let t1 = eg.add_timeout(a, Duration::from_secs(5));
        let t2 = eg.add_timeout(t1, Duration::from_secs(10));

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(t2)
            .expect("timeout extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        // Leaf (1) + timeout (1) + timeout (1) = 3
        assert_eq!(cert.cost.critical_path, 3);
    }

    #[test]
    fn extraction_is_deterministic() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let c = eg.add_leaf("c");
        let j1 = eg.add_join(vec![a, b]);
        let r = eg.add_race(vec![j1, c]);

        let mut extractor1 = Extractor::new(&mut eg);
        let (dag1, cert1) = extractor1
            .extract(r)
            .expect("first extraction should succeed");

        // Extract again (new extractor, same egraph)
        let mut extractor2 = Extractor::new(&mut eg);
        let (dag2, cert2) = extractor2
            .extract(r)
            .expect("second extraction should succeed");

        assert_eq!(cert1.plan_hash, cert2.plan_hash);
        assert_eq!(cert1.cost, cert2.cost);
        assert_eq!(dag1.nodes.len(), dag2.nodes.len());
    }

    #[test]
    fn extract_after_merge_picks_best() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let c = eg.add_leaf("c");

        // Two different representations of the same thing
        let j1 = eg.add_join(vec![a, b, c]);
        let inner_join = eg.add_join(vec![a, b]);
        let j2 = eg.add_join(vec![inner_join, c]);

        // Merge them into the same class
        eg.merge(j1, j2);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(j1)
            .expect("merged extraction should succeed");

        // Should pick the flatter representation (lower cost)
        assert!(cert.verify(&dag).is_ok());
        // The flat join is cheaper (fewer allocations)
        assert_eq!(cert.cost.allocations, 4); // 3 leaves + 1 join
    }

    #[test]
    fn extract_total_tie_prefers_better_full_cost_vector() {
        init_test();
        let mut eg = EGraph::new();

        let seed = eg.add_leaf("seed");
        let worse = eg.add_race(vec![seed]);

        let better_children: Vec<_> = (0..101)
            .map(|idx| eg.add_leaf(format!("join-{idx}")))
            .collect();
        let better = eg.add_join(better_children);

        eg.merge(worse, better);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(worse)
            .expect("tie-broken extraction should succeed");

        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.total(), 1102);
        assert_eq!(cert.cost.cancel_checkpoints, 0);
        assert_eq!(cert.cost.critical_path, 1);
        assert_eq!(cert.cost.allocations, 102);

        let root = dag.root().expect("root");
        assert!(matches!(
            dag.node(root),
            Some(PlanNode::Join { children }) if children.len() == 101
        ));
    }

    #[test]
    fn extract_merge_with_cyclic_enode_prefers_acyclic_candidate() {
        init_test();
        let mut eg = EGraph::new();
        let leaf = eg.add_leaf("a");
        let recursive_join = eg.add_join(vec![leaf]);

        // Rebuild canonicalizes the join into Join([leaf]), so this merge creates
        // a class containing both an acyclic leaf and a self-referential join.
        eg.merge(leaf, recursive_join);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(leaf)
            .expect("cyclic merge extraction should succeed");

        assert!(cert.verify(&dag).is_ok());
        assert_eq!(dag.nodes.len(), 1);
        assert_eq!(cert.cost, PlanCost::LEAF);

        let root = dag.root().expect("root");
        assert!(matches!(
            dag.node(root),
            Some(PlanNode::Leaf { label }) if label == "a"
        ));
    }

    #[test]
    fn extract_merge_with_empty_join_prefers_valid_candidate() {
        init_test();
        let mut eg = EGraph::new();
        let leaf = eg.add_leaf("a");
        let empty_join = eg.add_join(Vec::new());

        eg.merge(leaf, empty_join);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(leaf)
            .expect("empty-join merge extraction should succeed");

        assert!(cert.verify(&dag).is_ok());
        assert_eq!(dag.nodes.len(), 1);
        assert_eq!(cert.cost, PlanCost::LEAF);

        let root = dag.root().expect("root");
        assert!(matches!(
            dag.node(root),
            Some(PlanNode::Leaf { label }) if label == "a"
        ));
    }

    #[test]
    fn cost_total_ordering() {
        init_test();
        let low = PlanCost {
            allocations: 10,
            cancel_checkpoints: 0,
            obligation_pressure: 0,
            critical_path: 1,
        };
        let high = PlanCost {
            allocations: 1,
            cancel_checkpoints: 0,
            obligation_pressure: 0,
            critical_path: 10,
        };

        // Critical path dominates
        assert!(low.total() < high.total());
    }

    #[test]
    fn extract_root_with_only_empty_join_returns_error() {
        init_test();
        let mut eg = EGraph::new();
        let empty_join = eg.add_join(Vec::new());

        let result = Extractor::new(&mut eg).extract(empty_join);
        assert!(matches!(
            result,
            Err(ExtractionError::NoExtractableCandidate { class }) if class == empty_join
        ));
    }

    #[test]
    fn cost_display() {
        init_test();
        let cost = PlanCost {
            allocations: 5,
            cancel_checkpoints: 2,
            obligation_pressure: 1,
            critical_path: 3,
        };
        let display = format!("{cost}");
        assert!(display.contains("alloc=5"));
        assert!(display.contains("cancel=2"));
        assert!(display.contains("obl=1"));
        assert!(display.contains("depth=3"));
    }

    #[test]
    fn cost_ordering_breaks_weighted_total_ties_by_full_vector() {
        init_test();
        let shallower_without_cancel = PlanCost {
            allocations: 102,
            cancel_checkpoints: 0,
            obligation_pressure: 0,
            critical_path: 1,
        };
        let racier_with_fewer_allocations = PlanCost {
            allocations: 2,
            cancel_checkpoints: 1,
            obligation_pressure: 0,
            critical_path: 1,
        };

        assert_eq!(
            shallower_without_cancel.total(),
            racier_with_fewer_allocations.total()
        );
        assert_ne!(shallower_without_cancel, racier_with_fewer_allocations);
        assert_ne!(
            shallower_without_cancel.cmp(&racier_with_fewer_allocations),
            std::cmp::Ordering::Equal
        );
        assert!(shallower_without_cancel < racier_with_fewer_allocations);
    }

    #[test]
    fn certificate_version_mismatch() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (dag, mut cert) = extractor
            .extract(a)
            .expect("certificate source extraction should succeed");

        cert.version = CertificateVersion::from_number(99);
        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn certificate_hash_mismatch() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (mut dag, cert) = extractor
            .extract(a)
            .expect("hash-mismatch source extraction should succeed");

        // Mutate the DAG
        dag.leaf("extra");

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn certificate_cost_mismatch_is_rejected() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let join = eg.add_join(vec![a, b]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, mut cert) = extractor
            .extract(join)
            .expect("cost-mismatch source extraction should succeed");

        cert.cost.allocations = cert.cost.allocations.saturating_add(1);

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::CostMismatch { .. })
        ));
    }

    #[test]
    fn certificate_rejects_structurally_invalid_dag() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (mut dag, mut cert) = extractor
            .extract(a)
            .expect("invalid-dag source extraction should succeed");

        let root = dag.root().expect("root");
        dag.nodes[root.index()] = PlanNode::Join {
            children: Vec::new(),
        };
        cert.plan_hash = PlanHash::of(&dag);
        cert.node_count = dag.nodes.len();
        cert.cost = dag_plan_cost(&dag);

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::InvalidPlan(
                crate::plan::PlanError::EmptyChildren { parent }
            ))
                if parent == root
        ));
    }

    // Pure data-type tests (wave 37 – CyanBarn)

    #[test]
    fn plan_cost_debug_copy_default() {
        let cost = PlanCost::default();
        assert_eq!(cost.allocations, 0);
        assert_eq!(cost.cancel_checkpoints, 0);
        assert_eq!(cost.obligation_pressure, 0);
        assert_eq!(cost.critical_path, 0);

        let dbg = format!("{cost:?}");
        assert!(dbg.contains("PlanCost"));

        // Copy
        let cost2 = cost;
        assert_eq!(cost, cost2);

        // Clone
        let cost3 = cost;
        assert_eq!(cost, cost3);
    }

    #[test]
    fn plan_cost_constants() {
        assert_eq!(PlanCost::ZERO.total(), 0);
        assert_eq!(PlanCost::ZERO.allocations, 0);

        assert_eq!(PlanCost::LEAF.allocations, 1);
        assert_eq!(PlanCost::LEAF.critical_path, 1);
        assert_eq!(PlanCost::LEAF.cancel_checkpoints, 0);

        // UNKNOWN is sentinel
        assert_eq!(PlanCost::UNKNOWN.allocations, u64::MAX);
        assert_eq!(PlanCost::UNKNOWN.critical_path, u64::MAX);
    }

    #[test]
    fn plan_cost_add_sequential() {
        let a = PlanCost {
            allocations: 2,
            cancel_checkpoints: 1,
            obligation_pressure: 0,
            critical_path: 3,
        };
        let b = PlanCost {
            allocations: 3,
            cancel_checkpoints: 0,
            obligation_pressure: 1,
            critical_path: 5,
        };

        // add: critical_path = max
        let sum = a.add(b);
        assert_eq!(sum.allocations, 5);
        assert_eq!(sum.cancel_checkpoints, 1);
        assert_eq!(sum.obligation_pressure, 1);
        assert_eq!(sum.critical_path, 5); // max(3,5)

        // sequential: critical_path = sum
        let seq = a.sequential(b);
        assert_eq!(seq.allocations, 5);
        assert_eq!(seq.critical_path, 8); // 3+5
    }

    #[test]
    fn extraction_certificate_debug_clone() {
        let mut eg = EGraph::new();
        let a = eg.add_leaf("x");
        let mut ext = Extractor::new(&mut eg);
        let (_dag, cert) = ext
            .extract(a)
            .expect("certificate extraction should succeed");

        let dbg = format!("{cert:?}");
        assert!(dbg.contains("ExtractionCertificate"));

        let cloned = cert.clone();
        assert_eq!(cloned.node_count, cert.node_count);
        assert_eq!(cloned.cost, cert.cost);
    }

    #[test]
    fn extraction_verify_error_debug_clone_eq() {
        let e1 = ExtractionVerifyError::VersionMismatch {
            expected: 1,
            found: 2,
        };
        let e2 = ExtractionVerifyError::HashMismatch {
            expected: "10".to_string(),
            actual: "20".to_string(),
        };
        let e3 = ExtractionVerifyError::NodeCountMismatch {
            expected: 5,
            actual: 3,
        };
        let e4 = ExtractionVerifyError::CostMismatch {
            expected: PlanCost::ZERO,
            actual: PlanCost::LEAF,
        };
        let e5 = ExtractionVerifyError::InvalidPlan(crate::plan::PlanError::Cycle {
            at: PlanId::new(0),
        });

        let dbg1 = format!("{e1:?}");
        assert!(dbg1.contains("VersionMismatch"));
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("HashMismatch"));
        let dbg3 = format!("{e3:?}");
        assert!(dbg3.contains("NodeCountMismatch"));
        let dbg4 = format!("{e4:?}");
        assert!(dbg4.contains("CostMismatch"));
        let dbg5 = format!("{e5:?}");
        assert!(dbg5.contains("InvalidPlan"));

        // Clone + PartialEq
        let e1c = e1.clone();
        assert_eq!(e1, e1c);
        assert_ne!(e1, e2);
    }
