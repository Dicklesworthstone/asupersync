    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::time::Duration;

    fn leaf_dag(label: &str) -> (PlanDag, PlanId) {
        let mut dag = PlanDag::new();
        let id = dag.leaf(label);
        dag.set_root(id);
        (dag, id)
    }

    // ---- Leaf analysis ----

    #[test]
    fn leaf_is_fully_safe() {
        let (dag, root) = leaf_dag("a");
        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(root).expect("root analyzed");
        assert!(node.is_safe());
        assert_eq!(node.obligation, ObligationSafety::Clean);
        assert_eq!(node.cancel, CancelSafety::Safe);
        assert_eq!(node.budget.min_polls, 1);
        assert_eq!(node.budget.max_polls, Some(1));
    }

    #[test]
    fn leaf_cost_is_minimal() {
        let (dag, root) = leaf_dag("a");
        let analysis = PlanAnalyzer::analyze(&dag);
        let cost = analysis.get(root).expect("root analyzed").cost;
        assert_eq!(cost.allocations, 1_u64);
        assert_eq!(cost.cancel_checkpoints, 1_u64);
        assert_eq!(cost.obligation_pressure, 0_u64);
        assert_eq!(cost.critical_path, 1_u64);
    }

    #[test]
    fn leaf_obligation_increases_pressure() {
        let (dag, root) = leaf_dag("obl:permit");
        let analysis = PlanAnalyzer::analyze(&dag);
        let cost = analysis.get(root).expect("root analyzed").cost;
        assert_eq!(cost.obligation_pressure, 1_u64);
    }

    // ---- Join analysis ----

    #[test]
    fn join_of_leaves_is_safe() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(join).expect("join analyzed");
        assert!(node.is_safe());
        assert_eq!(node.budget.min_polls, 2);
        assert_eq!(node.budget.max_polls, Some(2));
        assert_eq!(node.budget.parallelism, 2);
    }

    #[test]
    fn join_cost_uses_max_critical_path() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let cost = analysis.get(join).expect("join analyzed").cost;
        assert_eq!(cost.allocations, 3_u64);
        assert_eq!(cost.cancel_checkpoints, 2_u64);
        assert_eq!(cost.critical_path, 2_u64);
    }

    // ---- Race analysis ----

    #[test]
    fn race_of_leaves_is_safe() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(race).expect("race analyzed");
        assert!(node.is_safe());
        assert_eq!(node.budget.min_polls, 1);
        assert_eq!(node.budget.max_polls, Some(1));
    }

    #[test]
    fn race_of_timeout_leaves_is_safe() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let timed_a = dag.timeout(a, Duration::from_secs(2));
        let timed_b = dag.timeout(b, Duration::from_secs(4));
        let race = dag.race(vec![timed_a, timed_b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(race).expect("race analyzed");
        assert!(node.is_safe());
        assert_eq!(node.cancel, CancelSafety::Safe);
    }

    #[test]
    fn race_cost_uses_min_critical_path() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let cost = analysis.get(race).expect("race analyzed").cost;
        assert_eq!(cost.allocations, 3_u64);
        assert_eq!(cost.cancel_checkpoints, 1_u64);
        assert_eq!(cost.critical_path, 2_u64);
    }

    // ---- Timeout analysis ----

    #[test]
    fn timeout_adds_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_secs(5));
        dag.set_root(t);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(t).expect("timeout analyzed");
        assert!(node.is_safe());
        assert!(node.budget.has_deadline);
    }

    #[test]
    fn timeout_cost_adds_node_overhead() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_secs(1));
        dag.set_root(t);

        let analysis = PlanAnalyzer::analyze(&dag);
        let cost = analysis.get(t).expect("timeout analyzed").cost;
        assert_eq!(cost.allocations, 2_u64);
        assert_eq!(cost.cancel_checkpoints, 1_u64);
        assert_eq!(cost.critical_path, 2_u64);
    }

    // ---- Composite: Race[Join[s,a], Join[s,b]] (the DedupRaceJoin pattern) ----

    #[test]
    fn dedup_race_join_pattern_is_safe() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s, b]);
        let race = dag.race(vec![j1, j2]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        assert!(analysis.all_safe());

        // Golden artifact: freeze analysis summary output
        insta::assert_snapshot!(analysis.summary());
    }

    // ---- Rewritten form: Join[s, Race[a, b]] ----

    #[test]
    fn rewritten_form_is_safe() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let race = dag.race(vec![a, b]);
        let join = dag.join(vec![s, race]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        assert!(analysis.all_safe());
    }

    // ---- Empty DAG ----

    #[test]
    fn empty_dag_analysis() {
        let dag = PlanDag::new();
        let analysis = PlanAnalyzer::analyze(&dag);
        assert!(analysis.all_safe());
        assert!(analysis.nodes.is_empty());
    }

    // ---- Side condition checker ----

    #[test]
    fn side_condition_independence() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.are_independent(a, b));
    }

    #[test]
    fn obligations_safe_rejects_leak_on_cancel() {
        let mut dag = PlanDag::new();
        let obl = dag.leaf("obl:permit");
        dag.set_root(obl);

        let checker = SideConditionChecker::new(&dag);
        assert!(!checker.obligations_safe(obl));
    }

    #[test]
    fn shared_child_not_independent() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s]);
        let race = dag.race(vec![j1, j2]);
        dag.set_root(race);

        let checker = SideConditionChecker::new(&dag);
        // j1 and j2 share s
        assert!(!checker.are_independent(j1, j2));
    }

    // ---- Rewrite preservation ----

    #[test]
    fn rewrite_preserves_safety_for_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join_node = dag.join(vec![a, b]);
        dag.set_root(join_node);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.rewrite_preserves_obligations(a, b));
        assert!(checker.rewrite_preserves_cancel(a, b));
    }

    #[test]
    fn budget_monotonicity_rejects_unbounded_after() {
        let before = BudgetEffect {
            min_polls: 2,
            max_polls: Some(10),
            has_deadline: true,
            parallelism: 2,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        let after = BudgetEffect {
            min_polls: 1,
            max_polls: None,
            has_deadline: true,
            parallelism: 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        assert!(!after.is_not_worse_than(before));
    }

    #[test]
    fn budget_monotonicity_accepts_tighter_deadline() {
        let before = BudgetEffect {
            min_polls: 5,
            max_polls: Some(10),
            has_deadline: false,
            parallelism: 2,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        let after = BudgetEffect {
            min_polls: 4,
            max_polls: Some(8),
            has_deadline: true,
            parallelism: 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        assert!(after.is_not_worse_than(before));
    }

    #[test]
    fn budget_monotonicity_rejects_increased_parallelism() {
        let before = BudgetEffect {
            min_polls: 4,
            max_polls: Some(8),
            has_deadline: false,
            parallelism: 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        let after = BudgetEffect {
            min_polls: 4,
            max_polls: Some(8),
            has_deadline: false,
            parallelism: 2,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        assert!(!after.is_not_worse_than(before));
    }

    #[test]
    fn budget_monotonicity_rejects_looser_max_deadline() {
        let before = BudgetEffect {
            min_polls: 4,
            max_polls: Some(8),
            has_deadline: true,
            parallelism: 1,
            min_deadline: DeadlineMicros::from_micros(1_000),
            max_deadline: DeadlineMicros::from_micros(2_000),
        };
        let after = BudgetEffect {
            min_polls: 4,
            max_polls: Some(8),
            has_deadline: true,
            parallelism: 1,
            min_deadline: DeadlineMicros::from_micros(1_000),
            max_deadline: DeadlineMicros::from_micros(3_000),
        };
        assert!(!after.is_not_worse_than(before));
    }

    // ---- Summary ----

    #[test]
    fn analysis_summary_format() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let summary = analysis.summary();
        assert!(summary.contains("3/3 safe"));
    }

    #[test]
    fn obligation_leaf_summary_uses_flow_derived_safety() {
        let mut dag = PlanDag::new();
        let obligation = dag.leaf("obl:permit");
        dag.set_root(obligation);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(obligation).expect("leaf analyzed");
        assert_eq!(node.obligation, ObligationSafety::Clean);
        assert_eq!(node.effective_obligation(), ObligationSafety::MayLeak);
        assert!(!node.is_safe());
        assert_eq!(analysis.obligation_issues().len(), 1);
        assert!(!analysis.all_safe());

        let summary = analysis.summary();
        assert!(summary.contains("0/1 safe"));
        assert!(summary.contains("1 obligation issue"));
    }

    // ---- Display impls ----

    #[test]
    fn display_impls() {
        let mut output = String::new();
        output.push_str("--- ObligationSafety ---\n");
        output.push_str(&format!("Clean: {}\n", ObligationSafety::Clean));
        output.push_str(&format!("MayLeak: {}\n", ObligationSafety::MayLeak));
        output.push_str(&format!("Leaked: {}\n", ObligationSafety::Leaked));
        output.push_str(&format!("Unknown: {}\n", ObligationSafety::Unknown));

        output.push_str("\n--- CancelSafety ---\n");
        output.push_str(&format!("Safe: {}\n", CancelSafety::Safe));
        output.push_str(&format!("MayOrphan: {}\n", CancelSafety::MayOrphan));
        output.push_str(&format!("Orphan: {}\n", CancelSafety::Orphan));
        output.push_str(&format!("Unknown: {}\n", CancelSafety::Unknown));

        output.push_str("\n--- BudgetEffect ---\n");
        output.push_str(&format!("LEAF: {}\n", BudgetEffect::LEAF));
        output.push_str(&format!(
            "Bounded: {}\n",
            BudgetEffect {
                min_polls: 2,
                max_polls: Some(5),
                has_deadline: true,
                min_deadline: DeadlineMicros(None),
                max_deadline: DeadlineMicros(None),
                parallelism: 1
            }
        ));
        output.push_str(&format!(
            "Unbounded: {}\n",
            BudgetEffect {
                min_polls: 1,
                max_polls: None,
                has_deadline: false,
                min_deadline: DeadlineMicros(None),
                max_deadline: DeadlineMicros(None),
                parallelism: 1
            }
        ));

        output.push_str("\n--- ObligationFlow ---\n");
        output.push_str(&format!("Empty: {}\n", ObligationFlow::empty()));
        let mut flow_complex = ObligationFlow::empty();
        flow_complex.reserves.push("SendPermit".to_string());
        flow_complex.must_resolve.push("SendPermit".to_string());
        flow_complex.leak_on_cancel.push("Lease".to_string());
        flow_complex.all_paths_resolve = false;
        output.push_str(&format!("Complex: {}\n", flow_complex));

        output.push_str("\n--- IndependenceResult ---\n");
        output.push_str(&format!(
            "Independent: {}\n",
            IndependenceResult::Independent
        ));
        output.push_str(&format!("Dependent: {}\n", IndependenceResult::Dependent));
        output.push_str(&format!("Uncertain: {}\n", IndependenceResult::Uncertain));

        output.push_str("\n--- TraceEquivalenceHint ---\n");
        output.push_str(&format!("Atomic: {}\n", TraceEquivalenceHint::Atomic));
        output.push_str(&format!(
            "FullyCommutative: {}\n",
            TraceEquivalenceHint::FullyCommutative
        ));
        output.push_str(&format!(
            "PartiallyCommutative: {}\n",
            TraceEquivalenceHint::PartiallyCommutative {
                groups: vec![vec![0, 1], vec![2, 3]]
            }
        ));
        output.push_str(&format!(
            "Sequential: {}\n",
            TraceEquivalenceHint::Sequential
        ));
        output.push_str(&format!("Unknown: {}\n", TraceEquivalenceHint::Unknown));

        insta::assert_snapshot!("analysis_display_outputs", output);
    }

    // ---- Deterministic ordering ----

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn analysis_is_deterministic() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let j = dag.join(vec![a, b]);
        let r = dag.race(vec![j, c]);
        dag.set_root(r);

        let a1 = PlanAnalyzer::analyze(&dag);
        let a2 = PlanAnalyzer::analyze(&dag);
        // Same keys in same order.
        let keys1: Vec<usize> = a1.nodes.keys().copied().collect();
        let keys2: Vec<usize> = a2.nodes.keys().copied().collect();
        assert_eq!(keys1, keys2);
        // Same obligation safety.
        for (k, v1) in &a1.nodes {
            let v2 = a2.nodes.get(k).expect("key exists");
            assert_eq!(v1.obligation, v2.obligation);
            assert_eq!(v1.cancel, v2.cancel);
        }
    }

    // ---- ObligationFlow tests ----

    #[test]
    fn obligation_flow_empty_is_clean() {
        let flow = ObligationFlow::empty();
        assert!(flow.reserves.is_empty());
        assert!(flow.must_resolve.is_empty());
        assert!(flow.leak_on_cancel.is_empty());
        assert!(flow.all_paths_resolve);
        assert!(flow.diagnostics().is_empty());
    }

    #[test]
    fn obligation_flow_leaf_with_obligation_tracks_it() {
        let flow = ObligationFlow::leaf_with_obligation("obl:permit".to_string());
        assert_eq!(flow.reserves, vec!["obl:permit"]);
        assert_eq!(flow.must_resolve, vec!["obl:permit"]);
        assert_eq!(flow.leak_on_cancel, vec!["obl:permit"]);
        assert!(flow.all_paths_resolve);
    }

    #[test]
    fn obligation_flow_join_combines_children() {
        let f1 = ObligationFlow::leaf_with_obligation("obl:a".to_string());
        let f2 = ObligationFlow::leaf_with_obligation("obl:b".to_string());
        let joined = f1.join(f2);
        assert_eq!(joined.reserves.len(), 2);
        assert!(joined.reserves.contains(&"obl:a".to_string()));
        assert!(joined.reserves.contains(&"obl:b".to_string()));
    }

    #[test]
    fn obligation_flow_race_adds_leak_risk() {
        let f1 = ObligationFlow::leaf_with_obligation("obl:a".to_string());
        let f2 = ObligationFlow::leaf_with_obligation("obl:b".to_string());
        let raced = f1.race(f2);
        // Both are started, loser may leak.
        assert!(!raced.leak_on_cancel.is_empty());
        assert!(raced.leak_on_cancel.contains(&"obl:a".to_string()));
        assert!(raced.leak_on_cancel.contains(&"obl:b".to_string()));
    }

    #[test]
    fn analyzer_tracks_obligation_flow_for_annotated_leaves() {
        let mut dag = PlanDag::new();
        let obl = dag.leaf("obl:permit");
        let plain = dag.leaf("compute");
        let join = dag.join(vec![obl, plain]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let join_node = analysis.get(join).expect("join analyzed");
        // The join should track the obligation from the obl: leaf.
        assert!(
            join_node
                .obligation_flow
                .reserves
                .contains(&"obl:permit".to_string())
        );
    }

    #[test]
    fn analyzer_detects_race_obligation_leak_risk() {
        let mut dag = PlanDag::new();
        let obl_a = dag.leaf("obl:a");
        let obl_b = dag.leaf("obl:b");
        let race = dag.race(vec![obl_a, obl_b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let race_node = analysis.get(race).expect("race analyzed");
        // In a race, the loser's obligations may leak.
        assert!(!race_node.obligation_flow.leak_on_cancel.is_empty());
        assert_eq!(race_node.obligation, ObligationSafety::MayLeak);
        assert_eq!(race_node.cancel, CancelSafety::MayOrphan);
        assert!(!race_node.is_safe());
        assert!(!analysis.all_safe());
    }

    #[test]
    fn timeout_over_obligation_leaf_reports_cancel_leak_risk() {
        let mut dag = PlanDag::new();
        let obligation = dag.leaf("obl:lease");
        let timeout = dag.timeout(obligation, Duration::from_secs(1));
        dag.set_root(timeout);

        let analysis = PlanAnalyzer::analyze(&dag);
        let timeout_node = analysis.get(timeout).expect("timeout analyzed");
        assert!(
            timeout_node
                .obligation_flow
                .leak_on_cancel
                .contains(&"obl:lease".to_string())
        );
        assert_eq!(timeout_node.obligation, ObligationSafety::MayLeak);
        assert_eq!(timeout_node.cancel, CancelSafety::MayOrphan);
        assert!(!timeout_node.is_safe());
    }

    #[test]
    fn race_of_timeout_obligation_leaf_reports_cancel_leak_risk() {
        let mut dag = PlanDag::new();
        let fast = dag.leaf("fast");
        let obligation = dag.leaf("obl:lease");
        let timeout = dag.timeout(obligation, Duration::from_secs(1));
        let race = dag.race(vec![fast, timeout]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let race_node = analysis.get(race).expect("race analyzed");
        assert_eq!(race_node.cancel, CancelSafety::MayOrphan);
        assert!(!race_node.is_safe());
    }

    #[test]
    fn obligation_flow_display() {
        let flow = ObligationFlow {
            reserves: vec!["obl:x".to_string()],
            must_resolve: vec!["obl:x".to_string()],
            leak_on_cancel: vec![],
            all_paths_resolve: true,
        };
        let display = format!("{flow}");
        assert!(display.contains("reserves="));
        assert!(display.contains("[all-paths-ok]"));
    }

    #[test]
    fn obligation_flow_diagnostics_reports_issues() {
        let flow = ObligationFlow {
            reserves: vec!["obl:x".to_string()],
            must_resolve: vec!["obl:x".to_string()],
            leak_on_cancel: vec!["obl:x".to_string()],
            all_paths_resolve: false,
        };
        let diags = flow.diagnostics();
        assert!(!diags.is_empty());
        assert!(diags.iter().any(|d| d.contains("not all paths")));
        assert!(diags.iter().any(|d| d.contains("leak on cancel")));
    }

    // ---- DeadlineMicros tests ----

    #[test]
    fn deadline_micros_unbounded() {
        let unbounded = DeadlineMicros::UNBOUNDED;
        assert!(unbounded.is_unbounded());
        assert_eq!(unbounded.as_micros(), None);
    }

    #[test]
    fn deadline_micros_from_duration() {
        let deadline = DeadlineMicros::from_duration(Duration::from_millis(500));
        assert!(!deadline.is_unbounded());
        assert_eq!(deadline.as_micros(), Some(500_000));
    }

    #[test]
    fn deadline_micros_min_takes_tighter() {
        let d1 = DeadlineMicros::from_micros(1000);
        let d2 = DeadlineMicros::from_micros(500);
        let unbounded = DeadlineMicros::UNBOUNDED;

        assert_eq!(d1.min(d2), d2); // 500 < 1000
        assert_eq!(d2.min(d1), d2);
        assert_eq!(d1.min(unbounded), d1); // finite < unbounded
        assert_eq!(unbounded.min(d1), d1);
    }

    #[test]
    fn deadline_micros_add_sequential() {
        let d1 = DeadlineMicros::from_micros(1000);
        let d2 = DeadlineMicros::from_micros(500);
        let unbounded = DeadlineMicros::UNBOUNDED;

        assert_eq!(d1.add(d2), DeadlineMicros::from_micros(1500));
        assert_eq!(d1.add(unbounded), DeadlineMicros::UNBOUNDED);
        assert_eq!(unbounded.add(d1), DeadlineMicros::UNBOUNDED);
    }

    #[test]
    fn deadline_micros_is_at_least_as_tight() {
        let tight = DeadlineMicros::from_micros(100);
        let loose = DeadlineMicros::from_micros(1000);
        let unbounded = DeadlineMicros::UNBOUNDED;

        assert!(tight.is_at_least_as_tight_as(loose));
        assert!(!loose.is_at_least_as_tight_as(tight));
        assert!(tight.is_at_least_as_tight_as(unbounded));
        assert!(loose.is_at_least_as_tight_as(unbounded));
        assert!(!unbounded.is_at_least_as_tight_as(tight));
    }

    #[test]
    fn deadline_micros_display() {
        assert_eq!(format!("{}", DeadlineMicros::UNBOUNDED), "∞");
        assert_eq!(format!("{}", DeadlineMicros::from_micros(500)), "500µs");
        assert_eq!(format!("{}", DeadlineMicros::from_micros(5000)), "5ms");
        assert_eq!(format!("{}", DeadlineMicros::from_micros(5_000_000)), "5s");
    }

    // ---- Budget deadline tracking tests ----

    #[test]
    fn timeout_tracks_actual_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_millis(100));
        dag.set_root(t);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(t).expect("timeout analyzed");
        assert!(node.budget.has_deadline);
        assert_eq!(
            node.budget.min_deadline,
            DeadlineMicros::from_micros(100_000)
        );
    }

    #[test]
    fn nested_timeout_takes_tighter_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t1 = dag.timeout(a, Duration::from_millis(200)); // outer: looser
        let t2 = dag.timeout(t1, Duration::from_millis(100)); // inner: tighter
        dag.set_root(t2);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(t2).expect("timeout analyzed");
        // Tightest deadline should be 100ms
        assert_eq!(
            node.budget.min_deadline,
            DeadlineMicros::from_micros(100_000)
        );
    }

    #[test]
    fn join_propagates_deadline_from_child() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t = dag.timeout(a, Duration::from_millis(50));
        let join = dag.join(vec![t, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(join).expect("join analyzed");
        assert!(node.budget.has_deadline);
        assert_eq!(
            node.budget.min_deadline,
            DeadlineMicros::from_micros(50_000)
        );
    }

    #[test]
    fn race_propagates_tightest_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t1 = dag.timeout(a, Duration::from_millis(100));
        let t2 = dag.timeout(b, Duration::from_millis(50)); // tighter
        let race = dag.race(vec![t1, t2]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(race).expect("race analyzed");
        assert!(node.budget.has_deadline);
        assert_eq!(
            node.budget.min_deadline,
            DeadlineMicros::from_micros(50_000)
        );
    }

    // ---- Side condition deadline preservation tests ----

    #[test]
    fn rewrite_preserves_deadline_when_tighter() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t1 = dag.timeout(a, Duration::from_millis(100)); // original
        let t2 = dag.timeout(b, Duration::from_millis(50)); // tighter (different leaf)
        // Make both reachable via join at root
        let root = dag.join(vec![t1, t2]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.rewrite_preserves_deadline(t1, t2)); // tighter is ok
    }

    #[test]
    fn rewrite_fails_deadline_when_looser() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t1 = dag.timeout(a, Duration::from_millis(50)); // original: tight
        let t2 = dag.timeout(b, Duration::from_millis(100)); // looser (different leaf)
        // Make both reachable via join at root
        let root = dag.join(vec![t1, t2]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        assert!(!checker.rewrite_preserves_deadline(t1, t2)); // looser not ok
    }

    #[test]
    fn rewrite_allows_deadline_when_none_before() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_millis(100));
        dag.set_root(t);

        let checker = SideConditionChecker::new(&dag);
        // No deadline -> any deadline is ok
        assert!(checker.rewrite_preserves_deadline(a, t));
    }

    #[test]
    fn deadline_tolerance_check() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t1 = dag.timeout(a, Duration::from_millis(100));
        let t2 = dag.timeout(b, Duration::from_millis(110)); // 10ms looser (different leaf)
        // Make both reachable via join at root
        let root = dag.join(vec![t1, t2]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        // 10ms tolerance: 110ms - 100ms = 10ms, should pass
        assert!(checker.deadline_within_tolerance(t1, t2, 10_000));
        // 5ms tolerance: should fail (10ms > 5ms)
        assert!(!checker.deadline_within_tolerance(t1, t2, 5_000));
    }

    #[test]
    fn effective_deadline_returns_none_for_no_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.effective_deadline(a).is_none());
    }

    #[test]
    fn effective_deadline_returns_value_for_timeout() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_millis(75));
        dag.set_root(t);

        let checker = SideConditionChecker::new(&dag);
        let deadline = checker.effective_deadline(t);
        assert!(deadline.is_some());
        assert_eq!(deadline.unwrap().as_micros(), Some(75_000));
    }

    // ---- Budget effect composition tests ----

    #[test]
    fn budget_effect_sequential_adds_deadlines() {
        let e1 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(100));
        let e2 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(200));
        let combined = e1.sequential(e2);

        assert!(combined.has_deadline);
        // Sequential: max_deadline adds up
        assert_eq!(combined.max_deadline, DeadlineMicros::from_micros(300));
        // min_deadline takes tighter
        assert_eq!(combined.min_deadline, DeadlineMicros::from_micros(100));
    }

    #[test]
    fn budget_effect_parallel_takes_tighter_deadline() {
        let e1 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(100));
        let e2 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(200));
        let combined = e1.parallel(e2);

        assert!(combined.has_deadline);
        // Parallel: both take min (tightest)
        assert_eq!(combined.min_deadline, DeadlineMicros::from_micros(100));
        assert_eq!(combined.max_deadline, DeadlineMicros::from_micros(100));
    }

    #[test]
    fn obligation_safety_join_keeps_unknown_state() {
        assert_eq!(
            ObligationSafety::Unknown.join(ObligationSafety::Leaked),
            ObligationSafety::Unknown
        );
        assert_eq!(
            ObligationSafety::MayLeak.join(ObligationSafety::Unknown),
            ObligationSafety::Unknown
        );
    }

    #[test]
    fn cancel_safety_join_keeps_unknown_state() {
        assert_eq!(
            CancelSafety::Unknown.join(CancelSafety::Orphan),
            CancelSafety::Unknown
        );
        assert_eq!(
            CancelSafety::MayOrphan.join(CancelSafety::Unknown),
            CancelSafety::Unknown
        );
    }

    #[test]
    fn budget_effect_parallel_prefers_bounded_winner() {
        let bounded = BudgetEffect {
            min_polls: 2,
            max_polls: Some(5),
            has_deadline: false,
            parallelism: 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        let unbounded = BudgetEffect {
            min_polls: 1,
            max_polls: None,
            has_deadline: false,
            parallelism: 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };

        let combined = bounded.parallel(unbounded);
        assert_eq!(combined.max_polls, Some(5));
    }

    #[test]
    fn race_analysis_keeps_bounded_upper_bound_with_unknown_sibling() {
        let mut dag = PlanDag::new();
        let winner = dag.leaf("winner");
        let unknown = PlanId::new(999);
        let race = dag.race(vec![winner, unknown]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(race).expect("race analyzed");
        assert_eq!(node.budget.min_polls, 0);
        assert_eq!(node.budget.max_polls, Some(1));
    }

    #[test]
    fn budget_effect_display_shows_deadline_range() {
        let effect = BudgetEffect {
            min_polls: 2,
            max_polls: Some(5),
            has_deadline: true,
            parallelism: 1,
            min_deadline: DeadlineMicros::from_micros(100_000),
            max_deadline: DeadlineMicros::from_micros(500_000),
        };
        let display = format!("{effect}");
        assert!(display.contains("deadline="));
        assert!(display.contains("100ms"));
        assert!(display.contains("500ms"));
    }

    #[test]
    fn budget_effect_sequential_saturates_min_polls() {
        let big = BudgetEffect {
            min_polls: u32::MAX - 1,
            max_polls: Some(u32::MAX - 1),
            has_deadline: false,
            parallelism: 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        let combined = big.sequential(big);
        assert_eq!(combined.min_polls, u32::MAX);
        assert_eq!(combined.max_polls, Some(u32::MAX));
    }

    #[test]
    fn budget_effect_parallel_saturates_parallelism() {
        // Regression: Join inline composition used .sum::<u32>() for parallelism
        // which wraps on overflow.
        let big = BudgetEffect {
            min_polls: 1,
            max_polls: Some(1),
            has_deadline: false,
            parallelism: u32::MAX - 1,
            min_deadline: DeadlineMicros::UNBOUNDED,
            max_deadline: DeadlineMicros::UNBOUNDED,
        };
        // fold(0, saturating_add) with two near-MAX values must saturate.
        let sum = [big.parallelism, big.parallelism]
            .into_iter()
            .fold(0u32, u32::saturating_add);
        assert_eq!(sum, u32::MAX);
    }

    // ---- Independence / trace equivalence tests ----

    #[test]
    fn independence_result_join() {
        use IndependenceResult::*;
        assert_eq!(Independent.join(Independent), Independent);
        assert_eq!(Independent.join(Dependent), Dependent);
        assert_eq!(Dependent.join(Independent), Dependent);
        assert_eq!(Independent.join(Uncertain), Uncertain);
        assert_eq!(Uncertain.join(Uncertain), Uncertain);
    }

    #[test]
    fn independence_result_display() {
        assert_eq!(
            format!("{}", IndependenceResult::Independent),
            "independent"
        );
        assert_eq!(format!("{}", IndependenceResult::Dependent), "dependent");
        assert_eq!(format!("{}", IndependenceResult::Uncertain), "uncertain");
    }

    #[test]
    fn independent_leaves_are_independent() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.check_independence(a, b).is_independent());
        assert!(checker.commutes(a, b));
    }

    #[test]
    fn same_node_is_not_independent() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let checker = SideConditionChecker::new(&dag);
        assert!(!checker.check_independence(a, a).is_independent());
        assert!(!checker.commutes(a, a));
    }

    #[test]
    fn shared_child_nodes_are_dependent() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("shared");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s, b]);
        let root = dag.race(vec![j1, j2]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        // j1 and j2 share 's', so they are dependent
        assert!(!checker.check_independence(j1, j2).is_independent());
    }

    #[test]
    fn independence_relation_empty() {
        let relation = IndependenceRelation::empty();
        assert_eq!(relation.pair_count(), 0);
        assert!(!relation.are_independent(0, 1));
    }

    #[test]
    fn independence_relation_add_and_check() {
        let mut relation = IndependenceRelation::empty();
        relation.add(1, 2);
        relation.add(3, 4);

        assert!(relation.are_independent(1, 2));
        assert!(relation.are_independent(2, 1)); // symmetric
        assert!(relation.are_independent(3, 4));
        assert!(!relation.are_independent(1, 3));
        assert_eq!(relation.pair_count(), 2);
    }

    #[test]
    fn compute_independence_relation_for_join() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join = dag.join(vec![a, b, c]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        let relation = checker.compute_independence_relation();

        // All leaves should be pairwise independent
        assert!(relation.are_independent(a.index(), b.index()));
        assert!(relation.are_independent(b.index(), c.index()));
        assert!(relation.are_independent(a.index(), c.index()));
        assert_eq!(relation.pair_count(), 3);
    }

    #[test]
    fn trace_equivalence_hint_for_leaf() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let checker = SideConditionChecker::new(&dag);
        assert_eq!(
            checker.trace_equivalence_hint(a),
            TraceEquivalenceHint::Atomic
        );
    }

    #[test]
    fn trace_equivalence_hint_for_fully_commutative_join() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join = dag.join(vec![a, b, c]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        assert_eq!(
            checker.trace_equivalence_hint(join),
            TraceEquivalenceHint::FullyCommutative
        );
    }

    #[test]
    fn trace_equivalence_hint_for_sequential_join() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("shared");
        let j1 = dag.join(vec![s]);
        let j2 = dag.join(vec![s]);
        let root = dag.join(vec![j1, j2]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        // j1 and j2 share 's', so they are not independent
        let hint = checker.trace_equivalence_hint(root);
        // Should be sequential since children share state
        assert_eq!(hint, TraceEquivalenceHint::Sequential);
    }

    #[test]
    fn reorderable_join_children_all_independent() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join = dag.join(vec![a, b, c]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        let groups = checker.reorderable_join_children(&[a, b, c]);

        // All independent, so should be one group with all three
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn rewrite_valid_up_to_trace_for_join_reorder() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![a, b]);
        let j2 = dag.join(vec![b, a]); // reordered
        let root = dag.join(vec![j1, j2]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        // j1 and j2 contain the same leaves in different order
        assert!(checker.rewrite_valid_up_to_trace(j1, j2));
    }

    #[test]
    fn trace_equivalence_hint_display() {
        assert_eq!(format!("{}", TraceEquivalenceHint::Atomic), "atomic");
        assert_eq!(
            format!("{}", TraceEquivalenceHint::FullyCommutative),
            "fully-commutative"
        );
        assert_eq!(
            format!("{}", TraceEquivalenceHint::Sequential),
            "sequential"
        );
        assert_eq!(format!("{}", TraceEquivalenceHint::Unknown), "unknown");

        let hint = TraceEquivalenceHint::PartiallyCommutative {
            groups: vec![vec![0, 1], vec![2]],
        };
        assert!(format!("{hint}").contains("2 groups"));
    }

    // =========================================================================
    // bd-3a1g: Cancellation / obligation safety side-condition tests
    // =========================================================================

    #[test]
    fn loser_drain_preserved_for_simple_race_reorder() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let r1 = dag.race(vec![a, b]);
        let r2 = dag.race(vec![b, a]); // reordered children
        let root = dag.join(vec![r1, r2]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // Both races have the same cancel safety — reorder is fine.
        assert!(checker.rewrite_preserves_loser_drain(r1, r2));
    }

    #[test]
    fn loser_drain_rejects_new_obligation_leak() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("obl:x");
        let r1 = dag.race(vec![a]);
        let r2 = dag.race(vec![a, b]); // adds obligation-bearing child
        let root = dag.join(vec![r1, r2]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // r2 introduces leak_on_cancel that r1 doesn't have ⇒ reject
        assert!(!checker.rewrite_preserves_loser_drain(r1, r2));
    }

    #[test]
    fn loser_drain_rejects_relative_may_orphan_after() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let d = dag.leaf("d");
        let inner_before = dag.race(vec![a, b]);
        let inner_after = dag.race(vec![c, d]);
        let before = dag.race(vec![inner_before, c]);
        let after = dag.race(vec![a, inner_after]);
        let root = dag.join(vec![before, after]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        assert_eq!(
            checker
                .analysis
                .get(before)
                .expect("before analysis")
                .cancel,
            CancelSafety::MayOrphan
        );
        assert_eq!(
            checker.analysis.get(after).expect("after analysis").cancel,
            CancelSafety::MayOrphan
        );
        assert!(!checker.rewrite_preserves_loser_drain(before, after));
    }

    #[test]
    fn finalize_order_preserved_for_join_with_same_obl_order() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("obl:a");
        let b = dag.leaf("b"); // no obligation
        let c = dag.leaf("obl:c");
        let j1 = dag.join(vec![a, b, c]);
        let j2 = dag.join(vec![a, c]); // dropped non-obligation child, order intact
        let root = dag.join(vec![j1, j2]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // obligation-bearing order is [a, c] in both
        assert!(checker.rewrite_preserves_finalize_order(j1, j2));
    }

    #[test]
    fn finalize_order_allows_flattening_nested_join_with_obligations() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("obl:a");
        let b = dag.leaf("obl:b");
        let c = dag.leaf("obl:c");
        let inner = dag.join(vec![a, b]);
        let nested = dag.join(vec![inner, c]);
        let flat = dag.join(vec![a, b, c]);
        let root = dag.join(vec![nested, flat]);
        dag.set_root(root);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.rewrite_preserves_finalize_order(nested, flat));
    }

    #[test]
    fn finalize_order_rejects_swapped_obligations() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("obl:a");
        let c = dag.leaf("obl:c");
        let j1 = dag.join(vec![a, c]);
        let j2 = dag.join(vec![c, a]); // obligation order swapped
        let root = dag.join(vec![j1, j2]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        assert!(!checker.rewrite_preserves_finalize_order(j1, j2));
    }

    #[test]
    fn finalize_order_allows_race_child_reorder() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("obl:a");
        let b = dag.leaf("obl:b");
        let r1 = dag.race(vec![a, b]);
        let r2 = dag.race(vec![b, a]);
        let root = dag.join(vec![r1, r2]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // Race nodes have no finalize ordering contract.
        assert!(checker.rewrite_preserves_finalize_order(r1, r2));
    }

    #[test]
    fn no_new_obligation_leaks_for_safe_rewrite() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("obl:a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![a, b]);
        let j2 = dag.join(vec![a, b]);
        let root = dag.join(vec![j1, j2]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // Identical structure ⇒ no new leaks.
        assert!(checker.rewrite_no_new_obligation_leaks(j1, j2));
    }

    #[test]
    fn no_new_obligation_leaks_rejects_degraded_all_paths_resolve() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("obl:a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![a, b]); // all_paths_resolve = true (join resolves all)
        let r1 = dag.race(vec![a, b]); // all_paths_resolve = false (race may cancel loser)
        let root = dag.join(vec![j1, r1]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // Degrading from join (all resolve) to race (may not) ⇒ reject
        assert!(!checker.rewrite_no_new_obligation_leaks(j1, r1));
    }

    #[test]
    fn structural_type_change_rejects_finalize_order() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j = dag.join(vec![a, b]);
        let r = dag.race(vec![a, b]);
        let root = dag.join(vec![j, r]);
        dag.set_root(root);
        let checker = SideConditionChecker::new(&dag);
        // Join → Race structural change ⇒ reject
        assert!(!checker.rewrite_preserves_finalize_order(j, r));
    }

    #[test]
    fn obligation_safety_debug_clone_copy_ord() {
        let s = ObligationSafety::Clean;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Clean"));

        let s2 = s;
        assert_eq!(s, s2);

        // Copy
        let s3 = s;
        assert_eq!(s, s3);

        // Ord: Clean < MayLeak < Leaked < Unknown
        assert!(ObligationSafety::Clean < ObligationSafety::MayLeak);
        assert!(ObligationSafety::MayLeak < ObligationSafety::Leaked);
        assert!(ObligationSafety::Leaked < ObligationSafety::Unknown);
    }

    #[test]
    fn cancel_safety_debug_clone_copy_ord() {
        let c = CancelSafety::Safe;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Safe"));

        let c2 = c;
        assert_eq!(c, c2);

        let c3 = c;
        assert_eq!(c, c3);

        assert!(CancelSafety::Safe < CancelSafety::Unknown);
    }

    #[test]
    fn deadline_micros_debug_clone_copy_eq() {
        let d = DeadlineMicros(Some(1000));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("1000"));

        let d2 = d;
        assert_eq!(d, d2);

        let d3 = d;
        assert_eq!(d, d3);

        assert!(DeadlineMicros(None) < DeadlineMicros(Some(0)));
    }

    #[test]
    fn obligation_flow_debug_clone_default() {
        let f = ObligationFlow::default();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("ObligationFlow"));

        let f2 = f.clone();
        assert_eq!(f, f2);

        // empty() differs from default(): all_paths_resolve = true vs false
        let f3 = ObligationFlow::empty();
        assert!(f3.all_paths_resolve);
        assert!(!f.all_paths_resolve);
    }

    #[test]
    fn independence_result_debug_clone_copy_eq() {
        let r = IndependenceResult::Independent;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Independent"));

        let r2 = r;
        assert_eq!(r, r2);

        let r3 = r;
        assert_eq!(r, r3);

        assert_ne!(
            IndependenceResult::Independent,
            IndependenceResult::Dependent
        );
    }

    #[test]
    fn trace_equivalence_hint_debug_clone_eq() {
        let h = TraceEquivalenceHint::Atomic;
        let dbg = format!("{h:?}");
        assert!(dbg.contains("Atomic"));

        let h2 = h.clone();
        assert_eq!(h, h2);

        assert_ne!(
            TraceEquivalenceHint::Atomic,
            TraceEquivalenceHint::Sequential
        );
    }

    // ---- Golden artifacts: Display outputs for complex analysis types ----
    //
    // These snapshots freeze the human-facing Display format so downstream
    // consumers (doctor reports, plan-dump CLI, operator dashboards) get a
    // stable contract. Changes here require an intentional `cargo insta
    // accept` by a reviewer.

    #[test]
    fn golden_display_obligation_safety_all_variants() {
        let rendered = [
            ObligationSafety::Clean,
            ObligationSafety::MayLeak,
            ObligationSafety::Leaked,
            ObligationSafety::Unknown,
        ]
        .map(|v| format!("{v:?} -> {v}"))
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_display_cancel_safety_all_variants() {
        let rendered = [
            CancelSafety::Safe,
            CancelSafety::MayOrphan,
            CancelSafety::Orphan,
            CancelSafety::Unknown,
        ]
        .map(|v| format!("{v:?} -> {v}"))
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_display_budget_effect_shapes() {
        let leaf = BudgetEffect::LEAF;
        let unknown = BudgetEffect::UNKNOWN;
        let with_deadline = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(2_500));
        let parallel = leaf.parallel(leaf);
        let sequential_with_deadline = leaf
            .with_deadline(DeadlineMicros::from_micros(500))
            .sequential(leaf.with_deadline(DeadlineMicros::from_micros(750)));
        let rendered = [
            ("leaf", leaf),
            ("unknown", unknown),
            ("with_deadline(2500µs)", with_deadline),
            ("parallel(leaf, leaf)", parallel),
            ("sequential(500µs, 750µs)", sequential_with_deadline),
        ]
        .map(|(tag, b)| format!("{tag}: {b}"))
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_display_obligation_flow_shapes() {
        let empty = ObligationFlow::empty();
        let leaf = ObligationFlow::leaf_with_obligation("obl:permit".to_string());
        let joined = ObligationFlow::leaf_with_obligation("obl:a".to_string())
            .join(ObligationFlow::leaf_with_obligation("obl:b".to_string()));
        let raced = ObligationFlow::leaf_with_obligation("obl:winner".to_string()).race(
            ObligationFlow::leaf_with_obligation("obl:loser".to_string()),
        );
        let rendered = [
            ("empty", empty),
            ("leaf_with_obligation", leaf),
            ("join(a,b)", joined),
            ("race(winner,loser)", raced),
        ]
        .iter()
        .map(|(tag, f)| format!("{tag}: {f}"))
        .collect::<Vec<_>>()
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_display_independence_result_all_variants() {
        let rendered = [
            IndependenceResult::Independent,
            IndependenceResult::Dependent,
            IndependenceResult::Uncertain,
        ]
        .map(|v| format!("{v:?} -> {v}"))
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_display_trace_equivalence_hint_all_variants() {
        let partial_two_groups = TraceEquivalenceHint::PartiallyCommutative {
            groups: vec![vec![0, 1], vec![2]],
        };
        let partial_three_groups = TraceEquivalenceHint::PartiallyCommutative {
            groups: vec![vec![0], vec![1], vec![2, 3]],
        };
        let rendered = [
            ("Atomic", TraceEquivalenceHint::Atomic),
            ("FullyCommutative", TraceEquivalenceHint::FullyCommutative),
            ("PartiallyCommutative(2)", partial_two_groups),
            ("PartiallyCommutative(3)", partial_three_groups),
            ("Sequential", TraceEquivalenceHint::Sequential),
            ("Unknown", TraceEquivalenceHint::Unknown),
        ]
        .iter()
        .map(|(tag, v)| format!("{tag}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_display_deadline_micros_orders_of_magnitude() {
        let rendered = [
            DeadlineMicros::UNBOUNDED,
            DeadlineMicros::ZERO,
            DeadlineMicros::from_micros(42),
            DeadlineMicros::from_micros(1_500),
            DeadlineMicros::from_micros(2_500_000),
        ]
        .map(|d| format!("{d:?} -> {d}"))
        .join("\n");
        insta::assert_snapshot!(rendered);
    }

    #[test]
    fn golden_analysis_summary_race_of_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(analysis.summary());
    }

    #[test]
    fn golden_analysis_summary_nested_join_in_race() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join = dag.join(vec![a, b]);
        let race = dag.race(vec![join, c]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(analysis.summary());
    }

    // ===========================================================================
    // Golden artifact tests for full analysis reports
    // ===========================================================================

    #[test]
    fn golden_full_analysis_single_leaf() {
        let (dag, _) = leaf_dag("simple_leaf");
        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_race_of_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("winner");
        let b = dag.leaf("loser");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_join_of_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("task_a");
        let b = dag.leaf("task_b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_nested_structure() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("leaf_a");
        let b = dag.leaf("leaf_b");
        let c = dag.leaf("leaf_c");
        let d = dag.leaf("leaf_d");

        // Build: race(join(a,b), join(c,d))
        let left_join = dag.join(vec![a, b]);
        let right_join = dag.join(vec![c, d]);
        let top_race = dag.race(vec![left_join, right_join]);
        dag.set_root(top_race);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_obligation_nodes() {
        let mut dag = PlanDag::new();
        let permit = dag.leaf("obl:permit");
        let ack = dag.leaf("obl:ack");
        let lease = dag.leaf("obl:lease");
        let normal = dag.leaf("normal_task");

        // Build: join(permit, race(ack, lease), normal)
        let obl_race = dag.race(vec![ack, lease]);
        let all_join = dag.join(vec![permit, obl_race, normal]);
        dag.set_root(all_join);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_timeout_structure() {
        let mut dag = PlanDag::new();
        let slow_task = dag.leaf("slow_operation");
        let timeout_node = dag.timeout(slow_task, std::time::Duration::from_millis(100));
        dag.set_root(timeout_node);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_complex_mixed_structure() {
        let mut dag = PlanDag::new();

        // Create a complex structure with multiple patterns:
        // timeout(race(join(obl:permit, task1), slow_task), 50ms)
        let permit = dag.leaf("obl:permit");
        let task1 = dag.leaf("fast_task");
        let slow_task = dag.leaf("slow_task");

        let left_join = dag.join(vec![permit, task1]);
        let race = dag.race(vec![left_join, slow_task]);
        let timeout_root = dag.timeout(race, std::time::Duration::from_millis(50));
        dag.set_root(timeout_root);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_full_analysis_empty_dag() {
        let dag = PlanDag::new();
        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    #[test]
    fn golden_single_node_analysis() {
        let (dag, root_id) = leaf_dag("test_node");
        let analysis = PlanAnalyzer::analyze(&dag);
        let node_analysis = analysis.get(root_id).unwrap();
        insta::assert_snapshot!(format!("{}", node_analysis));
    }

    #[test]
    fn golden_obligation_node_analysis() {
        let mut dag = PlanDag::new();
        let obl = dag.leaf("obl:lease:critical");
        dag.set_root(obl);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node_analysis = analysis.get(obl).unwrap();
        insta::assert_snapshot!(format!("{}", node_analysis));
    }

    #[test]
    fn golden_full_analysis_deep_nesting() {
        let mut dag = PlanDag::new();

        // Create deeply nested structure: timeout(join(race(a,b), race(c,d)), 200ms)
        let a = dag.leaf("task_a");
        let b = dag.leaf("task_b");
        let c = dag.leaf("task_c");
        let d = dag.leaf("task_d");

        let race1 = dag.race(vec![a, b]);
        let race2 = dag.race(vec![c, d]);
        let join = dag.join(vec![race1, race2]);
        let timeout_root = dag.timeout(join, std::time::Duration::from_millis(200));
        dag.set_root(timeout_root);

        let analysis = PlanAnalyzer::analyze(&dag);
        insta::assert_snapshot!(format!("{}", analysis));
    }

    // ------------------------------------------------------------------------
    // Golden-artifact: canonical plan-analysis machine-readable report.
    //
    // The existing `golden_full_analysis_*` snapshots freeze the human-readable
    // Display output. This complementary snapshot freezes every public accessor
    // on `PlanAnalysis` and `NodeAnalysis` for ONE non-trivial DAG:
    //
    //   timeout(
    //     join(
    //       obl:permit,
    //       race(
    //         obl:lease,
    //         normal_task,
    //       ),
    //       slow_task,
    //     ),
    //     100ms,
    //   )
    //
    // covering leaf / obligation-leaf / race / join / timeout in one report.
    // Any future change to accessor semantics surfaces as a diff.
    // ------------------------------------------------------------------------
    #[test]
    fn canonical_plan_analysis_report_snapshot() {
        let mut dag = PlanDag::new();
        let permit = dag.leaf("obl:permit");
        let lease = dag.leaf("obl:lease");
        let normal = dag.leaf("normal_task");
        let slow = dag.leaf("slow_task");
        let inner_race = dag.race(vec![lease, normal]);
        let join = dag.join(vec![permit, inner_race, slow]);
        let root = dag.timeout(join, std::time::Duration::from_millis(100));
        dag.set_root(root);

        let analysis = PlanAnalyzer::analyze(&dag);

        // Per-node view (sorted by PlanId index for determinism).
        let mut by_id: Vec<_> = analysis.nodes.iter().collect();
        by_id.sort_by_key(|(id, _)| **id);
        let per_node: Vec<_> = by_id
            .into_iter()
            .map(|(id, n)| {
                serde_json::json!({
                    "id": *id,
                    "obligation":            format!("{}", n.obligation),
                    "effective_obligation":  format!("{}", n.effective_obligation()),
                    "obligation_flow":       format!("{}", n.obligation_flow),
                    "cancel":                format!("{}", n.cancel),
                    "budget":                format!("{}", n.budget),
                    "cost":                  format!("{}", n.cost),
                    "has_obligation_issues": n.has_obligation_issues(),
                    "is_safe":               n.is_safe(),
                })
            })
            .collect();

        let obligation_ids: Vec<_> = analysis
            .obligation_issues()
            .iter()
            .map(|n| n.id.index())
            .collect();
        let cancel_ids: Vec<_> = analysis
            .cancel_issues()
            .iter()
            .map(|n| n.id.index())
            .collect();

        insta::assert_json_snapshot!(
            "canonical_plan_analysis_report",
            serde_json::json!({
                "summary":           analysis.summary(),
                "all_safe":          analysis.all_safe(),
                "node_count":        analysis.nodes.len(),
                "obligation_issue_ids": obligation_ids,
                "cancel_issue_ids":     cancel_ids,
                "per_node":          per_node,
            })
        );
    }

    #[test]
    fn display_outputs_golden_artifacts() {
        // Test all complex Display implementations for golden artifact stability

        // ObligationSafety variants
        insta::assert_snapshot!(
            "obligation_safety_clean",
            format!("{}", ObligationSafety::Clean)
        );
        insta::assert_snapshot!(
            "obligation_safety_may_leak",
            format!("{}", ObligationSafety::MayLeak)
        );
        insta::assert_snapshot!(
            "obligation_safety_leaked",
            format!("{}", ObligationSafety::Leaked)
        );
        insta::assert_snapshot!(
            "obligation_safety_unknown",
            format!("{}", ObligationSafety::Unknown)
        );

        // CancelSafety variants
        insta::assert_snapshot!("cancel_safety_safe", format!("{}", CancelSafety::Safe));
        insta::assert_snapshot!(
            "cancel_safety_may_orphan",
            format!("{}", CancelSafety::MayOrphan)
        );
        insta::assert_snapshot!("cancel_safety_orphan", format!("{}", CancelSafety::Orphan));
        insta::assert_snapshot!(
            "cancel_safety_unknown",
            format!("{}", CancelSafety::Unknown)
        );

        // BudgetEffect variants
        insta::assert_snapshot!("budget_effect_leaf", format!("{}", BudgetEffect::LEAF));
        insta::assert_snapshot!(
            "budget_effect_unknown",
            format!("{}", BudgetEffect::UNKNOWN)
        );

        let effect_with_deadline =
            BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(1500));
        insta::assert_snapshot!(
            "budget_effect_with_deadline",
            format!("{}", effect_with_deadline)
        );

        // ObligationFlow variants
        let empty_flow = ObligationFlow::empty();
        insta::assert_snapshot!("obligation_flow_empty", format!("{}", empty_flow));

        let flow_with_obligation =
            ObligationFlow::leaf_with_obligation("test_obligation".to_string());
        insta::assert_snapshot!(
            "obligation_flow_with_obligation",
            format!("{}", flow_with_obligation)
        );

        // DeadlineMicros variants
        insta::assert_snapshot!(
            "deadline_micros_unbounded",
            format!("{}", DeadlineMicros::UNBOUNDED)
        );
        insta::assert_snapshot!("deadline_micros_zero", format!("{}", DeadlineMicros::ZERO));
        insta::assert_snapshot!(
            "deadline_micros_microseconds",
            format!("{}", DeadlineMicros::from_micros(500))
        );
        insta::assert_snapshot!(
            "deadline_micros_milliseconds",
            format!("{}", DeadlineMicros::from_micros(2500))
        );
        insta::assert_snapshot!(
            "deadline_micros_seconds",
            format!("{}", DeadlineMicros::from_micros(3000000))
        );
    }
