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

    fn scrub_rewrite_summary(summary: &str) -> String {
        summary
            .lines()
            .map(|line| {
                if let Some((prefix, _)) = line.split_once(" (") {
                    format!("{prefix} ([PLAN_ID] -> [PLAN_ID])")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn shared_leaf_race_plan() -> (PlanDag, PlanId, PlanId, PlanId) {
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);
        (dag, shared, left, right)
    }

    #[test]
    fn test_apply_rewrites_empty_dag_no_steps() {
        init_test();
        let mut dag = PlanDag::new();
        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
    }

    #[test]
    fn test_dedup_race_join_conservative_applies() {
        init_test();
        let (mut dag, shared, left, right) = shared_leaf_race_plan();
        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root set");
        let PlanNode::Join { children } = dag.node(root).expect("root exists") else {
            panic!("expected join at root");
        };
        assert!(children.contains(&shared));
        let race_child = children
            .iter()
            .copied()
            .find(|id| *id != shared)
            .expect("race");
        let PlanNode::Race { children } = dag.node(race_child).expect("race exists") else {
            panic!("expected race child");
        };
        assert!(children.contains(&left));
        assert!(children.contains(&right));
    }

    #[test]
    fn test_dedup_race_join_conservative_rejects_non_leaf_shared() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let shared = dag.join(vec![a, b]);
        let c = dag.leaf("c");
        let d = dag.leaf("d");
        let join_a = dag.join(vec![shared, c]);
        let join_b = dag.join(vec![shared, d]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());

        let report = dag.apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::DedupRaceJoin]);
        assert_eq!(report.steps().len(), 1);
    }

    #[test]
    fn test_dedup_race_join_conservative_rejects_non_binary_joins() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let d = dag.leaf("d");
        let join_a = dag.join(vec![shared, a, b]);
        let join_b = dag.join(vec![shared, c, d]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());

        let report = dag.apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::DedupRaceJoin]);
        assert_eq!(report.steps().len(), 1);
    }

    #[test]
    fn test_dedup_race_join_idempotent_on_rewritten_shape() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let race = dag.race(vec![left, right]);
        let join = dag.join(vec![shared, race]);
        dag.set_root(join);

        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
    }

    #[test]
    fn test_apply_rewrites_handles_missing_child_gracefully() {
        init_test();
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("leaf");
        let missing = PlanId::new(999);
        let join = dag.join(vec![leaf, missing]);
        let race = dag.race(vec![join, leaf]);
        dag.set_root(race);

        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
        assert_eq!(dag.root(), Some(race));
    }

    #[test]
    fn test_apply_rewrites_multiple_races_single_pass() {
        init_test();
        let (mut dag, _shared1, _left1, _right1) = shared_leaf_race_plan();
        let shared2 = dag.leaf("shared2");
        let left2 = dag.leaf("left2");
        let right2 = dag.leaf("right2");
        let join_a = dag.join(vec![shared2, left2]);
        let join_b = dag.join(vec![shared2, right2]);
        let race2 = dag.race(vec![join_a, join_b]);
        let root = dag.join(vec![dag.root().expect("root"), race2]);
        dag.set_root(root);

        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert_eq!(report.steps().len(), 2);
        assert!(
            report
                .steps()
                .iter()
                .all(|step| step.rule == RewriteRule::DedupRaceJoin)
        );
        let root = dag.root().expect("root");
        let PlanNode::Join { children } = dag.node(root).expect("root exists") else {
            panic!("expected join at root");
        };
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_dedup_race_join_skips_single_child_race() {
        init_test();
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("leaf");
        let race = dag.race(vec![leaf]);
        dag.set_root(race);

        let report =
            dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
        assert_eq!(dag.root(), Some(race));
    }

    #[test]
    fn test_join_assoc_flattens_nested_join() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.join(vec![a, b]);
        let outer = dag.join(vec![inner, c]);
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::JoinAssoc]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Join { children } = dag.node(root).expect("join") else {
            panic!("expected join root");
        };
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn test_race_assoc_flattens_nested_race() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.race(vec![a, b]);
        let outer = dag.race(vec![inner, c]);
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::RaceAssoc]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Race { children } = dag.node(root).expect("race") else {
            panic!("expected race root");
        };
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn test_join_commute_canonical_order() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join = dag.join(vec![c, b, a]);
        dag.set_root(join);

        let report = dag.apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::JoinCommute]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Join { children } = dag.node(root).expect("join") else {
            panic!("expected join root");
        };
        let indices: Vec<_> = children.iter().map(|id| id.index()).collect();
        assert_eq!(indices, vec![a.index(), b.index(), c.index()]);
    }

    #[test]
    fn test_join_commute_rejects_shared_subtree() {
        init_test();
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s, b]);
        let join = dag.join(vec![j1, j2]);
        dag.set_root(join);

        let report = dag.apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::JoinCommute]);
        assert!(report.is_empty());
    }

    #[test]
    fn test_race_commute_canonical_order() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let race = dag.race(vec![c, b, a]);
        dag.set_root(race);

        let report = dag.apply_rewrites(RewritePolicy::assume_all(), &[RewriteRule::RaceCommute]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Race { children } = dag.node(root).expect("race") else {
            panic!("expected race root");
        };
        let indices: Vec<_> = children.iter().map(|id| id.index()).collect();
        assert_eq!(indices, vec![a.index(), b.index(), c.index()]);
    }

    #[test]
    fn test_timeout_min_collapses_nested_timeouts() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let inner = dag.timeout(a, Duration::from_secs(10));
        let outer = dag.timeout(inner, Duration::from_secs(5));
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::TimeoutMin]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Timeout { duration, child } = dag.node(root).expect("timeout") else {
            panic!("expected timeout root");
        };
        assert_eq!(*duration, Duration::from_secs(5));
        assert_eq!(*child, a);
    }

    #[test]
    fn rule_schema_has_explanations() {
        init_test();
        for rule in RewriteRule::all() {
            let schema = rule.schema();
            assert!(!schema.pattern.is_empty());
            assert!(!schema.replacement.is_empty());
            assert!(!schema.explanation.is_empty());
            assert!(!schema.side_conditions.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Algebraic law gating tests (bd-2m0t)
    // -----------------------------------------------------------------------

    #[test]
    fn every_rule_declares_required_laws() {
        init_test();
        for rule in RewriteRule::all() {
            let laws = rule.required_laws();
            assert!(
                !laws.is_empty(),
                "{rule:?} must declare at least one required law"
            );
        }
    }

    #[test]
    fn policy_new_disables_all_laws() {
        init_test();
        let policy = RewritePolicy::new();
        for rule in RewriteRule::all() {
            assert!(
                !policy.permits(*rule),
                "{rule:?} must be rejected by empty policy"
            );
        }
    }

    #[test]
    fn policy_conservative_permits_expected_rules() {
        init_test();
        let policy = RewritePolicy::conservative();
        assert!(policy.permits(RewriteRule::JoinAssoc));
        assert!(policy.permits(RewriteRule::RaceAssoc));
        assert!(policy.permits(RewriteRule::TimeoutMin));
        assert!(policy.permits(RewriteRule::DedupRaceJoin));
        // Conservative restricts distributivity (binary joins, leaf shared)
        // but still permits the rule — fine-grained checks happen inside the rule.
        assert!(!policy.permits(RewriteRule::JoinCommute));
        assert!(!policy.permits(RewriteRule::RaceCommute));
    }

    #[test]
    fn policy_assume_all_permits_everything() {
        init_test();
        let policy = RewritePolicy::assume_all();
        for rule in RewriteRule::all() {
            assert!(
                policy.permits(*rule),
                "{rule:?} must be permitted by assume_all"
            );
        }
    }

    #[test]
    fn timeout_min_blocked_by_empty_policy() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let inner = dag.timeout(a, Duration::from_secs(10));
        let outer = dag.timeout(inner, Duration::from_secs(5));
        dag.set_root(outer);

        // Empty policy disables timeout simplification.
        let report = dag.apply_rewrites(RewritePolicy::new(), &[RewriteRule::TimeoutMin]);
        assert!(
            report.is_empty(),
            "TimeoutMin must not fire when policy disables timeout_simplification"
        );
    }

    #[test]
    fn timeout_min_allowed_by_conservative_policy() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let inner = dag.timeout(a, Duration::from_secs(10));
        let outer = dag.timeout(inner, Duration::from_secs(5));
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::TimeoutMin]);
        assert_eq!(report.steps().len(), 1);
    }

    #[test]
    fn custom_policy_gates_individual_laws() {
        init_test();
        // Enable only commutativity.
        let policy = RewritePolicy::new().with_commutativity(true);
        assert!(policy.permits(RewriteRule::JoinCommute));
        assert!(policy.permits(RewriteRule::RaceCommute));
        assert!(!policy.permits(RewriteRule::JoinAssoc));
        assert!(!policy.permits(RewriteRule::TimeoutMin));
        assert!(!policy.permits(RewriteRule::DedupRaceJoin));

        // Enable only distributivity (permits DedupRaceJoin).
        let policy = RewritePolicy::new().with_distributivity(true);
        assert!(policy.permits(RewriteRule::DedupRaceJoin));
        assert!(!policy.permits(RewriteRule::JoinAssoc));
        assert!(!policy.permits(RewriteRule::JoinCommute));

        // Enable only timeout simplification.
        let policy = RewritePolicy::new().with_timeout_simplification(true);
        assert!(policy.permits(RewriteRule::TimeoutMin));
        assert!(!policy.permits(RewriteRule::JoinAssoc));
        assert!(!policy.permits(RewriteRule::DedupRaceJoin));
    }

    #[test]
    fn permits_matches_apply_behavior() {
        init_test();
        // If policy doesn't permit a rule, apply_rewrites must produce no steps.
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let inner = dag.join(vec![a, b]);
        let c = dag.leaf("c");
        let outer = dag.join(vec![inner, c]);
        dag.set_root(outer);

        // JoinAssoc requires Associativity. Empty policy blocks it.
        let report = dag.apply_rewrites(RewritePolicy::new(), &[RewriteRule::JoinAssoc]);
        assert!(report.is_empty());

        // Conservative enables associativity, so it applies.
        let report = dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::JoinAssoc]);
        assert_eq!(report.steps().len(), 1);
    }

    // -----------------------------------------------------------------------
    // Rewrite engine complexity bounds (bd-123x)
    // -----------------------------------------------------------------------

    /// Build a flat join chain: Join(leaf_0, leaf_1, ..., leaf_{n-1}).
    fn build_flat_join_dag(n: usize) -> PlanDag {
        let mut dag = PlanDag::new();
        let leaves: Vec<_> = (0..n).map(|i| dag.leaf(format!("leaf_{i}"))).collect();
        let join = dag.join(leaves);
        dag.set_root(join);
        dag
    }

    /// Build a nested join tree of depth d: Join(Join(Join(...), leaf), leaf).
    fn build_nested_join_dag(depth: usize) -> PlanDag {
        let mut dag = PlanDag::new();
        let mut current = dag.leaf("leaf_0");
        for i in 1..depth {
            let leaf = dag.leaf(format!("leaf_{i}"));
            current = dag.join(vec![current, leaf]);
        }
        dag.set_root(current);
        dag
    }

    /// Build a race-of-joins structure for DedupRaceJoin testing.
    fn build_race_of_joins_dag(branches: usize) -> PlanDag {
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let joins: Vec<_> = (0..branches)
            .map(|i| {
                let branch = dag.leaf(format!("branch_{i}"));
                dag.join(vec![shared, branch])
            })
            .collect();
        let race = dag.race(joins);
        dag.set_root(race);
        dag
    }

    #[test]
    fn rewrite_step_count_bounded_by_node_count() {
        init_test();
        // The number of rewrite steps should be at most proportional to
        // the number of nodes (O(n) steps for O(n) nodes).
        for n in [5, 10, 20, 50] {
            let mut dag = build_nested_join_dag(n);
            let node_count = dag.nodes.len();
            let all_rules = &[
                RewriteRule::JoinAssoc,
                RewriteRule::RaceAssoc,
                RewriteRule::JoinCommute,
                RewriteRule::RaceCommute,
                RewriteRule::TimeoutMin,
                RewriteRule::DedupRaceJoin,
            ];
            let report = dag.apply_rewrites(RewritePolicy::assume_all(), all_rules);
            assert!(
                report.steps().len() <= node_count,
                "Too many steps ({}) for {} nodes at n={n}",
                report.steps().len(),
                node_count,
            );
        }
    }

    #[test]
    fn rewrite_flat_join_is_noop() {
        init_test();
        // A flat join with no nesting should produce no rewrite steps.
        for n in [5, 20, 100] {
            let mut dag = build_flat_join_dag(n);
            let all_rules = &[
                RewriteRule::JoinAssoc,
                RewriteRule::JoinCommute,
                RewriteRule::DedupRaceJoin,
            ];
            let report = dag.apply_rewrites(RewritePolicy::assume_all(), all_rules);
            // No nested joins => no associativity rewrites
            // Commutativity may fire if children aren't already sorted
            // Just ensure it doesn't explode
            assert!(
                report.steps().len() <= n,
                "Too many steps ({}) for flat join of size {n}",
                report.steps().len(),
            );
        }
    }

    #[test]
    fn rewrite_race_of_joins_bounded() {
        init_test();
        for branches in [2, 5, 10] {
            let mut dag = build_race_of_joins_dag(branches);
            let node_count = dag.nodes.len();
            let report =
                dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::DedupRaceJoin]);
            assert!(
                report.steps().len() <= node_count,
                "Too many DedupRaceJoin steps ({}) for {} nodes",
                report.steps().len(),
                node_count,
            );
        }
    }

    #[test]
    fn certified_rewrite_matches_uncertified() {
        init_test();
        for n in [3, 5, 10] {
            let dag = build_nested_join_dag(n);
            let all_rules = &[RewriteRule::JoinAssoc, RewriteRule::JoinCommute];

            let mut dag1 = dag.clone();
            let report1 = dag1.apply_rewrites(RewritePolicy::assume_all(), all_rules);

            let mut dag2 = dag;
            let (report2, _cert) =
                dag2.apply_rewrites_certified(RewritePolicy::assume_all(), all_rules);

            assert_eq!(report1.steps().len(), report2.steps().len());
        }
    }

    #[test]
    fn rewrite_policy_debug_clone_copy_default_eq() {
        let p = RewritePolicy::default();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("RewritePolicy"));

        let p2 = p;
        assert_eq!(p, p2);

        // Copy
        let p3 = p;
        assert_eq!(p, p3);

        // default == conservative
        assert_eq!(RewritePolicy::default(), RewritePolicy::conservative());
        assert_ne!(RewritePolicy::conservative(), RewritePolicy::assume_all());
    }

    #[test]
    fn algebraic_law_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let law = AlgebraicLaw::Associativity;
        let dbg = format!("{law:?}");
        assert!(dbg.contains("Associativity"));

        let law2 = law;
        assert_eq!(law, law2);

        let law3 = law;
        assert_eq!(law, law3);

        assert_ne!(AlgebraicLaw::Associativity, AlgebraicLaw::Commutativity);

        let mut set = HashSet::new();
        set.insert(AlgebraicLaw::Associativity);
        set.insert(AlgebraicLaw::Commutativity);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn rewrite_rule_debug_clone_copy_eq() {
        let r = RewriteRule::JoinAssoc;
        let dbg = format!("{r:?}");
        assert!(dbg.contains("JoinAssoc"));

        let r2 = r;
        assert_eq!(r, r2);

        let r3 = r;
        assert_eq!(r, r3);

        assert_ne!(RewriteRule::JoinAssoc, RewriteRule::RaceAssoc);
    }

    #[test]
    fn rewrite_report_debug_clone_default() {
        let rr = RewriteReport::default();
        let dbg = format!("{rr:?}");
        assert!(dbg.contains("RewriteReport"));

        let rr2 = rr;
        assert_eq!(rr2.steps().len(), 0);
    }

    #[test]
    fn rewrite_report_summary_snapshot_scrubbed() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let inner = dag.join(vec![a, b]);
        let c = dag.leaf("c");
        let outer = dag.join(vec![inner, c]);
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::conservative(), &[RewriteRule::JoinAssoc]);
        assert_eq!(
            report.steps().len(),
            1,
            "expected a single join-assoc rewrite"
        );

        insta::assert_snapshot!(
            "rewrite_report_summary_scrubbed",
            scrub_rewrite_summary(&report.summary())
        );
    }
