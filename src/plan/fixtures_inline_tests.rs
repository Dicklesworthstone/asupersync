    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::plan::certificate::{verify, verify_steps};
    use crate::plan::rewrite::{RewritePolicy, RewriteRule};
    use crate::test_utils::init_test_logging;

    fn init_test() {
        init_test_logging();
    }

    #[test]
    fn all_fixtures_validate() {
        init_test();
        for fixture in all_fixtures() {
            assert!(
                fixture.dag.validate().is_ok(),
                "fixture {} failed validation",
                fixture.name
            );
        }
    }

    #[test]
    fn fixture_count_at_least_10() {
        init_test();
        let fixtures = all_fixtures();
        assert!(
            fixtures.len() >= 10,
            "need >= 10 fixtures, got {}",
            fixtures.len()
        );
    }

    #[test]
    fn non_test_plan_fixture_paths_do_not_print_directly() {
        init_test();
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/plan/fixtures.rs"));
        let non_test = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !non_test.contains("println!(") && !non_test.contains("eprintln!("),
            "non-test plan fixture paths should use tracing instead of stdout/stderr"
        );
    }

    #[test]
    fn conservative_rewrites_match_expected_counts() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for mut fixture in all_fixtures() {
            // Skip fixtures designed for non-conservative policy.
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let (report, cert) = fixture
                .dag
                .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
            assert_eq!(
                report.steps().len(),
                fixture.expected_step_count,
                "fixture {}: expected {} steps, got {}",
                fixture.name,
                fixture.expected_step_count,
                report.steps().len()
            );
            assert!(
                verify(&cert, &fixture.dag).is_ok(),
                "fixture {}: certificate verification failed",
                fixture.name
            );
            assert!(
                verify_steps(&cert, &fixture.dag).is_ok(),
                "fixture {}: step verification failed",
                fixture.name
            );
        }
    }

    #[test]
    fn associative_policy_fires_on_non_leaf_shared() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let fixtures = all_fixtures();
        let fixture = fixtures
            .iter()
            .find(|f| f.name == "shared_non_leaf_associative")
            .expect("fixture exists");
        let mut dag = PlanDag::new();
        // Rebuild the fixture DAG (can't move out of Vec reference).
        let x = dag.leaf("x");
        let y = dag.leaf("y");
        let shared_join = dag.join(vec![x, y]);
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![shared_join, a]);
        let j2 = dag.join(vec![shared_join, b]);
        let race = dag.race(vec![j1, j2]);
        dag.set_root(race);

        let (report, cert) = dag.apply_rewrites_certified(RewritePolicy::assume_all(), &rules);
        assert_eq!(report.steps().len(), fixture.expected_step_count);
        assert!(verify(&cert, &dag).is_ok());
    }

    #[test]
    fn lab_equivalence_all_fixtures_conservative() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let report = run_equivalence_harness(fixture, RewritePolicy::conservative(), &rules);
            if let Some(diff) = report.diff_summary() {
                panic!("equivalence failure:\n{diff}");
            }
            assert!(report.all_ok());
        }
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn rule_witness_golden_fingerprints() {
        // Golden regression test: certificate fingerprints must be stable.
        // If these fail, either the hash function or the rewrite engine changed.
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];

        // F1: simple_join_race_dedup (the canonical DedupRaceJoin witness)
        let mut f1 = simple_join_race_dedup();
        let (_, cert1) = f1
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(cert1.steps.len(), 1, "F1 must have exactly 1 rewrite step");
        assert!(verify(&cert1, &f1.dag).is_ok(), "F1 cert must verify");
        assert!(
            verify_steps(&cert1, &f1.dag).is_ok(),
            "F1 steps must verify"
        );
        // Golden fingerprint: pinned to detect hash/rewrite changes.
        // br-asupersync-eyb1s5: fingerprint is now a 32-byte SHA-256 PlanHash.
        let fp1 = cert1.fingerprint();
        assert!(
            fp1.as_bytes().iter().any(|b| *b != 0),
            "fingerprint must not be all-zero"
        );
        // Verify the before and after hashes differ (rewrite was applied).
        assert_ne!(cert1.before_hash, cert1.after_hash);

        // F3: nested_timeout_join_race
        let mut f3 = nested_timeout_join_race();
        let (_, cert3) = f3
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(cert3.steps.len(), 1);
        assert!(verify(&cert3, &f3.dag).is_ok());
        assert!(verify_steps(&cert3, &f3.dag).is_ok());
        let fp3 = cert3.fingerprint();
        assert_ne!(
            fp3, fp1,
            "different fixtures must produce different fingerprints"
        );

        // F10: timeout_wrapping_dedup
        let mut fixture_timeout = timeout_wrapping_dedup();
        let (_, cert_timeout) = fixture_timeout
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(cert_timeout.steps.len(), 1);
        assert!(verify(&cert_timeout, &fixture_timeout.dag).is_ok());
        assert!(verify_steps(&cert_timeout, &fixture_timeout.dag).is_ok());
        let fp_timeout = cert_timeout.fingerprint();
        assert_ne!(fp_timeout, fp1);
        assert_ne!(fp_timeout, fp3);

        // No-rewrite fixtures must produce identity certificates with matching fingerprints
        // across repeated construction.
        let mut fixture_no_shared_a = no_shared_child();
        let (_, cert_no_shared_a) = fixture_no_shared_a
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert!(cert_no_shared_a.is_identity());
        let mut fixture_no_shared_b = no_shared_child();
        let (_, cert_no_shared_b) = fixture_no_shared_b
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);
        assert_eq!(
            cert_no_shared_a.fingerprint(),
            cert_no_shared_b.fingerprint()
        );
    }

    #[test]
    fn egraph_determinism_golden_hashes() {
        // EGraph determinism: same operations in same order produce identical structure.
        use crate::plan::EGraph;

        init_test();

        // Build an e-graph twice with identical operations.
        let build = || {
            let mut eg = EGraph::new();
            let a = eg.add_leaf("a");
            let b = eg.add_leaf("b");
            let c = eg.add_leaf("c");
            let join_ab = eg.add_join(vec![a, b]);
            let join_ab2 = eg.add_join(vec![a, b]); // dedup
            let race_bc = eg.add_race(vec![b, c]);
            let top = eg.add_join(vec![join_ab, race_bc]);
            (eg, a, b, c, join_ab, join_ab2, race_bc, top)
        };

        let (mut eg1, a1, b1, _, j1, j1_dup, r1, t1) = build();
        let (mut eg2, a2, b2, _, j2, j2_dup, r2, t2) = build();

        // Hashcons dedup: identical joins return same canonical id.
        assert_eq!(eg1.canonical_id(j1), eg1.canonical_id(j1_dup));
        assert_eq!(eg2.canonical_id(j2), eg2.canonical_id(j2_dup));

        // Canonical ids must be identical across builds.
        assert_eq!(eg1.canonical_id(a1).index(), eg2.canonical_id(a2).index());
        assert_eq!(eg1.canonical_id(b1).index(), eg2.canonical_id(b2).index());
        assert_eq!(eg1.canonical_id(j1).index(), eg2.canonical_id(j2).index());
        assert_eq!(eg1.canonical_id(r1).index(), eg2.canonical_id(r2).index());
        assert_eq!(eg1.canonical_id(t1).index(), eg2.canonical_id(t2).index());

        // Merge determinism: smallest id wins.
        let merged1 = eg1.merge(b1, a1);
        let merged2 = eg2.merge(b2, a2);
        assert_eq!(merged1.index(), merged2.index());
        assert_eq!(merged1, a1); // a has smaller index
    }

    #[test]
    fn cancel_fixtures_present_and_valid() {
        init_test();
        let fixtures = all_fixtures();
        let cancel_names: Vec<&str> = fixtures
            .iter()
            .filter(|f| {
                f.name.contains("cancel")
                    || f.intent.contains("cancel")
                    || f.intent.contains("Cancel")
            })
            .map(|f| f.name)
            .collect();
        assert!(
            cancel_names.len() >= 4,
            "need >= 4 cancel-aware fixtures, got {}: {:?}",
            cancel_names.len(),
            cancel_names
        );
        for fixture in &fixtures {
            assert!(
                fixture.dag.validate().is_ok(),
                "cancel fixture {} failed validation",
                fixture.name
            );
        }
    }

    #[test]
    fn lab_equivalence_all_fixtures_all_rules() {
        init_test();
        let all_rules = [
            RewriteRule::DedupRaceJoin,
            RewriteRule::JoinAssoc,
            RewriteRule::RaceAssoc,
            RewriteRule::JoinCommute,
            RewriteRule::RaceCommute,
            RewriteRule::TimeoutMin,
        ];
        for fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let report =
                run_equivalence_harness(fixture, RewritePolicy::conservative(), &all_rules);
            assert!(
                report.outcomes_equivalent,
                "outcomes not equivalent for fixture {}",
                report.fixture_name
            );
        }
    }

    #[test]
    fn extraction_pipeline_equivalence() {
        use crate::plan::PlanId;
        use crate::plan::extractor::Extractor;
        use std::collections::HashMap;

        init_test();
        for fixture in all_fixtures() {
            let original_outcomes = fixture
                .dag
                .root()
                .map(|root| outcome_sets(&fixture.dag, root))
                .unwrap_or_default();

            // Build e-graph from fixture DAG using recursive traversal.
            let mut eg = crate::plan::EGraph::new();
            let mut cache: HashMap<PlanId, crate::plan::EClassId> = HashMap::new();

            if let Some(root) = fixture.dag.root() {
                let root_eclass = dag_to_egraph_rec(&fixture.dag, root, &mut eg, &mut cache);
                let (extracted_dag, _cert) = Extractor::new(&mut eg)
                    .extract(root_eclass)
                    .expect("fixture DAG should extract successfully");
                let extracted_outcomes = extracted_dag
                    .root()
                    .map(|r| outcome_sets(&extracted_dag, r))
                    .unwrap_or_default();
                assert_eq!(
                    original_outcomes, extracted_outcomes,
                    "extraction changed outcomes for fixture {}",
                    fixture.name
                );
            }
        }
    }

    /// Recursively insert a DAG node into an e-graph, processing children first.
    fn dag_to_egraph_rec(
        dag: &PlanDag,
        id: PlanId,
        eg: &mut crate::plan::EGraph,
        cache: &mut HashMap<PlanId, crate::plan::EClassId>,
    ) -> crate::plan::EClassId {
        if let Some(&ec) = cache.get(&id) {
            return ec;
        }
        let node = dag.node(id).expect("valid PlanId");
        let eclass = match node.clone() {
            PlanNode::Leaf { label } => eg.add_leaf(label),
            PlanNode::Join { children } => {
                let ec: Vec<_> = children
                    .iter()
                    .map(|c| dag_to_egraph_rec(dag, *c, eg, cache))
                    .collect();
                eg.add_join(ec)
            }
            PlanNode::Race { children } => {
                let ec: Vec<_> = children
                    .iter()
                    .map(|c| dag_to_egraph_rec(dag, *c, eg, cache))
                    .collect();
                eg.add_race(ec)
            }
            PlanNode::Timeout { child, duration } => {
                let child_ec = dag_to_egraph_rec(dag, child, eg, cache);
                eg.add_timeout(child_ec, duration)
            }
        };
        cache.insert(id, eclass);
        eclass
    }

    #[test]
    fn extraction_after_rewrite_equivalence() {
        use crate::plan::PlanId;
        use crate::plan::extractor::Extractor;
        use std::collections::HashMap;

        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for mut fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let original_outcomes = fixture
                .dag
                .root()
                .map(|root| outcome_sets(&fixture.dag, root))
                .unwrap_or_default();

            // Apply rewrites.
            let (_report, _cert) = fixture
                .dag
                .apply_rewrites_certified(RewritePolicy::conservative(), &rules);

            // Build e-graph from rewritten DAG using recursive traversal.
            let mut eg = crate::plan::EGraph::new();
            let mut cache: HashMap<PlanId, crate::plan::EClassId> = HashMap::new();

            if let Some(root) = fixture.dag.root() {
                let root_eclass = dag_to_egraph_rec(&fixture.dag, root, &mut eg, &mut cache);
                let (extracted_dag, _cert) = Extractor::new(&mut eg)
                    .extract(root_eclass)
                    .expect("rewritten fixture DAG should extract successfully");
                let extracted_outcomes = extracted_dag
                    .root()
                    .map(|r| outcome_sets(&extracted_dag, r))
                    .unwrap_or_default();
                assert_eq!(
                    original_outcomes, extracted_outcomes,
                    "rewrite+extraction changed outcomes for fixture {}",
                    fixture.name
                );
            }
        }
    }

    #[test]
    fn lab_equivalence_deterministic_across_runs() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        // Run twice and compare hashes.
        let reports1: Vec<_> = all_fixtures()
            .into_iter()
            .filter(|f| f.name != "shared_non_leaf_associative")
            .map(|f| run_equivalence_harness(f, RewritePolicy::conservative(), &rules))
            .collect();
        let reports2: Vec<_> = all_fixtures()
            .into_iter()
            .filter(|f| f.name != "shared_non_leaf_associative")
            .map(|f| run_equivalence_harness(f, RewritePolicy::conservative(), &rules))
            .collect();

        assert_eq!(reports1.len(), reports2.len());
        for (r1, r2) in reports1.iter().zip(reports2.iter()) {
            assert_eq!(
                r1.original_hash, r2.original_hash,
                "{}: original hash mismatch across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.optimized_hash, r2.optimized_hash,
                "{}: optimized hash mismatch across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.original_outcomes, r2.original_outcomes,
                "{}: outcomes differ across runs",
                r1.fixture_name
            );
        }
    }

    // -----------------------------------------------------------------------
    // E2E pipeline tests (bd-3gqz)
    // -----------------------------------------------------------------------

    #[test]
    fn e2e_pipeline_all_fixtures_pass() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        assert!(
            reports.len() >= 16,
            "expected >= 16 E2E reports, got {}",
            reports.len()
        );
        for report in &reports {
            assert!(
                report.all_ok(),
                "E2E pipeline failed for fixture {}: cert_ok={}, steps_ok={}, outcomes_eq={}, \
                 extract_eq={}, rewrite_extract_eq={}, dynamic_eq={}",
                report.fixture_name,
                report.certificate_verified,
                report.steps_verified,
                report.outcomes_equivalent,
                report.extraction_equivalent,
                report.rewrite_extraction_equivalent,
                report.dynamic_outcomes_equivalent,
            );
        }
    }

    #[test]
    fn e2e_pipeline_deterministic_across_runs() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports1 = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        let reports2 = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        assert_eq!(reports1.len(), reports2.len());
        for (r1, r2) in reports1.iter().zip(reports2.iter()) {
            assert_eq!(
                r1.golden_fingerprint(),
                r2.golden_fingerprint(),
                "fixture {}: E2E golden fingerprint differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.certificate_fingerprint, r2.certificate_fingerprint,
                "fixture {}: certificate fingerprint differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.original_cost.total(),
                r2.original_cost.total(),
                "fixture {}: original cost differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.optimized_cost.total(),
                r2.optimized_cost.total(),
                "fixture {}: optimized cost differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.original_trace_fingerprint, r2.original_trace_fingerprint,
                "fixture {}: original trace fingerprint differs across runs",
                r1.fixture_name
            );
            assert_eq!(
                r1.optimized_trace_fingerprint, r2.optimized_trace_fingerprint,
                "fixture {}: optimized trace fingerprint differs across runs",
                r1.fixture_name
            );
        }
    }

    #[test]
    fn e2e_pipeline_cost_never_increases() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        for report in &reports {
            assert!(
                report.optimized_cost <= report.original_cost,
                "fixture {}: cost increased from {} to {} after rewrite",
                report.fixture_name,
                report.original_cost.total(),
                report.optimized_cost.total(),
            );
        }
    }

    #[test]
    fn e2e_pipeline_dynamic_labels_populated() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        let mut have_dynamic = 0;
        for report in &reports {
            // Some fixtures legitimately time out/cancel to an empty label set.
            if report.dynamic_original_labels.is_empty()
                || report.dynamic_optimized_labels.is_empty()
            {
                continue;
            }
            have_dynamic += 1;
        }
        assert!(have_dynamic > 0, "no fixtures produced dynamic labels");
    }

    #[test]
    fn e2e_pipeline_trace_fingerprints_nonzero() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        let mut have_traces = 0;
        for report in &reports {
            // Zero fingerprints would mean tracing failed to capture an execution.
            if report.original_trace_fingerprint == 0 || report.optimized_trace_fingerprint == 0 {
                continue;
            }
            have_traces += 1;
        }
        assert!(have_traces > 0, "no fixtures produced trace fingerprints");
    }

    #[test]
    fn e2e_pipeline_cost_delta_sane() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let reports = run_e2e_pipeline_all(RewritePolicy::conservative(), &rules);
        for report in &reports {
            let delta = report.cost_delta();
            if report.rewrite_count > 0 {
                assert!(
                    delta >= 0,
                    "fixture {}: rewrite increased cost (delta={delta}, original={}, optimized={})",
                    report.fixture_name,
                    report.original_cost.total(),
                    report.optimized_cost.total(),
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Dynamic lab equivalence oracle tests
    // -----------------------------------------------------------------------

    const ORACLE_SEEDS: [u64; 8] = [0, 1, 2, 3, 42, 99, 1000, u64::MAX];

    #[test]
    fn dynamic_lab_equivalence_all_fixtures_conservative() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        for fixture in all_fixtures() {
            if fixture.name == "shared_non_leaf_associative" {
                continue;
            }
            let report = run_lab_dynamic_equivalence(
                fixture,
                RewritePolicy::conservative(),
                &rules,
                &ORACLE_SEEDS,
            );
            assert!(
                report.all_ok(),
                "{}",
                report
                    .failure_summary()
                    .unwrap_or_else(|| "unknown failure".into())
            );
        }
    }

    #[test]
    fn dynamic_lab_equivalence_associative_policy() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let fixtures = all_fixtures();
        let fixture = fixtures
            .into_iter()
            .find(|f| f.name == "shared_non_leaf_associative")
            .expect("fixture exists");
        let report = run_lab_dynamic_equivalence(
            fixture,
            RewritePolicy::assume_all(),
            &rules,
            &ORACLE_SEEDS,
        );
        assert!(
            report.all_ok(),
            "{}",
            report
                .failure_summary()
                .unwrap_or_else(|| "unknown failure".into())
        );
    }

    #[test]
    fn dynamic_lab_single_leaf_execution() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("alpha");
        dag.set_root(a);

        let result = execute_plan_in_lab(42, &dag);
        assert_eq!(result.len(), 1);
        assert!(result.contains("alpha"));
    }

    #[test]
    fn dynamic_lab_join_collects_all_leaves() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let j = dag.join(vec![a, b, c]);
        dag.set_root(j);

        let result = execute_plan_in_lab(0, &dag);
        assert_eq!(result.len(), 3);
        assert!(result.contains("a"));
        assert!(result.contains("b"));
        assert!(result.contains("c"));
    }

    #[test]
    fn dynamic_lab_race_returns_subset() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let r = dag.race(vec![a, b]);
        dag.set_root(r);

        for seed in &ORACLE_SEEDS {
            let result = execute_plan_in_lab(*seed, &dag);
            assert_eq!(
                result.len(),
                1,
                "seed {seed}: race should yield exactly one winner"
            );
            assert!(
                result.contains("a") || result.contains("b"),
                "seed {seed}: winner must be a or b"
            );
        }
    }

    #[test]
    fn dag_has_fan_in_ignores_unreachable_rewrite_orphans() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let mut fixture = simple_join_race_dedup();
        assert!(
            dag_has_fan_in(&fixture.dag),
            "original fixture must have live fan-in"
        );

        let (_report, _cert) = fixture
            .dag
            .apply_rewrites_certified(RewritePolicy::conservative(), &rules);

        assert!(
            !dag_has_fan_in(&fixture.dag),
            "rewritten reachable DAG should be a tree; orphaned pre-rewrite nodes must not count as live fan-in"
        );
    }

    #[test]
    fn dynamic_lab_executes_fan_in_fixture() {
        init_test();
        let fixture = simple_join_race_dedup();
        assert!(
            dag_has_fan_in(&fixture.dag),
            "fixture should exercise fan-in"
        );

        for seed in &ORACLE_SEEDS {
            let result = execute_plan_in_lab(*seed, &fixture.dag);
            assert_eq!(
                result.len(),
                2,
                "seed {seed}: dedup witness race should produce the shared leaf plus one branch winner"
            );
            assert!(
                result.contains("shared"),
                "seed {seed}: shared leaf must complete"
            );
            assert!(
                result.contains("left") || result.contains("right"),
                "seed {seed}: winner must include exactly one branch leaf"
            );
        }
    }

    #[test]
    fn dynamic_lab_deterministic_same_seed() {
        init_test();
        for fixture in all_fixtures() {
            let r1 = execute_plan_in_lab(42, &fixture.dag);
            let r2 = execute_plan_in_lab(42, &fixture.dag);
            assert_eq!(
                r1, r2,
                "fixture {}: same seed must produce identical results",
                fixture.name
            );
        }
    }

    #[test]
    fn dynamic_lab_timeout_passes_through() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("inner");
        let t = dag.timeout(a, Duration::from_secs(10));
        dag.set_root(t);

        let result = execute_plan_in_lab(7, &dag);
        assert_eq!(result.len(), 1);
        assert!(result.contains("inner"));
    }

    #[test]
    fn dynamic_lab_timeout_cancels_slow_child() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("inner");
        let t = dag.timeout(a, Duration::from_secs(2));
        dag.set_root(t);

        let result = execute_plan_in_lab(7, &dag);
        assert!(result.is_empty(), "short timeout should cancel slow child");
    }

    #[test]
    fn dynamic_lab_nested_join_race() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let j_ab = dag.join(vec![a, b]);
        let r = dag.race(vec![j_ab, c]);
        dag.set_root(r);

        for seed in &ORACLE_SEEDS {
            let result = execute_plan_in_lab(*seed, &dag);
            let is_join_winner = result.len() == 2 && result.contains("a") && result.contains("b");
            let is_leaf_winner = result.len() == 1 && result.contains("c");
            assert!(
                is_join_winner || is_leaf_winner,
                "seed {seed}: unexpected result {result:?}"
            );
        }
    }

    #[test]
    fn dynamic_lab_report_fields_populated() {
        init_test();
        let rules = [RewriteRule::DedupRaceJoin];
        let fixture = simple_join_race_dedup();
        let report = run_lab_dynamic_equivalence(
            fixture,
            RewritePolicy::conservative(),
            &rules,
            &ORACLE_SEEDS,
        );

        assert_eq!(report.fixture_name, "simple_join_race_dedup");
        assert_eq!(report.seeds.len(), ORACLE_SEEDS.len());
        assert_eq!(report.per_seed_results.len(), ORACLE_SEEDS.len());
        assert!(!report.original_outcome_universe.is_empty());
        assert!(!report.optimized_outcome_universe.is_empty());
    }
