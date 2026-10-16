    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::meta::mutation::builtin_mutations;

    #[test]
    fn meta_runner_deterministic() {
        let runner = MetaRunner::new(42);
        let r1 = runner.run(builtin_mutations());
        let r2 = runner.run(builtin_mutations());
        assert_eq!(r1.results().len(), r2.results().len());
        for (a, b) in r1.results().iter().zip(r2.results()) {
            assert_eq!(a.mutation, b.mutation);
            assert_eq!(a.invariant, b.invariant);
            assert_eq!(a.baseline_clean(), b.baseline_clean());
            assert_eq!(a.mutation_detected(), b.mutation_detected());
        }
    }

    #[test]
    fn meta_runner_all_mutations_pass() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let failures = report.failures();
        assert!(
            failures.is_empty(),
            "expected no failures, got: {:?}",
            failures.iter().map(|f| f.mutation).collect::<Vec<_>>()
        );
    }

    #[test]
    fn meta_runner_empty_mutations() {
        let runner = MetaRunner::new(42);
        let report = runner.run(std::iter::empty());
        assert!(report.results().is_empty());
        assert!(report.failures().is_empty());
    }

    #[test]
    fn meta_runner_single_mutation() {
        let runner = MetaRunner::new(42);
        let report = runner.run(vec![BuiltinMutation::TaskLeak]);
        assert_eq!(report.results().len(), 1);
        assert_eq!(report.results()[0].mutation, "mutation_task_leak");
        assert!(report.results()[0].baseline_clean());
        assert!(report.results()[0].mutation_detected());
    }

    #[test]
    fn meta_result_baseline_clean() {
        let result = MetaResult {
            mutation: "test",
            invariant: "test_inv",
            baseline_violations: vec![],
            mutation_violations: vec![],
        };
        assert!(result.baseline_clean());
    }

    #[test]
    fn meta_coverage_report_entries() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        assert_eq!(
            report.coverage().entries().len(),
            ALL_ORACLE_INVARIANTS.len()
        );
    }

    #[test]
    fn meta_coverage_missing_invariants() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let missing = report.coverage().missing_invariants();
        assert!(
            !missing.contains(&"actor_leak"),
            "actor_leak should be covered"
        );
        assert!(
            !missing.contains(&"supervision"),
            "supervision should be covered"
        );
        assert!(!missing.contains(&"mailbox"), "mailbox should be covered");
    }

    #[test]
    fn meta_coverage_entry_is_covered() {
        let covered = MetaCoverageEntry {
            invariant: "test",
            tests: vec!["m1"],
        };
        assert!(covered.is_covered());
        let not_covered = MetaCoverageEntry {
            invariant: "test",
            tests: vec![],
        };
        assert!(!not_covered.is_covered());
    }

    #[test]
    fn meta_report_to_text() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let text = report.to_text();
        assert!(text.contains("meta report:"));
        assert!(text.contains("mutations"));
        assert!(text.contains("coverage:"));
    }

    #[test]
    fn meta_report_to_json() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let json = report.to_json();
        assert!(json["summary"]["mutations"].as_u64().unwrap() > 0);
        assert!(json["results"].is_array());
        assert!(json["coverage"].is_object());
    }

    #[test]
    fn meta_coverage_to_text() {
        let runner = MetaRunner::new(42);
        let text = runner.run(builtin_mutations()).coverage().to_text();
        assert!(text.contains("task_leak:"));
    }

    #[test]
    fn meta_coverage_to_json() {
        let runner = MetaRunner::new(42);
        let json = runner.run(builtin_mutations()).coverage().to_json();
        assert!(json["invariants"].is_array());
    }

    #[test]
    fn harness_next_ids_increment() {
        let mut h = MetaHarness::new(42);
        let r1 = h.next_region();
        let r2 = h.next_region();
        assert_ne!(r1, r2);
        let t1 = h.next_task();
        let t2 = h.next_task();
        assert_ne!(t1, t2);
        let f1 = h.next_finalizer();
        let f2 = h.next_finalizer();
        assert_ne!(f1, f2);
    }

    #[test]
    fn harness_now_is_zero() {
        assert_eq!(MetaHarness::new(42).now(), Time::ZERO);
    }

    #[test]
    fn meta_runner_different_seeds() {
        for seed in [0, 1, 999, u64::MAX] {
            let runner = MetaRunner::new(seed);
            let report = runner.run(builtin_mutations());
            let has_failures = report
                .failures()
                .into_iter()
                .any(|f| f.mutation != "mutation_ambient_authority_spawn_without_capability");
            assert!(!has_failures, "seed {seed} produced failures");
        }
    }
