    use super::epoll_conformance_tests::*;

    #[test]
    fn run_epoll_conformance_suite() {
        let harness = EpollConformanceHarness::new();
        let context = TestContext::default();
        let report = harness.run_all(&context);

        // Generate detailed compliance report
        let compliance_matrix = report.generate_matrix();
        println!("\nEpoll Conformance Report:\n{}", compliance_matrix);

        // Verify critical requirements pass
        let must_failures: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must && !matches!(r.status, TestStatus::Pass))
            .collect();

        assert!(
            must_failures.is_empty(),
            "Critical conformance failures: {:#?}",
            must_failures
        );

        let passed = report
            .results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Pass))
            .count();
        let pass_rate = passed as f64 / report.results.len().max(1) as f64;
        println!("Overall pass rate: {:.1}%", pass_rate * 100.0);
        assert!(
            pass_rate >= 0.95,
            "Conformance pass rate below 95%: {:.1}%",
            pass_rate * 100.0
        );
    }
