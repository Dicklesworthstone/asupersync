    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn conformance_harness_runs_all_tests() {
        let mut harness = EProcessConformanceHarness::new();
        harness.run_all();

        // Should have results for all test cases
        assert_eq!(harness.results.len(), 8);

        // Generate matrix (should not panic)
        let matrix = harness.compliance_matrix();
        assert!(matrix.contains("E-Process Martingale Conformance Matrix"));

        // Should categorize by requirement level
        let must_count = harness
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must)
            .count();
        assert!(must_count >= 4); // We have several MUST requirements
    }

    #[test]
    fn individual_mathematical_test_runs() {
        // Verify each test function can run independently
        let result = test_likelihood_ratio_expectation();
        assert!(result.requirement_id == "MART-001");

        let result = test_ville_inequality_bound();
        assert!(result.requirement_id == "MART-003");

        // Should all have confidence > 0
        assert!(result.confidence > 0.0);
    }
