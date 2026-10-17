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
        let mut harness = LeakCheckConformanceHarness::new();
        harness.run_all();

        // Should have results for all test cases
        assert_eq!(harness.results.len(), 10);

        // Generate matrix (should not panic)
        let matrix = harness.compliance_matrix();
        assert!(matrix.contains("Static Leak Checker Conformance Matrix"));

        // Should categorize by requirement level
        let must_count = harness
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must)
            .count();
        assert!(must_count >= 7); // We have several MUST requirements
    }

    #[test]
    fn individual_leak_test_runs() {
        // Verify each test function can run independently
        let result = test_unmatched_reserve_detection();
        assert!(result.requirement_id == "LEAK-001");

        let result = test_matched_reserve_commit_clean();
        assert!(result.requirement_id == "LEAK-002");

        // Should all have confidence > 0
        assert!(result.confidence > 0.0);
    }
