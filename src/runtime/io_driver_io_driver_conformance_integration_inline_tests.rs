    use super::io_driver_conformance_tests::*;

    #[test]
    fn run_io_driver_conformance_suite() {
        let harness = IoDriverConformanceHarness::new();
        let report = harness.run_all_tests();

        // Generate detailed compliance report
        let _compliance_matrix = report.generate_compliance_matrix();
        // IoDriver Event Loop Conformance Report generated

        // Verify critical requirements pass
        let must_failures: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must && !r.passed)
            .collect();

        assert!(
            must_failures.is_empty(),
            "Critical event loop conformance failures: {:#?}",
            must_failures
        );

        let must_pass_rate = report.must_pass_rate();
        let overall_pass_rate = report.pass_rate();

        // MUST requirements and overall pass rate calculated

        // Event loop conformance requires 100% MUST pass rate
        assert!(
            must_pass_rate >= 1.0,
            "Event loop MUST requirements below 100%: {:.1}%",
            must_pass_rate * 100.0
        );
        assert!(
            overall_pass_rate >= 0.85,
            "Overall pass rate below 85%: {:.1}%",
            overall_pass_rate * 100.0
        );
    }
