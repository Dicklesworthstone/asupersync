    use super::registration_conformance_tests::*;

    #[test]
    fn run_registration_conformance_suite() {
        let harness = RegistrationConformanceHarness::new();
        let report = harness.run_all_tests();

        // Generate detailed compliance report
        let compliance_matrix = report.generate_compliance_matrix();
        println!(
            "\nRegistration RAII Conformance Report:\n{}",
            compliance_matrix
        );

        // Verify critical requirements pass
        let must_failures: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must && !r.passed)
            .collect();

        assert!(
            must_failures.is_empty(),
            "Critical RAII conformance failures: {:#?}",
            must_failures
        );

        let must_pass_rate = report.must_pass_rate();
        let overall_pass_rate = report.pass_rate();

        println!(
            "MUST requirements pass rate: {:.1}%",
            must_pass_rate * 100.0
        );
        println!("Overall pass rate: {:.1}%", overall_pass_rate * 100.0);

        // RAII conformance requires 100% MUST pass rate
        assert!(
            must_pass_rate >= 1.0,
            "RAII MUST requirements below 100%: {:.1}%",
            must_pass_rate * 100.0
        );
        assert!(
            overall_pass_rate >= 0.90,
            "Overall pass rate below 90%: {:.1}%",
            overall_pass_rate * 100.0
        );
    }
