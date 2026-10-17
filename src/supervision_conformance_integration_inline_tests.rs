    use super::supervision_conformance_tests::SupervisionConformanceHarness;

    #[test]
    fn supervision_conformance_suite() {
        crate::test_utils::init_test_logging();

        let harness = SupervisionConformanceHarness::new();

        // Run the full conformance test suite
        let report = harness.run_all_tests();

        let mut failures = Vec::new();
        let mut passes = 0;

        for result in report.results {
            if result.passed {
                passes += 1;
            } else {
                let reason = result
                    .error_message
                    .unwrap_or_else(|| "no failure reason reported".to_string());
                failures.push(format!("{}: {}", result.name, reason));
            }
        }

        assert!(
            failures.is_empty(),
            "Supervision conformance failures:\n{}",
            failures.join("\n")
        );

        assert!(
            passes > 0,
            "No conformance tests passed - harness may be broken"
        );

        crate::test_complete!("supervision_conformance_suite");
    }
