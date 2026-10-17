    use super::monitor_conformance_tests::{MonitorConformanceHarness, TestVerdict};

    #[test]
    fn monitor_conformance_suite() {
        crate::test_utils::init_test_logging();

        let mut harness = MonitorConformanceHarness::new();

        // Run the full conformance test suite
        let results = harness.run_full_suite();

        let mut failures = Vec::new();
        let mut passes = 0;

        for result in results {
            match result.verdict {
                TestVerdict::Pass => {
                    passes += 1;
                }
                TestVerdict::Fail(reason) => {
                    failures.push(format!("{}: {}", result.test_name, reason));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "Monitor conformance failures:\n{}",
            failures.join("\n")
        );

        assert!(
            passes > 0,
            "No conformance tests passed - harness may be broken"
        );

        crate::test_complete!("monitor_conformance_suite");
    }
