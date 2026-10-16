    use super::gen_server_conformance_tests::{GenServerConformanceHarness, TestVerdict};

    #[test]
    fn gen_server_conformance_suite() {
        crate::test_utils::init_test_logging();

        let mut harness = GenServerConformanceHarness::new();

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
            "GenServer conformance failures:\n{}",
            failures.join("\n")
        );

        assert!(
            passes > 0,
            "No conformance tests passed - harness may be broken"
        );

        crate::test_complete!("gen_server_conformance_suite");
    }
