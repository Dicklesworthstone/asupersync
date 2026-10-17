    use super::*;

    #[test]
    fn benchmark_suite_creation() {
        let suite = BenchmarkSuite::new("test-suite");
        assert_eq!(suite.name, "test-suite");
        assert!(suite.baseline_adapters.is_empty());
        assert!(suite.atp_profiles.is_empty());
    }

    #[test]
    fn smoke_test_suite_has_basics() {
        let suite = BenchmarkSuite::smoke_test_suite();
        assert_eq!(suite.baseline_adapters.len(), 1);
        assert_eq!(suite.atp_profiles.len(), 2);
    }

    #[test]
    fn comprehensive_suite_has_more_coverage() {
        let suite = BenchmarkSuite::comprehensive_suite();
        assert!(!suite.baseline_adapters.is_empty());
        assert!(!suite.atp_profiles.is_empty());
        assert!(suite.atp_profiles.len() >= 4); // Should have multiple profiles
    }

    #[test]
    fn suite_builder_works() {
        let suite = BenchmarkSuiteBuilder::new("builder-test")
            .with_scp()
            .with_atp_profile(AtpProfile::clean_lan())
            .build();

        assert_eq!(suite.name, "builder-test");
        assert_eq!(suite.baseline_adapters.len(), 1);
        assert_eq!(suite.atp_profiles.len(), 1);
    }

    #[test]
    fn suite_builder_all_atp_profiles() {
        let suite = BenchmarkSuiteBuilder::new("all-atp")
            .with_all_atp_profiles()
            .build();

        assert!(suite.atp_profiles.len() >= 4);
    }
