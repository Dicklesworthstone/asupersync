    use super::*;

    #[test]
    fn benchmark_config_smoke_test_is_fast() {
        let config = BenchmarkConfig::smoke_test();
        assert_eq!(config.data_size, 64 * 1024);
        assert_eq!(config.iterations, 1);
        assert!(config.timeout <= Duration::from_secs(30));
    }

    #[test]
    fn benchmark_config_stress_test_is_thorough() {
        let config = BenchmarkConfig::stress_test();
        assert!(config.data_size >= 1024 * 1024 * 1024);
        assert!(config.iterations >= 5);
        assert!(config.preserve_artifacts);
    }

    #[test]
    fn benchmark_environment_collection_succeeds() {
        let env = BenchmarkEnvironment::collect().unwrap();
        assert!(!env.os_info.is_empty());
        assert!(!env.cpu_info.is_empty());
        assert!(env.timestamp <= chrono::Utc::now());
    }
