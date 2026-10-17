    use super::*;

    #[test]
    fn test_algorithm_support() {
        assert!(AlgorithmRegistry::is_supported(CompressionAlgorithm::None));
        assert!(AlgorithmRegistry::is_supported(CompressionAlgorithm::Lz4));
        assert!(AlgorithmRegistry::is_supported(CompressionAlgorithm::Gzip));
        assert_eq!(
            AlgorithmRegistry::is_supported(CompressionAlgorithm::Brotli),
            cfg!(feature = "compression")
        );
    }

    #[test]
    fn test_performance_profiles() {
        let lz4_profile = AlgorithmRegistry::performance_profile(CompressionAlgorithm::Lz4);
        assert_eq!(lz4_profile.compression_speed, CompressionSpeed::VeryFast);
        assert_eq!(lz4_profile.cpu_usage, CpuUsage::Low);

        let gzip_profile = AlgorithmRegistry::performance_profile(CompressionAlgorithm::Gzip);
        assert_eq!(gzip_profile.compression_ratio, CompressionRatio::Medium);
    }

    #[test]
    fn test_lz4_adapter() {
        let adapter = Lz4Adapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Lz4);

        assert!(adapter.validate_params(&params).is_ok());

        let test_data = b"Hello, world! This is a test for LZ4 compression.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        let decompressed = adapter
            .decompress(&compressed, &params, test_data.len() as u64)
            .unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    fn test_lz4_adapter_honors_max_output_size() {
        let adapter = Lz4Adapter;
        let mut params = AlgorithmRegistry::default_params(CompressionAlgorithm::Lz4);
        let test_data = b"Hello, world! This is a test for capped LZ4 decompression.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        params.max_output_size = Some(test_data.len() as u64 - 1);

        let result = adapter.decompress(&compressed, &params, test_data.len() as u64);

        assert!(matches!(result, Err(CompressionError::CompressionBomb)));
    }

    #[test]
    fn test_gzip_adapter() {
        let adapter = GzipAdapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Gzip);

        assert!(adapter.validate_params(&params).is_ok());

        let test_data = b"Hello, world! This is a test for Gzip compression.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        let decompressed = adapter
            .decompress(&compressed, &params, test_data.len() as u64)
            .unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    fn test_gzip_adapter_honors_max_output_size() {
        let adapter = GzipAdapter;
        let mut params = AlgorithmRegistry::default_params(CompressionAlgorithm::Gzip);
        let test_data = b"Hello, world! This is a test for capped Gzip decompression.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        params.max_output_size = Some(test_data.len() as u64 - 1);

        let result = adapter.decompress(&compressed, &params, test_data.len() as u64);

        assert!(matches!(result, Err(CompressionError::CompressionBomb)));
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_brotli_adapter() {
        let adapter = BrotliAdapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Brotli);

        assert!(adapter.validate_params(&params).is_ok());

        let test_data =
            b"Hello, world! Brotli benefits from repeated repeated repeated transfer metadata.";
        let compressed = adapter.compress(test_data, &params).unwrap();
        let decompressed = adapter
            .decompress(&compressed, &params, test_data.len() as u64)
            .unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn test_brotli_adapter_reports_unsupported_without_feature() {
        let adapter = BrotliAdapter;
        let params = AlgorithmRegistry::default_params(CompressionAlgorithm::Brotli);

        assert!(matches!(
            adapter.validate_params(&params),
            Err(CompressionError::UnsupportedAlgorithm(
                CompressionAlgorithm::Brotli
            ))
        ));
    }
