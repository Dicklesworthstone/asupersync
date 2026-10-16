    use super::*;

    #[test]
    fn test_default_policy_validation() {
        let policy = CompressionPolicyEngine::default_policy();
        assert!(CompressionPolicyEngine::validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_disabled_policy() {
        let policy = CompressionPolicyEngine::disabled_policy();
        assert!(CompressionPolicyEngine::validate_policy(&policy).is_ok());

        // Should never compress with disabled policy
        assert!(!CompressionPolicyEngine::should_compress(
            &policy,
            ObjectKind::FileObject,
            1_000_000,
        ));
    }

    #[test]
    fn test_bulk_transfer_policy() {
        let policy = CompressionPolicyEngine::bulk_transfer_policy();
        assert!(CompressionPolicyEngine::validate_policy(&policy).is_ok());

        // Should compress large files
        assert!(CompressionPolicyEngine::should_compress(
            &policy,
            ObjectKind::FileObject,
            10_000,
        ));

        // Should not compress small files
        assert!(!CompressionPolicyEngine::should_compress(
            &policy,
            ObjectKind::FileObject,
            1000,
        ));
    }

    #[test]
    fn test_policy_validation_errors() {
        // Invalid gzip level
        let bad_policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Gzip,
            level: 15, // Too high
            min_size_threshold: 1024,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        assert!(matches!(
            CompressionPolicyEngine::validate_policy(&bad_policy),
            Err(CompressionError::PolicyViolation(_))
        ));

        // Inconsistent none algorithm
        let inconsistent_policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::None,
            level: 0,
            min_size_threshold: 1024,
            apply_to_kinds: vec![ObjectKind::FileObject], // Shouldn't have kinds for None
        };

        assert!(matches!(
            CompressionPolicyEngine::validate_policy(&inconsistent_policy),
            Err(CompressionError::PolicyViolation(_))
        ));
    }

    #[test]
    fn test_compression_ratio_estimates() {
        assert_eq!(
            CompressionPolicyEngine::estimate_compression_ratio(CompressionAlgorithm::None, 0),
            1.0
        );
        assert_eq!(
            CompressionPolicyEngine::estimate_compression_ratio(CompressionAlgorithm::Lz4, 1),
            0.6
        );
        assert!(
            CompressionPolicyEngine::estimate_compression_ratio(CompressionAlgorithm::Gzip, 9)
                < 0.5
        );
        assert!(
            CompressionPolicyEngine::estimate_compression_ratio(CompressionAlgorithm::Brotli, 11)
                < 0.4
        );
    }
