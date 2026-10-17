    use super::*;
    use crate::atp::manifest::{CompressionAlgorithm, ObjectKind};

    #[test]
    fn test_compression_metadata_validation() {
        let metadata = CompressionMetadata {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            original_size: 1000,
            compressed_size: 600,
            compression_ratio: 0.6,
        };

        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 100,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        assert!(
            CompressionValidator::validate_compression_metadata(&metadata, &policy, None).is_ok()
        );
    }

    #[test]
    fn test_compression_metadata_algorithm_mismatch() {
        let metadata = CompressionMetadata {
            algorithm: CompressionAlgorithm::Gzip, // Different from policy
            level: 1,
            original_size: 1000,
            compressed_size: 600,
            compression_ratio: 0.6,
        };

        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 100,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        assert!(matches!(
            CompressionValidator::validate_compression_metadata(&metadata, &policy, None),
            Err(CompressionError::PolicyViolation(_))
        ));
    }

    #[test]
    fn test_compression_metadata_rejects_zero_size() {
        let metadata = CompressionMetadata {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            original_size: 0,
            compressed_size: 0,
            compression_ratio: f32::NAN,
        };

        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 0,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        assert!(matches!(
            CompressionValidator::validate_compression_metadata(&metadata, &policy, None),
            Err(CompressionError::PolicyViolation(_))
        ));
    }

    #[test]
    fn test_compression_bomb_detection() {
        // Normal compression - should pass
        assert!(CompressionValidator::validate_compression_bomb_protection(1000, 600, 2.0).is_ok());

        // Suspicious compression ratio - should fail
        assert!(matches!(
            CompressionValidator::validate_compression_bomb_protection(1000000, 100, 2.0),
            Err(CompressionError::CompressionBomb)
        ));

        // Expansion beyond allowed ratio - should fail
        assert!(matches!(
            CompressionValidator::validate_compression_bomb_protection(1000, 3000, 2.0),
            Err(CompressionError::CompressionBomb)
        ));
    }

    #[test]
    fn test_transform_order_validation() {
        use crate::atp::manifest::{PrivacyLevel, VerificationBoundary, VerificationLevel};

        let valid_order = TransformOrder {
            transforms: vec![
                TransformType::Chunking,
                TransformType::Compression,
                TransformType::Encryption,
            ],
            hash_point: HashPoint::PostCompression,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::ContentHash,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::MetadataVisible,
            },
        };

        assert!(
            CompressionValidator::validate_transform_order_position(&valid_order, true).is_ok()
        );

        // Invalid order: compression before chunking
        let invalid_order = TransformOrder {
            transforms: vec![TransformType::Compression, TransformType::Chunking],
            hash_point: HashPoint::PostCompression,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::ContentHash,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::MetadataVisible,
            },
        };

        assert!(matches!(
            CompressionValidator::validate_transform_order_position(&invalid_order, true),
            Err(CompressionError::TransformOrderViolation(_))
        ));
    }
