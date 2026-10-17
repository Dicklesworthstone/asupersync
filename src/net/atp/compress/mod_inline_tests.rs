    use super::*;

    #[test]
    fn test_lz4_compression_roundtrip() {
        let test_data =
            b"Hello, world! This is a test string for compression. compression compression";
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 10,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let result =
            CompressionEngine::compress(test_data, ObjectKind::FileObject, &policy, None).unwrap();

        assert_eq!(result.metadata.algorithm, CompressionAlgorithm::Lz4);
        assert_eq!(result.metadata.original_size, test_data.len() as u64);
        assert!(result.metadata.compression_ratio <= 1.0);

        let decompressed =
            CompressionEngine::decompress(&result.compressed_data, &result.metadata).unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn test_brotli_compression_roundtrip() {
        let test_data = b"ATP metadata compresses well when repeated: manifest manifest manifest chunk chunk chunk object object object";
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Brotli,
            level: 6,
            min_size_threshold: 10,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let result =
            CompressionEngine::compress(test_data, ObjectKind::FileObject, &policy, None).unwrap();

        assert_eq!(result.metadata.algorithm, CompressionAlgorithm::Brotli);
        assert_eq!(result.metadata.original_size, test_data.len() as u64);
        assert_eq!(
            result.metadata.compressed_size,
            result.compressed_data.len() as u64
        );

        let decompressed =
            CompressionEngine::decompress(&result.compressed_data, &result.metadata).unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn test_brotli_reports_unsupported_without_feature() {
        let test_data = b"ATP metadata compresses well when repeated: manifest manifest manifest";
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Brotli,
            level: 6,
            min_size_threshold: 10,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let result = CompressionEngine::compress(test_data, ObjectKind::FileObject, &policy, None);

        assert!(matches!(
            result,
            Err(CompressionError::UnsupportedAlgorithm(
                CompressionAlgorithm::Brotli
            ))
        ));
    }

    #[test]
    fn test_compression_disabled_for_wrong_object_kind() {
        let test_data = b"Hello, world!";
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 10,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let result = CompressionEngine::compress(
            test_data,
            ObjectKind::Directory, // Not in apply_to_kinds
            &policy,
            None,
        );

        assert!(matches!(result, Err(CompressionError::PolicyViolation(_))));
    }

    #[test]
    fn test_size_threshold_enforcement() {
        let test_data = b"Hi"; // Too small
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 100,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let result = CompressionEngine::compress(test_data, ObjectKind::FileObject, &policy, None);

        assert!(matches!(
            result,
            Err(CompressionError::SizeThresholdViolation)
        ));
    }

    #[test]
    fn test_empty_payload_rejected_even_with_zero_threshold() {
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 0,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        let result = CompressionEngine::compress(b"", ObjectKind::FileObject, &policy, None);

        assert!(matches!(
            result,
            Err(CompressionError::SizeThresholdViolation)
        ));
    }

    #[test]
    fn test_decompression_rejects_metadata_size_mismatch_before_decode() {
        let test_data = vec![b'a'; 2048];
        let compressed_data = lz4_flex::compress_prepend_size(&test_data);
        let metadata = CompressionMetadata {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            original_size: test_data.len() as u64,
            compressed_size: compressed_data.len() as u64 + 1,
            compression_ratio: compressed_data.len() as f32 / test_data.len() as f32,
        };

        let result = CompressionEngine::decompress(&compressed_data, &metadata);

        assert!(matches!(result, Err(CompressionError::PolicyViolation(_))));
    }

    #[test]
    fn test_decompression_rejects_suspicious_metadata_before_decode() {
        let compressed_data = vec![0_u8; 4];
        let original_size = 1_000_000_000_u64;
        let metadata = CompressionMetadata {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            original_size,
            compressed_size: compressed_data.len() as u64,
            compression_ratio: compressed_data.len() as f32 / original_size as f32,
        };

        let result = CompressionEngine::decompress(&compressed_data, &metadata);

        assert!(matches!(result, Err(CompressionError::CompressionBomb)));
    }

    #[test]
    fn test_transform_order_validation() {
        use crate::atp::manifest::{
            HashPoint, PrivacyLevel, TransformOrder, TransformType, VerificationBoundary,
            VerificationLevel,
        };

        let test_data = b"Hello, world! This is a test string for compression.";
        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 10,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };

        // Valid order: Chunking -> Compression -> Encryption
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

        let result = CompressionEngine::compress(
            test_data,
            ObjectKind::FileObject,
            &policy,
            Some(&valid_order),
        );
        assert!(result.is_ok());

        // Invalid order: Compression before Chunking
        let invalid_order = TransformOrder {
            transforms: vec![
                TransformType::Compression,
                TransformType::Chunking,
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

        let result = CompressionEngine::compress(
            test_data,
            ObjectKind::FileObject,
            &policy,
            Some(&invalid_order),
        );
        assert!(matches!(
            result,
            Err(CompressionError::TransformOrderViolation(_))
        ));
    }

    #[test]
    fn test_transform_order_must_include_compression_when_applied() {
        use crate::atp::manifest::{
            HashPoint, PrivacyLevel, TransformOrder, TransformType, VerificationBoundary,
            VerificationLevel,
        };

        let policy = CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 10,
            apply_to_kinds: vec![ObjectKind::FileObject],
        };
        let missing_compression = TransformOrder {
            transforms: vec![TransformType::Chunking, TransformType::Encryption],
            hash_point: HashPoint::PostCompression,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::ContentHash,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::MetadataVisible,
            },
        };

        let result = CompressionEngine::compress(
            b"Hello, world! This is a test string for compression.",
            ObjectKind::FileObject,
            &policy,
            Some(&missing_compression),
        );

        assert!(matches!(
            result,
            Err(CompressionError::TransformOrderViolation(_))
        ));
    }
