//! Compression validation and proof support for ATP-C4.
//!
//! This module implements validation logic that ensures compression
//! transforms preserve verification semantics and comply with ATP-C4
//! transform proof policies.

use super::CompressionError;
use crate::atp::manifest::{
    CompressionMetadata, CompressionPolicy, HashPoint, TransformOrder, TransformProofPolicy,
    TransformType,
};

/// Compression validation engine.
pub struct CompressionValidator;

impl CompressionValidator {
    /// Validate compression metadata against policy.
    pub fn validate_compression_metadata(
        metadata: &CompressionMetadata,
        policy: &CompressionPolicy,
        proof_policy: Option<&TransformProofPolicy>,
    ) -> Result<(), CompressionError> {
        // Check algorithm consistency
        if metadata.algorithm != policy.algorithm {
            return Err(CompressionError::PolicyViolation(
                "compression metadata algorithm doesn't match policy".to_string(),
            ));
        }

        // Check level consistency
        if metadata.level != policy.level {
            return Err(CompressionError::PolicyViolation(
                "compression metadata level doesn't match policy".to_string(),
            ));
        }

        // Validate compression ratio bounds
        if metadata.compression_ratio <= 0.0 || metadata.compression_ratio > 1.5 {
            return Err(CompressionError::PolicyViolation(
                "invalid compression ratio".to_string(),
            ));
        }

        // Check size consistency
        let computed_ratio = metadata.compressed_size as f32 / metadata.original_size as f32;
        let ratio_diff = (computed_ratio - metadata.compression_ratio).abs();
        if ratio_diff > 0.01 {
            return Err(CompressionError::PolicyViolation(
                "compression ratio doesn't match computed ratio".to_string(),
            ));
        }

        // Validate against proof policy if present
        if let Some(proof) = proof_policy {
            Self::validate_against_proof_policy(metadata, proof)?;
        }

        Ok(())
    }

    /// Validate compression metadata against transform proof policy.
    fn validate_against_proof_policy(
        metadata: &CompressionMetadata,
        proof_policy: &TransformProofPolicy,
    ) -> Result<(), CompressionError> {
        // Check lossy transforms
        let is_potentially_lossy = Self::is_potentially_lossy_algorithm(metadata.algorithm);
        if is_potentially_lossy && !proof_policy.allow_lossy_transforms {
            return Err(CompressionError::PolicyViolation(
                "lossy compression algorithm not allowed by proof policy".to_string(),
            ));
        }

        // Check compression ratio bounds
        if let Some(max_ratio) = proof_policy.max_compression_ratio {
            if metadata.compression_ratio > max_ratio {
                return Err(CompressionError::PolicyViolation(
                    "compression ratio exceeds policy maximum".to_string(),
                ));
            }
        }

        // Validate deterministic requirements
        if proof_policy.require_deterministic_transforms {
            Self::validate_deterministic_compression(metadata)?;
        }

        Ok(())
    }

    /// Check if compression algorithm is potentially lossy.
    fn is_potentially_lossy_algorithm(
        algorithm: crate::atp::manifest::CompressionAlgorithm,
    ) -> bool {
        use crate::atp::manifest::CompressionAlgorithm;

        // Currently all our implemented algorithms are lossless
        // This would change if we added lossy algorithms like JPEG compression
        match algorithm {
            CompressionAlgorithm::None => false,
            CompressionAlgorithm::Lz4 => false,
            CompressionAlgorithm::Gzip => false,
            CompressionAlgorithm::Brotli => false,
        }
    }

    /// Validate that compression is deterministic for proof strength.
    fn validate_deterministic_compression(
        metadata: &CompressionMetadata,
    ) -> Result<(), CompressionError> {
        use crate::atp::manifest::CompressionAlgorithm;

        // Check if algorithm produces deterministic output
        let is_deterministic = match metadata.algorithm {
            CompressionAlgorithm::None => true,
            CompressionAlgorithm::Lz4 => true, // LZ4 is deterministic
            CompressionAlgorithm::Gzip => true, // Gzip is deterministic at same level
            CompressionAlgorithm::Brotli => true, // Brotli is deterministic at same level
        };

        if !is_deterministic {
            return Err(CompressionError::PolicyViolation(
                "non-deterministic compression algorithm used".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate transform order for compression position.
    pub fn validate_transform_order_position(
        transform_order: &TransformOrder,
        has_compression: bool,
    ) -> Result<(), CompressionError> {
        let compression_in_order = transform_order
            .transforms
            .contains(&TransformType::Compression);

        // Check consistency
        if has_compression != compression_in_order {
            return Err(CompressionError::TransformOrderViolation(
                "compression presence doesn't match transform order".to_string(),
            ));
        }

        if !has_compression {
            return Ok(()); // No compression, nothing to validate
        }

        let compression_pos = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Compression)
            .unwrap();

        // Compression should come after chunking if present
        if let Some(chunking_pos) = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Chunking)
        {
            if compression_pos <= chunking_pos {
                return Err(CompressionError::TransformOrderViolation(
                    "compression must come after chunking".to_string(),
                ));
            }
        }

        // Compression should come before encryption if present
        if let Some(encryption_pos) = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Encryption)
        {
            if compression_pos >= encryption_pos {
                return Err(CompressionError::TransformOrderViolation(
                    "compression must come before encryption".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate hash point consistency with compression.
    pub fn validate_hash_point_consistency(
        transform_order: &TransformOrder,
        has_compression: bool,
    ) -> Result<(), CompressionError> {
        if !has_compression {
            // If no compression, post-compression hash point is invalid
            if matches!(transform_order.hash_point, HashPoint::PostCompression) {
                return Err(CompressionError::TransformOrderViolation(
                    "post-compression hash point without compression".to_string(),
                ));
            }
            return Ok(());
        }

        // If compression is present, validate hash point makes sense
        match transform_order.hash_point {
            HashPoint::Plaintext => Ok(()),
            HashPoint::PostCompression => Ok(()),
            HashPoint::Ciphertext => {
                // Valid if encryption comes after compression
                let has_encryption = transform_order
                    .transforms
                    .contains(&TransformType::Encryption);
                if !has_encryption {
                    return Err(CompressionError::TransformOrderViolation(
                        "ciphertext hash point without encryption".to_string(),
                    ));
                }
                Ok(())
            }
            HashPoint::MultiPoint => Ok(()), // Always valid
        }
    }

    /// Validate compression bomb protection.
    pub fn validate_compression_bomb_protection(
        original_size: u64,
        compressed_size: u64,
        max_expansion_ratio: f32,
    ) -> Result<(), CompressionError> {
        if compressed_size > original_size {
            let expansion_ratio = compressed_size as f32 / original_size as f32;
            if expansion_ratio > max_expansion_ratio {
                return Err(CompressionError::CompressionBomb);
            }
        }

        // Also check for suspiciously good compression ratios
        if original_size > 0 {
            let compression_ratio = compressed_size as f32 / original_size as f32;
            if compression_ratio < 0.001 {
                // Better than 1000:1 compression is suspicious
                return Err(CompressionError::CompressionBomb);
            }
        }

        Ok(())
    }
}

/// Compression proof builder for ATP-C4 verification.
pub struct CompressionProofBuilder;

impl CompressionProofBuilder {
    /// Build proof data for compression transform.
    pub fn build_compression_proof(
        original_hash: [u8; 32],
        compressed_hash: [u8; 32],
        metadata: &CompressionMetadata,
        policy: &CompressionPolicy,
    ) -> CompressionProof {
        CompressionProof {
            original_hash,
            compressed_hash,
            algorithm: metadata.algorithm,
            level: metadata.level,
            original_size: metadata.original_size,
            compressed_size: metadata.compressed_size,
            compression_ratio: metadata.compression_ratio,
            policy_hash: Self::compute_policy_hash(policy),
        }
    }

    /// Compute hash of compression policy for proof binding.
    fn compute_policy_hash(policy: &CompressionPolicy) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        hasher.update([policy.algorithm as u8]);
        hasher.update([policy.level]);
        hasher.update(policy.min_size_threshold.to_be_bytes());

        for kind in &policy.apply_to_kinds {
            hasher.update([*kind as u8]);
        }

        hasher.finalize().into()
    }
}

/// Compression proof structure for ATP-C4 verification.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionProof {
    /// Hash of original uncompressed data.
    pub original_hash: [u8; 32],
    /// Hash of compressed data.
    pub compressed_hash: [u8; 32],
    /// Compression algorithm used.
    pub algorithm: crate::atp::manifest::CompressionAlgorithm,
    /// Compression level used.
    pub level: u8,
    /// Original data size.
    pub original_size: u64,
    /// Compressed data size.
    pub compressed_size: u64,
    /// Achieved compression ratio.
    pub compression_ratio: f32,
    /// Hash of compression policy.
    pub policy_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
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
}
