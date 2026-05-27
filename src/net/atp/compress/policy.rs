//! Compression policy enforcement and validation for ATP-C4.
//!
//! This module implements policy-driven compression decisions that respect
//! the verification transparency requirements of ATP-C4. Policies can disable
//! compression per object type or path without affecting verification semantics.

use super::CompressionError;
use crate::atp::manifest::{CompressionAlgorithm, CompressionPolicy, ObjectKind};

/// Policy-driven compression decision engine.
pub struct CompressionPolicyEngine;

impl CompressionPolicyEngine {
    /// Create a default compression policy for standard ATP usage.
    pub fn default_policy() -> CompressionPolicy {
        CompressionPolicy {
            algorithm: CompressionAlgorithm::Lz4,
            level: 1,
            min_size_threshold: 1024, // 1KB minimum
            apply_to_kinds: vec![ObjectKind::FileObject, ObjectKind::ContentAddressedBlob],
        }
    }

    /// Create a disabled compression policy (no compression).
    pub fn disabled_policy() -> CompressionPolicy {
        CompressionPolicy {
            algorithm: CompressionAlgorithm::None,
            level: 0,
            min_size_threshold: u64::MAX,
            apply_to_kinds: vec![],
        }
    }

    /// Create a policy for bulk data transfers (high compression).
    pub fn bulk_transfer_policy() -> CompressionPolicy {
        CompressionPolicy {
            algorithm: CompressionAlgorithm::Gzip,
            level: 6,
            min_size_threshold: 4096, // 4KB minimum
            apply_to_kinds: vec![
                ObjectKind::FileObject,
                ObjectKind::ContentAddressedBlob,
                ObjectKind::StreamObject,
            ],
        }
    }

    /// Validate compression policy for ATP-C4 compliance.
    pub fn validate_policy(policy: &CompressionPolicy) -> Result<(), CompressionError> {
        // Validate compression level ranges
        match policy.algorithm {
            CompressionAlgorithm::None => {
                if policy.level != 0 {
                    return Err(CompressionError::PolicyViolation(
                        "none algorithm must have level 0".to_string(),
                    ));
                }
            }
            CompressionAlgorithm::Lz4 => {
                // LZ4 typically doesn't use levels, but we accept any value
            }
            CompressionAlgorithm::Gzip => {
                if policy.level > 9 {
                    return Err(CompressionError::PolicyViolation(
                        "gzip level must be 0-9".to_string(),
                    ));
                }
            }
            CompressionAlgorithm::Brotli => {
                if policy.level > 11 {
                    return Err(CompressionError::PolicyViolation(
                        "brotli level must be 0-11".to_string(),
                    ));
                }
            }
        }

        // Validate size threshold is reasonable
        if policy.min_size_threshold > 1_000_000 {
            return Err(CompressionError::PolicyViolation(
                "min_size_threshold too large (>1MB)".to_string(),
            ));
        }

        // Validate object kinds are not contradictory
        if matches!(policy.algorithm, CompressionAlgorithm::None)
            && !policy.apply_to_kinds.is_empty()
        {
            return Err(CompressionError::PolicyViolation(
                "none algorithm should have empty apply_to_kinds".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if compression should be applied for a given object and size.
    pub fn should_compress(
        policy: &CompressionPolicy,
        object_kind: ObjectKind,
        object_size: u64,
    ) -> bool {
        // Never compress if algorithm is None
        if matches!(policy.algorithm, CompressionAlgorithm::None) {
            return false;
        }

        // Check if object kind is allowed
        if !policy.apply_to_kinds.contains(&object_kind) {
            return false;
        }

        // Check size threshold
        object_size >= policy.min_size_threshold
    }

    /// Estimate compression ratio for policy planning.
    pub fn estimate_compression_ratio(algorithm: CompressionAlgorithm, level: u8) -> f32 {
        match algorithm {
            CompressionAlgorithm::None => 1.0,
            CompressionAlgorithm::Lz4 => 0.6, // ~40% compression typically
            CompressionAlgorithm::Gzip => match level {
                0..=2 => 0.7, // Fast compression
                3..=6 => 0.5, // Balanced
                7..=9 => 0.4, // High compression
                _ => 0.5,
            },
            CompressionAlgorithm::Brotli => match level {
                0..=3 => 0.6,  // Fast
                4..=7 => 0.4,  // Balanced
                8..=11 => 0.3, // High compression
                _ => 0.4,
            },
        }
    }
}

#[cfg(test)]
mod tests {
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
}
