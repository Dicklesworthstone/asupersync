//! ATP compression module for policy-driven compression with verification transparency.
//!
//! This module implements compression transforms for ATP objects while maintaining
//! clear verification semantics and proof boundaries. Supports optional compression
//! that can be disabled per object type/path without affecting verification truth.
//!
//! Key design principles:
//! - Compression is always optional and configurable
//! - Transform order is explicitly tracked in manifests
//! - Verification boundaries are preserved across transforms
//! - Lossy compression requires explicit policy approval
//! - Compression metadata enables proof reconstruction

use crate::atp::manifest::{
    CompressionAlgorithm, CompressionMetadata, CompressionPolicy, ObjectKind, TransformOrder,
    TransformType,
};
use std::io::{Read, Write};

pub mod algorithms;
pub mod policy;
pub mod validation;

pub use algorithms::*;
pub use policy::*;
pub use validation::*;

const COMPRESSION_RATIO_TOLERANCE: f32 = 0.01;
const DECOMPRESSION_READ_CHUNK_SIZE: usize = 8192;

pub(crate) fn checked_expected_size(expected_size: u64) -> Result<usize, CompressionError> {
    usize::try_from(expected_size).map_err(|_| {
        CompressionError::DecompressionFailed("expected size does not fit usize".to_string())
    })
}

pub(crate) fn checked_expected_size_with_limit(
    expected_size: u64,
    max_output_size: Option<u64>,
) -> Result<usize, CompressionError> {
    if let Some(max_output_size) = max_output_size
        && expected_size > max_output_size
    {
        return Err(CompressionError::CompressionBomb);
    }

    checked_expected_size(expected_size)
}

pub(crate) fn lz4_prepended_size(data: &[u8]) -> Result<usize, CompressionError> {
    let Some(prefix) = data.get(..4) else {
        return Err(CompressionError::DecompressionFailed(
            "missing LZ4 size prefix".to_string(),
        ));
    };

    let mut size_bytes = [0_u8; 4];
    size_bytes.copy_from_slice(prefix);
    usize::try_from(u32::from_le_bytes(size_bytes)).map_err(|_| {
        CompressionError::DecompressionFailed("LZ4 size prefix does not fit usize".to_string())
    })
}

pub(crate) fn read_decompressed_exact<R: Read>(
    reader: &mut R,
    expected_size: usize,
) -> Result<Vec<u8>, CompressionError> {
    let mut decompressed = Vec::with_capacity(expected_size.min(DECOMPRESSION_READ_CHUNK_SIZE));
    let mut buffer = [0_u8; DECOMPRESSION_READ_CHUNK_SIZE];

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
        if read == 0 {
            break;
        }

        let next_len = decompressed.len().checked_add(read).ok_or_else(|| {
            CompressionError::DecompressionFailed("decompressed size overflow".to_string())
        })?;
        if next_len > expected_size {
            return Err(CompressionError::DecompressionFailed(
                "decompressed size mismatch".to_string(),
            ));
        }

        decompressed.extend_from_slice(&buffer[..read]);
    }

    if decompressed.len() != expected_size {
        return Err(CompressionError::DecompressionFailed(
            "decompressed size mismatch".to_string(),
        ));
    }

    Ok(decompressed)
}

/// Compression result with metadata for verification.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionResult {
    /// Compressed data.
    pub compressed_data: Vec<u8>,
    /// Compression metadata for manifest.
    pub metadata: CompressionMetadata,
    /// Original data hash (for verification boundary).
    pub plaintext_hash: [u8; 32],
    /// Compressed data hash.
    pub compressed_hash: [u8; 32],
}

/// Compression error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// Policy violation.
    PolicyViolation(String),
    /// Unsupported algorithm.
    UnsupportedAlgorithm(CompressionAlgorithm),
    /// Compression failed.
    CompressionFailed(String),
    /// Decompression failed.
    DecompressionFailed(String),
    /// Size threshold violation.
    SizeThresholdViolation,
    /// Compression bomb detected.
    CompressionBomb,
    /// Transform order violation.
    TransformOrderViolation(String),
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyViolation(msg) => write!(f, "compression policy violation: {msg}"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported compression algorithm: {alg:?}")
            }
            Self::CompressionFailed(msg) => write!(f, "compression failed: {msg}"),
            Self::DecompressionFailed(msg) => write!(f, "decompression failed: {msg}"),
            Self::SizeThresholdViolation => write!(f, "size below compression threshold"),
            Self::CompressionBomb => write!(f, "compression bomb detected"),
            Self::TransformOrderViolation(msg) => write!(f, "transform order violation: {msg}"),
        }
    }
}

impl std::error::Error for CompressionError {}

/// ATP compression engine with policy enforcement.
pub struct CompressionEngine;

impl CompressionEngine {
    /// Apply compression according to policy and transform order.
    pub fn compress(
        data: &[u8],
        object_kind: ObjectKind,
        policy: &CompressionPolicy,
        transform_order: Option<&TransformOrder>,
    ) -> Result<CompressionResult, CompressionError> {
        if data.is_empty() {
            return Err(CompressionError::SizeThresholdViolation);
        }

        // Validate compression is allowed for this object kind
        if !policy.apply_to_kinds.contains(&object_kind) {
            return Err(CompressionError::PolicyViolation(format!(
                "compression not allowed for object kind {object_kind:?}"
            )));
        }

        // Check size threshold
        if data.len() < policy.min_size_threshold as usize {
            return Err(CompressionError::SizeThresholdViolation);
        }

        // Validate transform order if specified
        if let Some(order) = transform_order {
            Self::validate_transform_position(
                order,
                !matches!(policy.algorithm, CompressionAlgorithm::None),
            )?;
        }

        // Compute plaintext hash before compression
        let plaintext_hash = Self::compute_hash(data);

        // Apply compression
        let compressed_data = match policy.algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Lz4 => Self::compress_lz4(data, policy.level)?,
            CompressionAlgorithm::Gzip => Self::compress_gzip(data, policy.level)?,
            CompressionAlgorithm::Brotli => Self::compress_brotli(data, policy.level)?,
        };

        // Compute compressed data hash
        let compressed_hash = Self::compute_hash(&compressed_data);

        // Calculate compression ratio and validate bounds
        let compression_ratio = compressed_data.len() as f32 / data.len() as f32;
        if compression_ratio > 1.2 {
            // If compression made things worse, consider using uncompressed
            return Ok(CompressionResult {
                compressed_data: data.to_vec(),
                metadata: CompressionMetadata {
                    algorithm: CompressionAlgorithm::None,
                    level: 0,
                    original_size: data.len() as u64,
                    compressed_size: data.len() as u64,
                    compression_ratio: 1.0,
                },
                plaintext_hash,
                compressed_hash: plaintext_hash,
            });
        }

        let metadata = CompressionMetadata {
            algorithm: policy.algorithm,
            level: policy.level,
            original_size: data.len() as u64,
            compressed_size: compressed_data.len() as u64,
            compression_ratio,
        };

        Ok(CompressionResult {
            compressed_data,
            metadata,
            plaintext_hash,
            compressed_hash,
        })
    }

    /// Decompress data according to metadata.
    pub fn decompress(
        compressed_data: &[u8],
        metadata: &CompressionMetadata,
    ) -> Result<Vec<u8>, CompressionError> {
        let expected_size = Self::validate_decompression_metadata(compressed_data, metadata)?;

        match metadata.algorithm {
            CompressionAlgorithm::None => Ok(compressed_data.to_vec()),
            CompressionAlgorithm::Lz4 => Self::decompress_lz4(compressed_data, expected_size),
            CompressionAlgorithm::Gzip => Self::decompress_gzip(compressed_data, expected_size),
            CompressionAlgorithm::Brotli => Self::decompress_brotli(compressed_data, expected_size),
        }
    }

    /// Check if compression is enabled for object type in policy.
    pub fn is_compression_enabled(policy: &CompressionPolicy, object_kind: ObjectKind) -> bool {
        !matches!(policy.algorithm, CompressionAlgorithm::None)
            && policy.apply_to_kinds.contains(&object_kind)
    }

    /// Validate transform position in the transform order.
    fn validate_transform_position(
        transform_order: &TransformOrder,
        has_compression: bool,
    ) -> Result<(), CompressionError> {
        let compression_pos = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Compression);

        if has_compression != compression_pos.is_some() {
            return Err(CompressionError::TransformOrderViolation(
                "compression presence doesn't match transform order".to_string(),
            ));
        }

        let Some(pos) = compression_pos else {
            return Ok(());
        };

        // Compression should come after chunking but before encryption
        if let Some(chunk_pos) = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Chunking)
        {
            if pos <= chunk_pos {
                return Err(CompressionError::TransformOrderViolation(
                    "compression must come after chunking".to_string(),
                ));
            }
        }

        if let Some(enc_pos) = transform_order
            .transforms
            .iter()
            .position(|&t| t == TransformType::Encryption)
        {
            if pos >= enc_pos {
                return Err(CompressionError::TransformOrderViolation(
                    "compression must come before encryption".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn validate_decompression_metadata(
        compressed_data: &[u8],
        metadata: &CompressionMetadata,
    ) -> Result<usize, CompressionError> {
        if metadata.original_size == 0 || metadata.compressed_size == 0 {
            return Err(CompressionError::PolicyViolation(
                "compression metadata sizes must be non-zero".to_string(),
            ));
        }

        let actual_compressed_size = u64::try_from(compressed_data.len()).map_err(|_| {
            CompressionError::DecompressionFailed("compressed size does not fit u64".to_string())
        })?;
        if metadata.compressed_size != actual_compressed_size {
            return Err(CompressionError::PolicyViolation(
                "compressed data length doesn't match metadata".to_string(),
            ));
        }

        if !metadata.compression_ratio.is_finite()
            || metadata.compression_ratio <= 0.0
            || metadata.compression_ratio > 1.5
        {
            return Err(CompressionError::PolicyViolation(
                "invalid compression ratio".to_string(),
            ));
        }

        let computed_ratio = metadata.compressed_size as f32 / metadata.original_size as f32;
        let ratio_diff = (computed_ratio - metadata.compression_ratio).abs();
        if ratio_diff > COMPRESSION_RATIO_TOLERANCE {
            return Err(CompressionError::PolicyViolation(
                "compression ratio doesn't match computed ratio".to_string(),
            ));
        }

        if metadata.compression_ratio < 0.001 {
            return Err(CompressionError::CompressionBomb);
        }

        checked_expected_size(metadata.original_size)
    }

    /// Compute SHA-256 hash.
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compress using LZ4.
    fn compress_lz4(data: &[u8], _level: u8) -> Result<Vec<u8>, CompressionError> {
        Ok(lz4_flex::compress_prepend_size(data))
    }

    /// Decompress LZ4.
    fn decompress_lz4(
        compressed: &[u8],
        expected_size: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        if lz4_prepended_size(compressed)? != expected_size {
            return Err(CompressionError::DecompressionFailed(
                "decompressed size mismatch".to_string(),
            ));
        }

        let decompressed = lz4_flex::decompress_size_prepended(compressed)
            .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;

        if decompressed.len() != expected_size {
            return Err(CompressionError::DecompressionFailed(
                "decompressed size mismatch".to_string(),
            ));
        }

        Ok(decompressed)
    }

    /// Compress using Gzip.
    fn compress_gzip(data: &[u8], level: u8) -> Result<Vec<u8>, CompressionError> {
        use flate2::{Compression, write::GzEncoder};

        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level.into()));
        encoder
            .write_all(data)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;

        encoder
            .finish()
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
    }

    /// Decompress Gzip.
    fn decompress_gzip(
        compressed: &[u8],
        expected_size: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        use flate2::read::GzDecoder;

        let mut decoder = GzDecoder::new(compressed);
        read_decompressed_exact(&mut decoder, expected_size)
    }

    /// Compress using Brotli.
    #[cfg(feature = "compression")]
    fn compress_brotli(data: &[u8], level: u8) -> Result<Vec<u8>, CompressionError> {
        let quality = u32::from(level.min(11));
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, quality, 22);
        encoder
            .write_all(data)
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
        encoder
            .flush()
            .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
        Ok(encoder.into_inner())
    }

    /// Compress using Brotli.
    #[cfg(not(feature = "compression"))]
    fn compress_brotli(_data: &[u8], _level: u8) -> Result<Vec<u8>, CompressionError> {
        Err(CompressionError::UnsupportedAlgorithm(
            CompressionAlgorithm::Brotli,
        ))
    }

    /// Decompress Brotli.
    #[cfg(feature = "compression")]
    fn decompress_brotli(
        compressed: &[u8],
        expected_size: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = brotli::Decompressor::new(compressed, 4096);
        read_decompressed_exact(&mut decoder, expected_size)
    }

    /// Decompress Brotli.
    #[cfg(not(feature = "compression"))]
    fn decompress_brotli(
        _compressed: &[u8],
        _expected_size: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        Err(CompressionError::UnsupportedAlgorithm(
            CompressionAlgorithm::Brotli,
        ))
    }
}

#[cfg(test)]
mod tests {
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
}
