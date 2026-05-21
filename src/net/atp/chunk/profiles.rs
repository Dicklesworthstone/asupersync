//! Common trait and utilities for chunking profiles.
//!
//! This module defines the common interface that all chunking profiles implement,
//! along with shared utilities for chunk boundary computation and validation.

use super::ChunkingProfileError;
use crate::atp::manifest::{ChunkBoundary, ChunkMetadata, ChunkPlan, ChunkStrategy};

/// Common interface for all chunking profiles.
pub trait ChunkingProfile {
    /// Get the recommended chunk plan for the given object size.
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan;

    /// Compute chunk boundaries for the given data using this profile.
    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError>;

    /// Validate chunk boundaries for consistency with this profile.
    fn validate_boundaries(boundaries: &[ChunkBoundary]) -> Result<(), ChunkingProfileError>;

    /// Get the minimum object size where chunking provides benefits.
    fn min_chunking_threshold() -> u64;

    /// Get the maximum recommended chunk size for this profile.
    fn max_chunk_size() -> u64;

    /// Whether this profile supports incremental/streaming chunking.
    fn supports_incremental_chunking() -> bool;
}

/// Shared utilities for chunk computation across profiles.
pub mod utils {
    use super::*;
    use sha2::{Sha256, Digest};

    /// Compute SHA-256 hash of chunk data.
    pub fn compute_chunk_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Rolling hash implementation for content-defined chunking.
    pub struct RollingHash {
        window_size: usize,
        hash: u64,
        window: Vec<u8>,
        position: usize,
    }

    impl RollingHash {
        /// Create a new rolling hash with the given window size.
        pub fn new(window_size: usize) -> Self {
            let window_size = std::cmp::max(1, window_size);
            Self {
                window_size,
                hash: 0,
                window: vec![0; window_size],
                position: 0,
            }
        }

        /// Add a byte to the rolling hash and return the current hash value.
        pub fn update(&mut self, byte: u8) -> u64 {
            let old_byte = self.window[self.position % self.window_size]; // ubs:ignore
            self.window[self.position % self.window_size] = byte; // ubs:ignore

            // Simple rolling hash: remove old byte, add new byte
            let multiplier = 31_u64.wrapping_pow(self.window_size as u32);
            self.hash = self.hash.wrapping_mul(31)
                .wrapping_sub((old_byte as u64).wrapping_mul(multiplier))
                .wrapping_add(byte as u64);

            self.position += 1;
            self.hash
        }

        /// Get the current hash value.
        pub fn current_hash(&self) -> u64 {
            self.hash
        }

        /// Reset the rolling hash state.
        pub fn reset(&mut self) {
            self.hash = 0;
            self.window.fill(0);
            self.position = 0;
        }
    }

    /// Detect content-defined chunk boundaries using rolling hash.
    pub fn find_cdc_boundaries(
        data: &[u8],
        window_size: usize,
        avg_chunk_size: u64,
        min_chunk_size: u64,
        max_chunk_size: u64,
    ) -> Vec<u64> {
        if data.len() < min_chunk_size as usize {
            return vec![data.len() as u64];
        }

        let mut boundaries = Vec::new();
        let mut rolling_hash = RollingHash::new(window_size);
        let mut last_boundary = 0u64;

        // Compute mask for average chunk size
        let mask = (1u64 << (64 - avg_chunk_size.leading_zeros() - 1)) - 1;

        for (i, &byte) in data.iter().enumerate() {
            let hash = rolling_hash.update(byte);
            let current_pos = i as u64 + 1;
            let chunk_size_since_last = current_pos - last_boundary;

            // Check for boundary conditions
            let is_boundary = if chunk_size_since_last < min_chunk_size {
                false // Too small, keep going
            } else if chunk_size_since_last >= max_chunk_size {
                true // Hit max size, force boundary
            } else {
                // Check rolling hash for natural boundary
                (hash & mask) == 0
            };

            if is_boundary {
                boundaries.push(current_pos);
                last_boundary = current_pos;
                rolling_hash.reset();
            }
        }

        // Add final boundary if not already present
        if last_boundary < data.len() as u64 {
            boundaries.push(data.len() as u64);
        }

        boundaries
    }

    /// Validate that chunk boundaries are properly ordered and non-overlapping.
    pub fn validate_boundary_ordering(boundaries: &[ChunkBoundary]) -> Result<(), ChunkingProfileError> {
        if boundaries.is_empty() {
            return Ok(());
        }

        let mut last_end = 0u64;
        for (i, boundary) in boundaries.iter().enumerate() {
            if boundary.byte_offset != last_end {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    format!(
                        "boundary {} has gap: expected offset {}, got {}",
                        i, last_end, boundary.byte_offset
                    )
                ));
            }

            if boundary.size_bytes == 0 {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    format!("boundary {} has zero size", i)
                ));
            }

            if boundary.index != i as u32 {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    format!("boundary {} has incorrect index: expected {}, got {}",
                            i, i, boundary.index)
                ));
            }

            last_end = boundary.byte_offset + boundary.size_bytes;
        }

        Ok(())
    }

    /// Convert byte positions to chunk boundaries with computed hashes.
    pub fn positions_to_boundaries(
        data: &[u8],
        positions: &[u64],
        strategy: ChunkStrategy,
        metadata_fn: impl Fn(u32, u64, u64, &[u8]) -> ChunkMetadata,
    ) -> Vec<ChunkBoundary> {
        let mut boundaries = Vec::new();
        let mut last_pos = 0u64;

        for (index, &pos) in positions.iter().enumerate() {
            let chunk_start = last_pos as usize;
            let chunk_end = pos as usize;
            let chunk_data = &data[chunk_start..chunk_end];
            let chunk_size = pos - last_pos;

            let boundary = ChunkBoundary {
                index: index as u32,
                byte_offset: last_pos,
                size_bytes: chunk_size,
                content_hash: compute_chunk_hash(chunk_data),
                strategy,
                metadata: Some(metadata_fn(index as u32, last_pos, chunk_size, chunk_data)),
            };

            boundaries.push(boundary);
            last_pos = pos;
        }

        boundaries
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::atp::manifest::ThroughputTier;

        #[test]
        fn rolling_hash_is_deterministic() {
            let mut hash1 = RollingHash::new(4);
            let mut hash2 = RollingHash::new(4);

            let data = b"hello world";
            for &byte in data {
                let h1 = hash1.update(byte);
                let h2 = hash2.update(byte);
                assert_eq!(h1, h2);
            }
        }

        #[test]
        fn rolling_hash_changes_with_content() {
            let mut hash = RollingHash::new(4);

            let hash1 = hash.update(b'a');
            let hash2 = hash.update(b'b');
            let hash3 = hash.update(b'c');

            // Hashes should be different
            assert_ne!(hash1, hash2);
            assert_ne!(hash2, hash3);
        }

        #[test]
        fn cdc_boundaries_respect_size_limits() {
            let data = vec![0u8; 10000]; // 10KB of zeros
            let boundaries = find_cdc_boundaries(
                &data,
                64,    // window size
                1024,  // avg chunk size
                512,   // min chunk size
                2048,  // max chunk size
            );

            // Check that all chunks respect size constraints
            let mut last_pos = 0u64;
            for &boundary in &boundaries {
                let chunk_size = boundary - last_pos;
                if last_pos > 0 { // Skip first chunk size check
                    assert!(chunk_size >= 512, "Chunk too small: {}", chunk_size);
                }
                assert!(chunk_size <= 2048, "Chunk too large: {}", chunk_size);
                last_pos = boundary;
            }

            // Should end at data length
            assert_eq!(*boundaries.last().unwrap(), data.len() as u64);
        }

        #[test]
        fn boundary_ordering_validation_works() {
            // Valid boundaries
            let valid_boundaries = vec![
                ChunkBoundary {
                    index: 0,
                    byte_offset: 0,
                    size_bytes: 1000,
                    content_hash: [1; 32],
                    strategy: ChunkStrategy::FixedSize,
                    metadata: Some(ChunkMetadata::BulkFile {
                        throughput_tier: ThroughputTier::Standard,
                    }),
                },
                ChunkBoundary {
                    index: 1,
                    byte_offset: 1000,
                    size_bytes: 500,
                    content_hash: [2; 32],
                    strategy: ChunkStrategy::FixedSize,
                    metadata: Some(ChunkMetadata::BulkFile {
                        throughput_tier: ThroughputTier::Standard,
                    }),
                },
            ];

            assert!(validate_boundary_ordering(&valid_boundaries).is_ok());

            // Invalid boundaries with gap
            let invalid_boundaries = vec![
                ChunkBoundary {
                    index: 0,
                    byte_offset: 0,
                    size_bytes: 1000,
                    content_hash: [1; 32],
                    strategy: ChunkStrategy::FixedSize,
                    metadata: Some(ChunkMetadata::BulkFile {
                        throughput_tier: ThroughputTier::Standard,
                    }),
                },
                ChunkBoundary {
                    index: 1,
                    byte_offset: 1500, // Gap!
                    size_bytes: 500,
                    content_hash: [2; 32],
                    strategy: ChunkStrategy::FixedSize,
                    metadata: Some(ChunkMetadata::BulkFile {
                        throughput_tier: ThroughputTier::Standard,
                    }),
                },
            ];

            assert!(validate_boundary_ordering(&invalid_boundaries).is_err());
        }

        #[test]
        fn chunk_hash_is_deterministic() {
            let data = b"test chunk data";
            let hash1 = compute_chunk_hash(data);
            let hash2 = compute_chunk_hash(data);
            assert_eq!(hash1, hash2);

            // Different data should produce different hashes
            let hash3 = compute_chunk_hash(b"different data");
            assert_ne!(hash1, hash3);
        }
    }
}
