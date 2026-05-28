//! Stream chunking profile optimized for rolling manifests and early consumption.
//!
//! This profile is designed for real-time streaming scenarios where data arrives
//! incrementally and consumers need to process chunks as they become available.
//! It supports rolling manifests that can be updated as new chunks arrive.
//!
//! Key characteristics:
//! - Fixed-size chunking for predictable timing
//! - Sequence-based ordering for streaming
//! - Early consumption safety markers
//! - Rolling manifest updates
//! - Optimized for real-time data streams

use super::{
    ChunkBoundary, ChunkMetadata, ChunkingProfileError,
    profiles::{ChunkingProfile as ChunkingProfileTrait, utils},
};
use crate::atp::manifest::{ChunkPlan, ChunkStrategy};

/// Stream chunking profile implementation.
pub struct StreamProfile;

impl ChunkingProfileTrait for StreamProfile {
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan {
        let (target_size, min_size, max_size) = Self::compute_chunk_sizes(object_size_bytes);

        ChunkPlan {
            strategy: ChunkStrategy::FixedSize, // Fixed chunks for predictable timing
            target_chunk_size: target_size,
            min_chunk_size: min_size,
            max_chunk_size: max_size,
            cdc_params: None, // Fixed-size chunking doesn't use CDC
        }
    }

    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_plan = Self::chunk_plan(utils::data_len_u64(data)?);
        let positions = Self::find_stream_boundaries(data, &chunk_plan)?;

        let boundaries = utils::positions_to_boundaries(
            data,
            &positions,
            ChunkStrategy::FixedSize,
            |index, offset, _size, chunk_data| {
                let sequence = Self::compute_sequence_number(index, offset);
                let early_consumption_safe =
                    Self::is_early_consumption_safe(chunk_data, index, positions.len());

                ChunkMetadata::Stream {
                    sequence,
                    early_consumption_safe,
                }
            },
        )?;

        utils::validate_boundary_ordering(&boundaries)?;
        Self::validate_stream_properties(&boundaries)?;
        Ok(boundaries)
    }

    fn validate_boundaries(boundaries: &[ChunkBoundary]) -> Result<(), ChunkingProfileError> {
        utils::validate_boundary_ordering(boundaries)?;

        for boundary in boundaries {
            if !matches!(boundary.strategy, ChunkStrategy::FixedSize) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "stream profile requires fixed-size chunking".to_string(),
                ));
            }

            if !matches!(boundary.metadata, Some(ChunkMetadata::Stream { .. })) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "stream profile requires Stream metadata".to_string(),
                ));
            }

            if boundary.size_bytes < Self::min_chunking_threshold() {
                return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                    "chunk size {} below minimum {}",
                    boundary.size_bytes,
                    Self::min_chunking_threshold()
                )));
            }

            if boundary.size_bytes > Self::max_chunk_size() {
                return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                    "chunk size {} above maximum {}",
                    boundary.size_bytes,
                    Self::max_chunk_size()
                )));
            }
        }

        Self::validate_stream_properties(boundaries)?;
        Ok(())
    }

    fn min_chunking_threshold() -> u64 {
        // Minimum 4KB for streaming efficiency
        4 * 1024
    }

    fn max_chunk_size() -> u64 {
        // Maximum 1MB to maintain low latency
        1024 * 1024
    }

    fn supports_incremental_chunking() -> bool {
        true // Stream processing is inherently incremental
    }
}

impl StreamProfile {
    /// Compute chunk sizes optimized for streaming scenarios.
    fn compute_chunk_sizes(object_size_bytes: u64) -> (u64, u64, u64) {
        match object_size_bytes {
            // Very small streams: minimal chunking
            0..=16_384 => {
                // Up to 16KB: 4KB chunks for low latency
                (4 * 1024, 1024, 8 * 1024)
            }
            // Small streams: balance latency and efficiency
            16_385..=1_048_576 => {
                // 16KB-1MB: 16KB chunks
                (16 * 1024, 4 * 1024, 32 * 1024)
            }
            // Medium streams: optimize for throughput while maintaining responsiveness
            1_048_577..=67_108_864 => {
                // 1MB-64MB: 64KB chunks
                (64 * 1024, 16 * 1024, 128 * 1024)
            }
            // Large streams: larger chunks for efficiency
            67_108_865..=1_073_741_824 => {
                // 64MB-1GB: 256KB chunks
                (256 * 1024, 64 * 1024, 512 * 1024)
            }
            // Very large streams: maximum efficiency while maintaining streaming capability
            _ => {
                // >1GB: 1MB chunks maximum
                (1024 * 1024, 256 * 1024, 1024 * 1024)
            }
        }
    }

    /// Find chunk boundaries optimized for streaming.
    fn find_stream_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        let target_size = utils::u64_to_usize(chunk_plan.target_chunk_size, "target chunk size")?;
        let min_size = utils::u64_to_usize(chunk_plan.min_chunk_size, "minimum chunk size")?;
        let merge_threshold =
            utils::checked_usize_add(target_size, min_size, "stream remainder threshold")?;

        let mut boundaries = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let remaining = data.len() - pos;

            // Use fixed size, but handle remainder gracefully
            let chunk_size = if remaining <= merge_threshold {
                remaining // Take all remaining data to avoid tiny last chunk
            } else {
                target_size
            };

            pos = pos.checked_add(chunk_size).ok_or_else(|| {
                ChunkingProfileError::InvalidChunkParameters(
                    "stream chunk position overflow".to_string(),
                )
            })?;
            boundaries.push(utils::usize_to_u64(pos, "stream chunk boundary")?);
        }

        Ok(boundaries)
    }

    /// Compute sequence number for streaming order.
    fn compute_sequence_number(chunk_index: u32, chunk_offset: u64) -> u64 {
        // Simple sequence based on index, with offset as tie-breaker
        (chunk_index as u64) << 32 | (chunk_offset & 0xFFFFFFFF)
    }

    /// Determine if chunk can be safely consumed before all chunks arrive.
    fn is_early_consumption_safe(chunk_data: &[u8], chunk_index: u32, total_chunks: usize) -> bool {
        // Early chunks are generally safe for early consumption
        if chunk_index < 3 {
            return true;
        }

        // Last chunk requires all previous chunks
        let is_last_chunk = match usize::try_from(chunk_index) {
            Ok(index) => index >= total_chunks.saturating_sub(1),
            Err(_) => true,
        };
        if is_last_chunk {
            return false;
        }

        // Check if chunk appears to contain metadata or headers
        if Self::contains_stream_metadata(chunk_data) {
            return false;
        }

        // Check if chunk has dependencies on other chunks
        if Self::has_chunk_dependencies(chunk_data) {
            return false;
        }

        // Most data chunks can be consumed early
        true
    }

    /// Check if chunk contains stream metadata that might depend on other chunks.
    fn contains_stream_metadata(chunk_data: &[u8]) -> bool {
        if chunk_data.is_empty() {
            return false;
        }

        // Look for common metadata patterns
        let data_str = String::from_utf8_lossy(&chunk_data[..64.min(chunk_data.len())]);

        // JSON metadata
        if data_str.trim_start().starts_with('{') && data_str.contains("metadata") {
            return true;
        }

        // XML metadata
        if data_str.trim_start().starts_with('<') && data_str.contains("meta") {
            return true;
        }

        // Binary metadata headers
        if chunk_data.starts_with(b"META")
            || chunk_data.starts_with(b"HEAD")
            || chunk_data.starts_with(b"INFO")
        {
            return true;
        }

        false
    }

    /// Check if chunk has dependencies on other chunks.
    fn has_chunk_dependencies(chunk_data: &[u8]) -> bool {
        if chunk_data.len() < 8 {
            return false;
        }

        // Look for reference patterns
        let data_str = String::from_utf8_lossy(&chunk_data[..128.min(chunk_data.len())]);

        // References to other chunks
        if data_str.contains("ref:")
            || data_str.contains("chunk:")
            || data_str.contains("depends:")
            || data_str.contains("requires:")
        {
            return true;
        }

        // Binary reference sentinels used by compact rolling manifests.
        chunk_data
            .windows(4)
            .any(|w| w == b"REF\x00" || w == b"\x00REF")
    }

    /// Validate stream-specific properties.
    fn validate_stream_properties(
        boundaries: &[ChunkBoundary],
    ) -> Result<(), ChunkingProfileError> {
        // Check sequence ordering
        let mut last_sequence = 0u64;
        for boundary in boundaries {
            if let Some(ChunkMetadata::Stream { sequence, .. }) = &boundary.metadata {
                if *sequence < last_sequence {
                    return Err(ChunkingProfileError::StreamSequencingError(
                        "sequence numbers must be monotonically increasing".to_string(),
                    ));
                }
                last_sequence = *sequence;
            }
        }

        // Check that at least some chunks are early-consumption safe
        let safe_chunks = boundaries
            .iter()
            .filter(|b| {
                if let Some(ChunkMetadata::Stream {
                    early_consumption_safe,
                    ..
                }) = &b.metadata
                {
                    *early_consumption_safe
                } else {
                    false
                }
            })
            .count();

        if safe_chunks == 0 && boundaries.len() > 1 {
            return Err(ChunkingProfileError::StreamSequencingError(
                "at least some chunks should be early-consumption safe".to_string(),
            ));
        }

        Ok(())
    }

    /// Get optimal streaming order for chunks.
    pub fn get_streaming_order(boundaries: &[ChunkBoundary]) -> Vec<usize> {
        let mut indexed_boundaries: Vec<(usize, &ChunkBoundary)> =
            boundaries.iter().enumerate().collect();

        // Sort by sequence number (should already be ordered)
        indexed_boundaries.sort_by(|(_, a), (_, b)| {
            let a_seq = if let Some(ChunkMetadata::Stream { sequence, .. }) = &a.metadata {
                *sequence
            } else {
                0
            };

            let b_seq = if let Some(ChunkMetadata::Stream { sequence, .. }) = &b.metadata {
                *sequence
            } else {
                0
            };

            a_seq.cmp(&b_seq)
        });

        indexed_boundaries.into_iter().map(|(idx, _)| idx).collect()
    }

    /// Get chunks that can be consumed early (before stream completion).
    pub fn get_early_consumption_chunks(boundaries: &[ChunkBoundary]) -> Vec<usize> {
        boundaries
            .iter()
            .enumerate()
            .filter_map(|(idx, boundary)| {
                if let Some(ChunkMetadata::Stream {
                    early_consumption_safe,
                    ..
                }) = &boundary.metadata
                {
                    if *early_consumption_safe {
                        Some(idx)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Create rolling manifest update for new chunk.
    pub fn create_rolling_manifest_update(
        boundary: &ChunkBoundary,
        total_expected_size: Option<u64>,
    ) -> RollingManifestUpdate {
        let (sequence, early_consumption_safe) = if let Some(ChunkMetadata::Stream {
            sequence,
            early_consumption_safe,
        }) = &boundary.metadata
        {
            (*sequence, *early_consumption_safe)
        } else {
            (0, false)
        };

        let completion_ratio = if let Some(total_size) = total_expected_size {
            if total_size > 0 {
                boundary.byte_offset.saturating_add(boundary.size_bytes) as f64 / total_size as f64
            } else {
                1.0
            }
        } else {
            0.0 // Unknown total size
        };

        RollingManifestUpdate {
            chunk_index: boundary.index,
            chunk_offset: boundary.byte_offset,
            chunk_size: boundary.size_bytes,
            chunk_hash: boundary.content_hash,
            sequence,
            early_consumption_safe,
            completion_ratio,
            timestamp_nanos: Self::current_timestamp_nanos(),
        }
    }

    /// Estimate streaming latency for the given chunk plan.
    pub fn estimate_streaming_latency(
        boundaries: &[ChunkBoundary],
        bandwidth_mbps: u64,
        latency_ms: u64,
    ) -> StreamingLatencyEstimate {
        if boundaries.is_empty() {
            return StreamingLatencyEstimate {
                first_chunk_latency: std::time::Duration::from_millis(0),
                full_stream_latency: std::time::Duration::from_millis(0),
                early_consumption_latency: std::time::Duration::from_millis(0),
            };
        }

        // First chunk latency
        let first_chunk_size = boundaries[0].size_bytes;
        let safe_bw = bandwidth_mbps.max(1) as f64;
        let first_chunk_transfer_ms = (first_chunk_size as f64 * 8.0) / (safe_bw * 1000.0);
        let first_chunk_latency = std::time::Duration::from_millis(
            (first_chunk_transfer_ms + latency_ms as f64).ceil() as u64,
        );

        // Full stream latency
        let total_size = boundaries.iter().fold(0u64, |acc, boundary| {
            acc.saturating_add(boundary.size_bytes)
        });
        let total_transfer_ms = (total_size as f64 * 8.0) / (safe_bw * 1000.0);
        let total_latency_overhead_ms = boundaries.len() as f64 * latency_ms as f64;
        let full_stream_latency = std::time::Duration::from_millis(
            (total_transfer_ms + total_latency_overhead_ms).ceil() as u64,
        );

        // Early consumption latency (chunks available for early consumption)
        let early_chunks = Self::get_early_consumption_chunks(boundaries);
        let early_consumption_size = early_chunks.iter().fold(0u64, |acc, &idx| {
            acc.saturating_add(boundaries[idx].size_bytes)
        });
        let early_transfer_ms = (early_consumption_size as f64 * 8.0) / (safe_bw * 1000.0);
        let early_latency_overhead_ms = early_chunks.len() as f64 * latency_ms as f64;
        let early_consumption_latency = std::time::Duration::from_millis(
            (early_transfer_ms + early_latency_overhead_ms).ceil() as u64,
        );

        StreamingLatencyEstimate {
            first_chunk_latency,
            full_stream_latency,
            early_consumption_latency,
        }
    }

    /// Get current timestamp in nanoseconds.
    fn current_timestamp_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Validate that stream chunks can be processed incrementally.
    pub fn validate_incremental_processing(
        boundaries: &[ChunkBoundary],
    ) -> Result<(), ChunkingProfileError> {
        // Check that chunk sizes are reasonable for incremental processing
        for boundary in boundaries {
            if boundary.size_bytes > Self::max_chunk_size() {
                return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                    "chunk size {} too large for incremental processing",
                    boundary.size_bytes
                )));
            }
        }

        // Check that early consumption is possible
        let early_chunks = Self::get_early_consumption_chunks(boundaries);
        if early_chunks.is_empty() && boundaries.len() > 3 {
            return Err(ChunkingProfileError::StreamSequencingError(
                "no chunks available for early consumption in large stream".to_string(),
            ));
        }

        Ok(())
    }
}

/// Rolling manifest update for streaming scenarios.
#[derive(Debug, Clone, PartialEq)]
pub struct RollingManifestUpdate {
    /// Chunk index in the stream.
    pub chunk_index: u32,
    /// Byte offset of this chunk.
    pub chunk_offset: u64,
    /// Size of this chunk.
    pub chunk_size: u64,
    /// Content hash of this chunk.
    pub chunk_hash: [u8; 32],
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Whether this chunk can be consumed early.
    pub early_consumption_safe: bool,
    /// Completion ratio (0.0 to 1.0) if total size is known.
    pub completion_ratio: f64,
    /// Timestamp when this update was created.
    pub timestamp_nanos: u64,
}

/// Streaming latency estimates.
#[derive(Debug, Clone)]
pub struct StreamingLatencyEstimate {
    /// Time to receive and process the first chunk.
    pub first_chunk_latency: std::time::Duration,
    /// Time to receive and process the complete stream.
    pub full_stream_latency: std::time::Duration,
    /// Time to receive chunks available for early consumption.
    pub early_consumption_latency: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_optimize_for_streaming() {
        // Small streams should use small chunks for low latency
        let (target, min, max) = StreamProfile::compute_chunk_sizes(8_192);
        assert_eq!(target, 4 * 1024);
        assert_eq!(min, 1024);
        assert!(max <= 32 * 1024);

        // Large streams should use bigger chunks for efficiency
        let (target, min, max) = StreamProfile::compute_chunk_sizes(2_000_000_000);
        assert!(min <= target);
        assert_eq!(target, 1024 * 1024);
        assert_eq!(max, 1024 * 1024);
    }

    #[test]
    fn sequence_number_computation() {
        let seq1 = StreamProfile::compute_sequence_number(0, 0);
        let seq2 = StreamProfile::compute_sequence_number(1, 4096);
        let seq3 = StreamProfile::compute_sequence_number(0, 8192);

        // Later chunks should have higher sequences
        assert!(seq2 > seq1);

        // Same index but different offset
        assert!(seq3 > seq1);
        assert!(seq2 > seq3); // Different index wins over offset
    }

    #[test]
    fn early_consumption_safety() {
        // Early chunks should be safe
        let early_chunk_data = b"regular data content";
        assert!(StreamProfile::is_early_consumption_safe(
            early_chunk_data,
            0,
            10
        ));
        assert!(StreamProfile::is_early_consumption_safe(
            early_chunk_data,
            2,
            10
        ));

        // Last chunk should not be safe
        assert!(!StreamProfile::is_early_consumption_safe(
            early_chunk_data,
            9,
            10
        ));

        // Metadata chunks should not be safe
        let metadata_chunk = b"{\"metadata\": {\"type\": \"header\"}}";
        assert!(!StreamProfile::is_early_consumption_safe(
            metadata_chunk,
            5,
            10
        ));
    }

    #[test]
    fn stream_metadata_detection() {
        assert!(StreamProfile::contains_stream_metadata(
            b"{\"metadata\": true}"
        ));
        assert!(StreamProfile::contains_stream_metadata(
            b"<metadata><info>test</info></metadata>"
        ));
        assert!(StreamProfile::contains_stream_metadata(
            b"META\x00\x00\x00\x04"
        ));
        assert!(!StreamProfile::contains_stream_metadata(
            b"just regular data content"
        ));
    }

    #[test]
    fn chunk_dependency_detection() {
        assert!(StreamProfile::has_chunk_dependencies(
            b"data with ref:chunk-123 reference"
        ));
        assert!(StreamProfile::has_chunk_dependencies(b"depends: chunk-456"));
        assert!(StreamProfile::has_chunk_dependencies(
            b"REF\x00binary reference"
        ));
        assert!(!StreamProfile::has_chunk_dependencies(
            b"independent chunk data"
        ));
    }

    #[test]
    fn stream_chunking_creates_boundaries() {
        let stream_data = vec![1u8; 100_000]; // 100KB stream
        let boundaries = StreamProfile::compute_boundaries(&stream_data).unwrap();

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::FixedSize));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::Stream { .. })
            ));
        }

        // Validate sequence ordering
        let mut last_sequence = 0u64;
        for boundary in &boundaries {
            if let Some(ChunkMetadata::Stream { sequence, .. }) = &boundary.metadata {
                assert!(*sequence >= last_sequence);
                last_sequence = *sequence;
            }
        }

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, stream_data.len() as u64);
    }

    #[test]
    fn streaming_order_respects_sequence() {
        let boundaries = vec![
            ChunkBoundary {
                index: 2,
                byte_offset: 8192,
                size_bytes: 4096,
                content_hash: [3; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 2,
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 4096,
                content_hash: [1; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 0,
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 4096,
                size_bytes: 4096,
                content_hash: [2; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 1,
                    early_consumption_safe: false,
                }),
            },
        ];

        let order = StreamProfile::get_streaming_order(&boundaries);
        // Should be ordered by sequence: 0, 1, 2
        assert_eq!(order, vec![1, 2, 0]); // Indices of chunks with sequences 0, 1, 2
    }

    #[test]
    fn early_consumption_chunk_filtering() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 4096,
                content_hash: [1; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 0,
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 4096,
                size_bytes: 4096,
                content_hash: [2; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 1,
                    early_consumption_safe: false,
                }),
            },
            ChunkBoundary {
                index: 2,
                byte_offset: 8192,
                size_bytes: 4096,
                content_hash: [3; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 2,
                    early_consumption_safe: true,
                }),
            },
        ];

        let early_chunks = StreamProfile::get_early_consumption_chunks(&boundaries);
        assert_eq!(early_chunks, vec![0, 2]); // Only chunks 0 and 2 are early-safe
    }

    #[test]
    fn rolling_manifest_update_creation() {
        let boundary = ChunkBoundary {
            index: 5,
            byte_offset: 20480,
            size_bytes: 4096,
            content_hash: [5; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::Stream {
                sequence: 5,
                early_consumption_safe: true,
            }),
        };

        let update = StreamProfile::create_rolling_manifest_update(&boundary, Some(100_000));

        assert_eq!(update.chunk_index, 5);
        assert_eq!(update.chunk_offset, 20480);
        assert_eq!(update.chunk_size, 4096);
        assert_eq!(update.chunk_hash, [5; 32]);
        assert_eq!(update.sequence, 5);
        assert!(update.early_consumption_safe);
        assert!((update.completion_ratio - 0.24576).abs() < 0.001); // (20480 + 4096) / 100000
        assert!(update.timestamp_nanos > 0);
    }

    #[test]
    fn streaming_latency_estimation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 10_000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 0,
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 10_000,
                size_bytes: 10_000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 1,
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 2,
                byte_offset: 20_000,
                size_bytes: 10_000,
                content_hash: [3; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 2,
                    early_consumption_safe: false,
                }),
            },
        ];

        let estimate = StreamProfile::estimate_streaming_latency(&boundaries, 100, 50);

        // Should have reasonable latencies
        assert!(estimate.first_chunk_latency > std::time::Duration::from_millis(50));
        assert!(estimate.full_stream_latency > estimate.first_chunk_latency);
        assert!(estimate.early_consumption_latency > estimate.first_chunk_latency);
        assert!(estimate.early_consumption_latency < estimate.full_stream_latency);
    }

    #[test]
    fn stream_properties_validation() {
        let valid_boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 4096,
                content_hash: [1; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 0,
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 4096,
                size_bytes: 4096,
                content_hash: [2; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 1,
                    early_consumption_safe: false,
                }),
            },
        ];

        assert!(StreamProfile::validate_stream_properties(&valid_boundaries).is_ok());

        // Invalid sequence order
        let invalid_boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 4096,
                content_hash: [1; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 5, // Higher sequence
                    early_consumption_safe: true,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 4096,
                size_bytes: 4096,
                content_hash: [2; 32],
                strategy: ChunkStrategy::FixedSize,
                metadata: Some(ChunkMetadata::Stream {
                    sequence: 1, // Lower sequence!
                    early_consumption_safe: false,
                }),
            },
        ];

        assert!(StreamProfile::validate_stream_properties(&invalid_boundaries).is_err());
    }

    #[test]
    fn incremental_processing_validation() {
        let valid_boundaries = vec![ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100_000, // Reasonable size
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::Stream {
                sequence: 0,
                early_consumption_safe: true,
            }),
        }];

        assert!(StreamProfile::validate_incremental_processing(&valid_boundaries).is_ok());

        let invalid_boundaries = vec![ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 10_000_000, // Too large!
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::Stream {
                sequence: 0,
                early_consumption_safe: true,
            }),
        }];

        assert!(StreamProfile::validate_incremental_processing(&invalid_boundaries).is_err());
    }

    #[test]
    fn boundary_validation_enforces_stream_requirements() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100_000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::ContentDefined, // Wrong strategy!
            metadata: Some(ChunkMetadata::Stream {
                sequence: 0,
                early_consumption_safe: true,
            }),
        };

        let result = StreamProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn profile_properties() {
        assert!(StreamProfile::supports_incremental_chunking());
        assert_eq!(StreamProfile::min_chunking_threshold(), 4 * 1024);
        assert_eq!(StreamProfile::max_chunk_size(), 1024 * 1024);
    }

    #[test]
    fn empty_stream_handling() {
        let boundaries = StreamProfile::compute_boundaries(&[]).unwrap();
        assert!(boundaries.is_empty());

        let estimate = StreamProfile::estimate_streaming_latency(&[], 100, 50);
        assert_eq!(
            estimate.first_chunk_latency,
            std::time::Duration::from_millis(0)
        );
        assert_eq!(
            estimate.full_stream_latency,
            std::time::Duration::from_millis(0)
        );
        assert_eq!(
            estimate.early_consumption_latency,
            std::time::Duration::from_millis(0)
        );
    }

    #[test]
    fn avoids_tiny_remainder_chunks() {
        let data_size = 64 * 1024 + 500; // Just over one chunk + small remainder
        let data = vec![0u8; data_size];

        let boundaries = StreamProfile::compute_boundaries(&data).unwrap();

        // Should merge tiny remainder into last chunk
        for boundary in &boundaries {
            assert!(
                boundary.size_bytes >= 4096,
                "Chunk too small: {}",
                boundary.size_bytes
            );
        }
    }
}
