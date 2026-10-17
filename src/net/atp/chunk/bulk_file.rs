//! Bulk file chunking profile optimized for maximum throughput.
//!
//! This profile uses large fixed-size chunks to minimize overhead and maximize
//! throughput for large file transfers. It's designed for scenarios where raw
//! transfer speed is more important than deduplication efficiency.
//!
//! Key characteristics:
//! - Large fixed-size chunks (1MB-16MB) to minimize protocol overhead
//! - No content analysis to reduce CPU overhead
//! - Optimized for bulk data movement scenarios
//! - Reproducible chunking for proof strength
//! - Adaptive sizing based on object size and network characteristics

use super::{
    ChunkingProfileError,
    profiles::{ChunkingProfile as ChunkingProfileTrait, utils},
};
use crate::atp::manifest::{
    ChunkBoundary, ChunkMetadata, ChunkPlan, ChunkStrategy, ThroughputTier,
};

/// Bulk file chunking profile implementation.
pub struct BulkFileProfile;

impl ChunkingProfileTrait for BulkFileProfile {
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan {
        let (target_chunk_size, min_chunk_size, max_chunk_size) =
            Self::compute_chunk_sizes(object_size_bytes);

        ChunkPlan {
            strategy: ChunkStrategy::FixedSize,
            target_chunk_size,
            min_chunk_size,
            max_chunk_size,
            cdc_params: None, // Fixed-size chunking doesn't use CDC
        }
    }

    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let data_len = utils::data_len_u64(data)?;
        let chunk_plan = Self::chunk_plan(data_len);
        let target_size = utils::u64_to_usize(chunk_plan.target_chunk_size, "target chunk size")?;
        let min_size = utils::u64_to_usize(chunk_plan.min_chunk_size, "minimum chunk size")?;
        let merge_threshold =
            utils::checked_usize_add(target_size, min_size, "bulk remainder threshold")?;

        let mut positions = Vec::new();
        let mut current_pos = 0usize;

        while current_pos < data.len() {
            let remaining = data.len() - current_pos;

            // Use target size, but avoid tiny remainder chunks
            let chunk_size = if remaining <= merge_threshold {
                remaining // Take all remaining data
            } else {
                target_size
            };

            current_pos = current_pos.checked_add(chunk_size).ok_or_else(|| {
                ChunkingProfileError::InvalidChunkParameters(
                    "bulk chunk position overflow".to_string(),
                )
            })?;
            positions.push(utils::usize_to_u64(current_pos, "bulk chunk boundary")?);
        }

        let boundaries = utils::positions_to_boundaries(
            data,
            &positions,
            ChunkStrategy::FixedSize,
            |_index, _offset, size, _chunk_data| {
                let throughput_tier = Self::determine_throughput_tier(size, data_len);
                ChunkMetadata::BulkFile { throughput_tier }
            },
        )?;

        utils::validate_boundary_ordering(&boundaries)?;
        Ok(boundaries)
    }

    fn validate_boundaries(boundaries: &[ChunkBoundary]) -> Result<(), ChunkingProfileError> {
        utils::validate_boundary_ordering(boundaries)?;

        for boundary in boundaries {
            if !matches!(boundary.strategy, ChunkStrategy::FixedSize) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "bulk file profile requires fixed-size chunking".to_string(),
                ));
            }

            if !matches!(boundary.metadata, Some(ChunkMetadata::BulkFile { .. })) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "bulk file profile requires BulkFile metadata".to_string(),
                ));
            }

            // Validate chunk size is within reasonable bounds
            if boundary.size_bytes < Self::absolute_min_chunk_size() {
                return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                    "chunk size {} below minimum {}",
                    boundary.size_bytes,
                    Self::absolute_min_chunk_size()
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

        Ok(())
    }

    fn min_chunking_threshold() -> u64 {
        // Only chunk files larger than 256KB
        256 * 1024
    }

    fn max_chunk_size() -> u64 {
        // Maximum 16MB chunks for bulk transfers
        16 * 1024 * 1024
    }

    fn supports_incremental_chunking() -> bool {
        true // Fixed-size chunking supports incremental processing
    }
}

impl BulkFileProfile {
    /// Compute optimal chunk sizes based on object size.
    fn compute_chunk_sizes(object_size_bytes: u64) -> (u64, u64, u64) {
        match object_size_bytes {
            // Small files: use smaller chunks for better granularity
            0..=1_048_576 => {
                // Up to 1MB: 64KB chunks
                (64 * 1024, 16 * 1024, 128 * 1024)
            }
            // Medium files: balanced chunk size
            1_048_577..=100_000_000 => {
                // 1MB-100MB: 1MB chunks
                (1024 * 1024, 256 * 1024, 2 * 1024 * 1024)
            }
            // Large files: bigger chunks for throughput
            100_000_001..=1_000_000_000 => {
                // 100MB-1GB: 4MB chunks
                (4 * 1024 * 1024, 1024 * 1024, 8 * 1024 * 1024)
            }
            // Very large files: maximum chunk size for efficiency
            _ => {
                // >1GB: 16MB chunks
                (16 * 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024)
            }
        }
    }

    /// Determine throughput tier for a chunk based on its characteristics.
    fn determine_throughput_tier(chunk_size: u64, total_size: u64) -> ThroughputTier {
        let chunk_ratio = if total_size == 0 {
            0.0
        } else {
            chunk_size as f64 / total_size as f64
        };

        if chunk_size < 256 * 1024 || chunk_ratio < 0.01 {
            // Small chunks or small relative to total
            ThroughputTier::Tail
        } else if chunk_size >= 4 * 1024 * 1024 {
            // Large chunks optimized for bulk transfer
            ThroughputTier::Bulk
        } else {
            // Standard sized chunks
            ThroughputTier::Standard
        }
    }

    /// Absolute minimum chunk size to prevent excessive fragmentation.
    const fn absolute_min_chunk_size() -> u64 {
        4 * 1024 // 4KB minimum
    }

    /// Get recommended chunk plan for specific network characteristics.
    pub fn chunk_plan_for_network(
        object_size_bytes: u64,
        bandwidth_mbps: u64,
        latency_ms: u64,
    ) -> ChunkPlan {
        let base_plan = Self::chunk_plan(object_size_bytes);

        // Adjust for network characteristics
        let latency_factor = (latency_ms as f64 / 50.0).clamp(0.5, 4.0); // 50ms baseline
        let bandwidth_factor = (bandwidth_mbps as f64 / 100.0).clamp(0.1, 10.0); // 100Mbps baseline

        // Higher latency or lower bandwidth benefits from larger chunks
        let size_multiplier = (latency_factor * (2.0 / bandwidth_factor)).clamp(0.5, 4.0);

        let adjusted_target = (base_plan.target_chunk_size as f64 * size_multiplier) as u64;
        let adjusted_min = (base_plan.min_chunk_size as f64 * size_multiplier.min(2.0)) as u64;
        let adjusted_max = (base_plan.max_chunk_size as f64 * size_multiplier) as u64;

        ChunkPlan {
            strategy: base_plan.strategy,
            target_chunk_size: adjusted_target.min(Self::max_chunk_size()),
            min_chunk_size: adjusted_min.max(Self::absolute_min_chunk_size()),
            max_chunk_size: adjusted_max.min(Self::max_chunk_size()),
            cdc_params: None,
        }
    }

    /// Estimate transfer time for the given chunk plan and network conditions.
    pub fn estimate_transfer_time(
        object_size_bytes: u64,
        chunk_plan: &ChunkPlan,
        bandwidth_mbps: u64,
        latency_ms: u64,
    ) -> std::time::Duration {
        let safe_target = chunk_plan.target_chunk_size.max(1);
        let num_chunks = object_size_bytes.saturating_add(safe_target - 1) / safe_target;

        let transfer_time_ms =
            (object_size_bytes as f64 * 8.0) / (bandwidth_mbps.max(1) as f64 * 1000.0);
        let latency_overhead_ms = num_chunks as f64 * latency_ms as f64;

        let total_ms = transfer_time_ms + latency_overhead_ms;
        std::time::Duration::from_millis(total_ms as u64)
    }
}

#[cfg(test)]
#[path = "bulk_file_inline_tests.rs"]
mod tests;
