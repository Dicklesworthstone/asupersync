//! Sync tree chunking profile optimized for deduplication across source trees.
//!
//! This profile uses content-defined chunking (CDC) to enable efficient deduplication
//! when synchronizing source code trees, documentation, and other structured content.
//! It prioritizes deduplication efficiency over raw throughput.
//!
//! Key characteristics:
//! - Content-defined chunking for maximum deduplication
//! - Optimized for text-based content with line-oriented structure
//! - Balance between chunk size and deduplication opportunities
//! - Similarity scoring for intelligent chunk grouping
//! - Efficient handling of common code patterns (imports, headers, etc.)

use super::{
    ChunkBoundary, ChunkMetadata, ChunkingProfileError,
    profiles::{ChunkingProfile as ChunkingProfileTrait, utils},
};
use crate::atp::manifest::{CdcParams, ChunkPlan, ChunkStrategy};

/// Sync tree chunking profile implementation.
pub struct SyncTreeProfile;

impl ChunkingProfileTrait for SyncTreeProfile {
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan {
        let (target_size, min_size, max_size) = Self::compute_chunk_sizes(object_size_bytes);

        ChunkPlan {
            strategy: ChunkStrategy::ContentDefined,
            target_chunk_size: target_size,
            min_chunk_size: min_size,
            max_chunk_size: max_size,
            cdc_params: Some(Self::cdc_parameters(target_size)),
        }
    }

    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_plan = Self::chunk_plan(utils::data_len_u64(data)?);
        let cdc_params = chunk_plan.cdc_params.as_ref().ok_or_else(|| {
            ChunkingProfileError::InvalidChunkParameters(
                "sync tree profile requires CDC parameters".to_string(),
            )
        })?;

        // Use enhanced CDC that considers line structure for source code
        let positions = Self::find_enhanced_cdc_boundaries(
            data,
            usize::try_from(cdc_params.window_size).map_err(|_| {
                ChunkingProfileError::InvalidChunkParameters(format!(
                    "CDC window size {} exceeds usize::MAX",
                    cdc_params.window_size
                ))
            })?,
            chunk_plan.target_chunk_size,
            chunk_plan.min_chunk_size,
            chunk_plan.max_chunk_size,
        )?;

        let boundaries = utils::positions_to_boundaries(
            data,
            &positions,
            ChunkStrategy::ContentDefined,
            |_index, offset, _size, chunk_data| {
                let boundary_hash = Self::compute_boundary_hash(chunk_data, offset);
                let similarity_score = Self::compute_similarity_score(chunk_data);

                ChunkMetadata::SyncTree {
                    boundary_hash,
                    similarity_score,
                }
            },
        )?;

        utils::validate_boundary_ordering(&boundaries)?;
        Ok(boundaries)
    }

    fn validate_boundaries(boundaries: &[ChunkBoundary]) -> Result<(), ChunkingProfileError> {
        utils::validate_boundary_ordering(boundaries)?;

        for boundary in boundaries {
            if !matches!(boundary.strategy, ChunkStrategy::ContentDefined) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "sync tree profile requires content-defined chunking".to_string(),
                ));
            }

            if !matches!(boundary.metadata, Some(ChunkMetadata::SyncTree { .. })) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "sync tree profile requires SyncTree metadata".to_string(),
                ));
            }

            if boundary.size_bytes < Self::min_chunking_threshold() {
                return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                    "chunk size {} below minimum threshold {}",
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

        Ok(())
    }

    fn min_chunking_threshold() -> u64 {
        // Chunk files as small as 4KB for good deduplication
        4 * 1024
    }

    fn max_chunk_size() -> u64 {
        // Limit to 256KB to maintain good deduplication granularity
        256 * 1024
    }

    fn supports_incremental_chunking() -> bool {
        true // CDC can be done incrementally with rolling hash
    }
}

impl SyncTreeProfile {
    /// Compute optimal chunk sizes for sync tree operations.
    fn compute_chunk_sizes(object_size_bytes: u64) -> (u64, u64, u64) {
        match object_size_bytes {
            // Small files: fine-grained chunking for maximum deduplication
            0..=32_768 => {
                // Up to 32KB: 2KB average chunks
                (2 * 1024, 512, 8 * 1024)
            }
            // Medium files: balanced chunking
            32_769..=1_048_576 => {
                // 32KB-1MB: 8KB average chunks
                (8 * 1024, 1024, 32 * 1024)
            }
            // Large files: larger chunks but still dedupe-friendly
            1_048_577..=16_777_216 => {
                // 1MB-16MB: 16KB average chunks
                (16 * 1024, 2 * 1024, 64 * 1024)
            }
            // Very large files: maximum dedupe efficiency
            _ => {
                // >16MB: 32KB average chunks
                (32 * 1024, 4 * 1024, 128 * 1024)
            }
        }
    }

    /// Get CDC parameters optimized for source tree content.
    fn cdc_parameters(target_chunk_size: u64) -> CdcParams {
        CdcParams {
            window_size: 64, // Good balance for code content
            average_chunk_size: target_chunk_size,
            normalization: Self::normalization_constant(target_chunk_size),
        }
    }

    /// Compute normalization constant for the rolling hash.
    fn normalization_constant(avg_chunk_size: u64) -> u64 {
        // Use power of 2 based on average chunk size for efficient computation
        let bits = 64 - avg_chunk_size.leading_zeros();
        1u64 << bits.clamp(8, 20) // Clamp between 2^8 and 2^20
    }

    /// Enhanced CDC that considers line structure for better source code chunking.
    fn find_enhanced_cdc_boundaries(
        data: &[u8],
        window_size: usize,
        avg_chunk_size: u64,
        min_chunk_size: u64,
        max_chunk_size: u64,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        let data_len = utils::data_len_u64(data)?;
        if data_len < min_chunk_size {
            return Ok(vec![data_len]);
        }

        let mut boundaries = Vec::new();
        let mut rolling_hash = utils::RollingHash::new(window_size);
        let mut last_boundary = 0u64;

        // Compute mask for average chunk size
        let mask = Self::compute_cdc_mask(avg_chunk_size);

        for (i, &byte) in data.iter().enumerate() {
            let hash = rolling_hash.update(byte);
            let current_pos = utils::usize_to_u64(i, "sync-tree boundary index")?
                .checked_add(1)
                .ok_or_else(|| {
                    ChunkingProfileError::InvalidChunkParameters(format!(
                        "sync-tree boundary position overflow at index {i}"
                    ))
                })?;
            let chunk_size_since_last = current_pos - last_boundary;

            // Check for boundary conditions
            let is_boundary = if chunk_size_since_last < min_chunk_size {
                false
            } else if chunk_size_since_last >= max_chunk_size {
                true
            } else {
                // Enhanced boundary detection
                Self::is_enhanced_boundary(data, i, hash, mask, chunk_size_since_last)
            };

            if is_boundary {
                boundaries.push(current_pos);
                last_boundary = current_pos;
                rolling_hash.reset();
            }
        }

        // Add final boundary
        if last_boundary < data_len {
            boundaries.push(data_len);
        }

        Ok(boundaries)
    }

    /// Enhanced boundary detection that considers code structure.
    fn is_enhanced_boundary(
        data: &[u8],
        position: usize,
        hash: u64,
        base_mask: u64,
        chunk_size: u64,
    ) -> bool {
        // Basic rolling hash boundary
        let _hash_boundary = (hash & base_mask) == 0;

        // Line-based bonus for source code
        let line_boundary_bonus = if position > 0 && position < data.len() - 1 {
            match (data[position - 1], data[position]) {
                // End of line followed by newline
                (b'\n', _) => true,
                // End of function/class/block
                (b'}', b'\n' | b' ' | b'\t') => true,
                // Import/include statements
                _ if Self::is_at_import_boundary(data, position) => true,
                _ => false,
            }
        } else {
            false
        };

        // Reducing an all-ones CDC mask increases boundary probability.
        let mut effective_mask = if line_boundary_bonus {
            base_mask >> 1
        } else {
            base_mask
        };

        if chunk_size > 64 * 1024 {
            effective_mask >>= 1;
        }

        (hash & effective_mask) == 0
    }

    /// Check if we're at an import/include statement boundary.
    fn is_at_import_boundary(data: &[u8], position: usize) -> bool {
        if position < 10 || position + 10 >= data.len() {
            return false;
        }

        let start = position.saturating_sub(20);
        let end = (position + 20).min(data.len());
        let context = &data[start..end];

        // Look for common import/include patterns
        let context_str = std::str::from_utf8(context).unwrap_or("");
        context_str.contains("import ")
            || context_str.contains("include ")
            || context_str.contains("use ")
            || context_str.contains("from ")
            || context_str.contains("#include")
            || context_str.contains("require(")
    }

    /// Compute CDC mask for boundary detection.
    fn compute_cdc_mask(avg_chunk_size: u64) -> u64 {
        // Create mask that gives approximately the right average chunk size
        let bits = (avg_chunk_size as f64).log2() as u32;
        (1u64 << bits.clamp(8, 20)) - 1
    }

    /// Compute boundary hash for this chunk (used for deduplication hints).
    fn compute_boundary_hash(chunk_data: &[u8], offset: u64) -> u64 {
        let mut rolling_hash = utils::RollingHash::new(32);

        // Include position information for better distribution
        for byte in &offset.to_be_bytes() {
            rolling_hash.update(*byte);
        }

        // Hash first and last portions of chunk for boundary signature
        let sample_size = 64.min(chunk_data.len());
        for &byte in chunk_data.iter().take(sample_size) {
            rolling_hash.update(byte);
        }

        if chunk_data.len() > sample_size {
            for &byte in chunk_data.iter().rev().take(sample_size) {
                rolling_hash.update(byte);
            }
        }

        rolling_hash.current_hash()
    }

    /// Compute similarity score for this chunk (used for grouping similar chunks).
    fn compute_similarity_score(chunk_data: &[u8]) -> u32 {
        let mut score = 0u32;

        // Text content characteristics
        let text_ratio = Self::compute_text_ratio(chunk_data);
        score += (text_ratio * 1000.0) as u32;

        // Line count (normalized)
        let line_count = chunk_data
            .iter()
            .fold(0usize, |count, byte| count + usize::from(*byte == b'\n'));
        score += (line_count * 10).min(1000) as u32;

        // Whitespace ratio (indicates structure)
        let whitespace_count = chunk_data
            .iter()
            .filter(|&&b| b.is_ascii_whitespace())
            .count();
        let whitespace_ratio = if chunk_data.is_empty() {
            0.0
        } else {
            whitespace_count as f64 / chunk_data.len() as f64
        };
        score += (whitespace_ratio * 500.0) as u32;

        // Code pattern detection
        if Self::has_code_patterns(chunk_data) {
            score += 2000;
        }

        score
    }

    /// Compute ratio of text characters in the chunk.
    fn compute_text_ratio(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let text_bytes = data
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();

        text_bytes as f64 / data.len() as f64
    }

    /// Detect common code patterns in the chunk.
    fn has_code_patterns(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            // Look for common programming constructs
            text.contains("function ")
                || text.contains("class ")
                || text.contains("def ")
                || text.contains("fn ")
                || text.contains("impl ")
                || text.contains("struct ")
                || text.contains("enum ")
                || text.contains("interface ")
                || text.contains("module ")
                || text.contains("export ")
                || text.contains("const ")
                || text.contains("var ")
                || text.contains("let ")
        } else {
            false
        }
    }

    /// Analyze content for optimal chunking parameters.
    pub fn analyze_content_for_optimal_chunking(data: &[u8]) -> ChunkPlan {
        let text_ratio = Self::compute_text_ratio(data);
        let has_code = Self::has_code_patterns(data);

        // Adjust chunk sizes based on content analysis
        let base_plan = Self::chunk_plan(u64::try_from(data.len()).unwrap_or(u64::MAX));

        if text_ratio > 0.8 && has_code {
            // High-quality source code: use smaller chunks for better deduplication
            ChunkPlan {
                strategy: base_plan.strategy,
                target_chunk_size: base_plan.target_chunk_size / 2,
                min_chunk_size: base_plan.min_chunk_size,
                max_chunk_size: base_plan.max_chunk_size / 2,
                cdc_params: base_plan.cdc_params,
            }
        } else if text_ratio < 0.5 {
            // Binary content: use larger chunks
            ChunkPlan {
                strategy: base_plan.strategy,
                target_chunk_size: base_plan.target_chunk_size * 2,
                min_chunk_size: base_plan.min_chunk_size * 2,
                max_chunk_size: base_plan.max_chunk_size.min(Self::max_chunk_size()),
                cdc_params: base_plan.cdc_params,
            }
        } else {
            base_plan
        }
    }

    /// Estimate deduplication potential for a set of chunk boundaries.
    pub fn estimate_deduplication_ratio(boundaries: &[ChunkBoundary]) -> f64 {
        if boundaries.len() < 2 {
            return 0.0;
        }

        // Simple estimation based on chunk size distribution and similarity scores
        let mut total_similarity = 0u32;
        let mut unique_chunks = std::collections::HashSet::new();

        for boundary in boundaries {
            if let Some(ChunkMetadata::SyncTree {
                similarity_score, ..
            }) = &boundary.metadata
            {
                total_similarity += similarity_score;
                unique_chunks.insert(boundary.content_hash);
            }
        }

        let avg_similarity = total_similarity as f64 / boundaries.len() as f64;
        let unique_ratio = unique_chunks.len() as f64 / boundaries.len() as f64;

        // Higher similarity and lower unique ratio suggest better deduplication potential
        let dedup_potential = (1.0 - unique_ratio) * (avg_similarity / 5000.0).min(1.0);
        dedup_potential.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_favor_deduplication() {
        // Small file should use small chunks
        let (target, min, max) = SyncTreeProfile::compute_chunk_sizes(16_384);
        assert!(min >= 256);
        assert!(target <= 8 * 1024);
        assert!(max <= 32 * 1024);

        // Large file should still keep chunks reasonable for dedup
        let (target, min, max) = SyncTreeProfile::compute_chunk_sizes(100_000_000);
        assert!(min >= 4 * 1024);
        assert!(target <= 32 * 1024);
        assert!(max <= 128 * 1024);
    }

    #[test]
    fn cdc_parameters_are_reasonable() {
        let params = SyncTreeProfile::cdc_parameters(8192);
        assert_eq!(params.window_size, 64);
        assert_eq!(params.average_chunk_size, 8192);
        assert!(params.normalization > 0);
    }

    #[test]
    fn text_ratio_computation() {
        let text_data = b"hello world\nthis is text\n";
        let ratio = SyncTreeProfile::compute_text_ratio(text_data);
        assert!(ratio > 0.9);

        let binary_data = &[0u8, 1u8, 2u8, 255u8, 254u8];
        let ratio = SyncTreeProfile::compute_text_ratio(binary_data);
        assert!(ratio < 0.5);
    }

    #[test]
    fn code_pattern_detection() {
        let code_data = b"function test() {\n  return 42;\n}";
        assert!(SyncTreeProfile::has_code_patterns(code_data));

        let plain_text = b"this is just plain text without code";
        assert!(!SyncTreeProfile::has_code_patterns(plain_text));
    }

    #[test]
    fn import_boundary_detection() {
        let code_with_import = b"import numpy as np\nfrom collections import defaultdict\n";
        // This would be called at position of newline after import
        let pos = code_with_import.iter().position(|&b| b == b'\n').unwrap();
        assert!(SyncTreeProfile::is_at_import_boundary(
            code_with_import,
            pos
        ));
    }

    #[test]
    fn enhanced_chunking_creates_boundaries() {
        let code_data = b"import os\nimport sys\n\ndef function1():\n    return 42\n\ndef function2():\n    return 84\n";
        let boundaries = SyncTreeProfile::compute_boundaries(code_data).unwrap();

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::ContentDefined));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::SyncTree { .. })
            ));
        }

        // Validate coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, code_data.len() as u64);
    }

    #[test]
    fn similarity_score_varies_by_content() {
        let code_chunk = b"function test() {\n  return 42;\n}";
        let text_chunk = b"this is plain text content";
        let binary_chunk = &[0u8, 1u8, 2u8, 255u8, 254u8];

        let code_score = SyncTreeProfile::compute_similarity_score(code_chunk);
        let text_score = SyncTreeProfile::compute_similarity_score(text_chunk);
        let binary_score = SyncTreeProfile::compute_similarity_score(binary_chunk);

        // Code should have highest score due to patterns
        assert!(code_score > text_score);
        assert!(text_score > binary_score);
    }

    #[test]
    fn boundary_validation_enforces_cdc() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 8192,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize, // Wrong for sync tree!
            metadata: Some(ChunkMetadata::SyncTree {
                boundary_hash: 12345,
                similarity_score: 1000,
            }),
        };

        let result = SyncTreeProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn content_analysis_adjusts_chunk_plan() {
        let code_data = b"fn main() {\n    println!(\"hello\");\n}\n".repeat(100);
        let binary_data = vec![0u8; 1000];

        let code_plan = SyncTreeProfile::analyze_content_for_optimal_chunking(&code_data);
        let binary_plan = SyncTreeProfile::analyze_content_for_optimal_chunking(&binary_data);

        // Code should use smaller chunks for better deduplication
        assert!(code_plan.target_chunk_size < binary_plan.target_chunk_size);
    }

    #[test]
    fn deduplication_ratio_estimation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 1000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::SyncTree {
                    boundary_hash: 123,
                    similarity_score: 3000,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 1000,
                size_bytes: 1000,
                content_hash: [1; 32], // Same hash = potential duplication
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::SyncTree {
                    boundary_hash: 456,
                    similarity_score: 3500,
                }),
            },
        ];

        let ratio = SyncTreeProfile::estimate_deduplication_ratio(&boundaries);
        assert!(ratio > 0.0);
        assert!(ratio <= 1.0);
    }

    #[test]
    fn profile_properties() {
        assert!(SyncTreeProfile::supports_incremental_chunking());
        assert_eq!(SyncTreeProfile::min_chunking_threshold(), 4 * 1024);
        assert_eq!(SyncTreeProfile::max_chunk_size(), 256 * 1024);
    }

    #[test]
    fn cdc_mask_computation() {
        let mask_small = SyncTreeProfile::compute_cdc_mask(1024);
        let mask_large = SyncTreeProfile::compute_cdc_mask(32768);

        // Larger average chunk size should result in a larger mask, which
        // lowers the chance that `(hash & mask) == 0`.
        assert!(mask_large > mask_small);
    }

    #[test]
    fn line_boundary_bonus_increases_boundary_probability() {
        let base_mask = 0b11_1111;
        let hash = 0b10_0000;

        assert!(!SyncTreeProfile::is_enhanced_boundary(
            b"abcd", 2, hash, base_mask, 1024,
        ));
        assert!(SyncTreeProfile::is_enhanced_boundary(
            b"a\nbc", 2, hash, base_mask, 1024,
        ));
    }

    #[test]
    fn normalization_constant_scaling() {
        let norm_small = SyncTreeProfile::normalization_constant(1024);
        let norm_large = SyncTreeProfile::normalization_constant(32768);

        assert!(norm_small < norm_large);
        assert!(norm_small >= 256); // At least 2^8
        assert!(norm_large <= 1048576); // At most 2^20
    }
}
