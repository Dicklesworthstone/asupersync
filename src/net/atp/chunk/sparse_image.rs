//! Sparse image chunking profile optimized for sparse files and VM images.
//!
//! This profile efficiently handles sparse files, virtual machine images, and other
//! data with significant holes by preserving hole metadata and avoiding unnecessary
//! transmission of null regions. It's designed for systems that support sparse files.
//!
//! Key characteristics:
//! - Hole-aware chunking that preserves sparse file structure
//! - Platform-specific hole metadata preservation where supported
//! - Efficient skip-over of large zero regions
//! - Optimized for VM images, disk images, and large sparse datasets
//! - Maintains file system hole semantics during reconstruction

use super::{
    ChunkBoundary, ChunkMetadata, ChunkingProfileError, SparseHoleMetadata,
    profiles::{ChunkingProfile as ChunkingProfileTrait, utils},
};
use crate::atp::manifest::{ChunkPlan, ChunkStrategy};
use std::collections::BTreeMap;

/// Sparse image chunking profile implementation.
pub struct SparseImageProfile;

impl ChunkingProfileTrait for SparseImageProfile {
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan {
        let (target_size, min_size, max_size) = Self::compute_chunk_sizes(object_size_bytes);

        ChunkPlan {
            strategy: ChunkStrategy::ObjectSpecific, // Sparse-aware chunking
            target_chunk_size: target_size,
            min_chunk_size: min_size,
            max_chunk_size: max_size,
            cdc_params: None, // Uses sparse-specific boundary detection
        }
    }

    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_plan = Self::chunk_plan(utils::data_len_u64(data)?);
        let sparse_regions = Self::detect_sparse_regions(data)?;

        let positions = Self::find_sparse_aware_boundaries(data, &chunk_plan, &sparse_regions)?;

        let boundaries = utils::positions_to_boundaries(
            data,
            &positions,
            ChunkStrategy::ObjectSpecific,
            |_index, offset, _size, chunk_data| {
                let (is_sparse_hole, hole_metadata) =
                    Self::analyze_chunk_sparsity(chunk_data, offset, &sparse_regions);

                ChunkMetadata::SparseImage {
                    is_sparse_hole,
                    hole_metadata,
                }
            },
        )?;

        utils::validate_boundary_ordering(&boundaries)?;
        Ok(boundaries)
    }

    fn validate_boundaries(boundaries: &[ChunkBoundary]) -> Result<(), ChunkingProfileError> {
        utils::validate_boundary_ordering(boundaries)?;

        for boundary in boundaries {
            if !matches!(boundary.strategy, ChunkStrategy::ObjectSpecific) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "sparse image profile requires object-specific chunking".to_string(),
                ));
            }

            if !matches!(boundary.metadata, Some(ChunkMetadata::SparseImage { .. })) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "sparse image profile requires SparseImage metadata".to_string(),
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

            // Validate sparse hole metadata
            if let Some(ChunkMetadata::SparseImage {
                is_sparse_hole,
                hole_metadata,
                ..
            }) = &boundary.metadata
            {
                if *is_sparse_hole && hole_metadata.is_none() {
                    return Err(ChunkingProfileError::SparseHoleDetectionFailed(
                        "sparse hole chunks must include hole metadata".to_string(),
                    ));
                }

                if let Some(metadata) = hole_metadata {
                    if metadata.hole_size > boundary.size_bytes {
                        return Err(ChunkingProfileError::SparseHoleDetectionFailed(
                            "hole size cannot exceed chunk size".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn min_chunking_threshold() -> u64 {
        // Minimum 64KB to make hole detection worthwhile
        64 * 1024
    }

    fn max_chunk_size() -> u64 {
        // Maximum 8MB for sparse images to balance hole detection and transfer efficiency
        8 * 1024 * 1024
    }

    fn supports_incremental_chunking() -> bool {
        true // Sparse detection can be done incrementally
    }
}

/// Sparse region descriptor for hole detection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SparseRegion {
    /// Start offset of the region.
    start: u64,
    /// End offset of the region.
    end: u64,
    /// Type of sparse region.
    region_type: SparseRegionType,
    /// Fill pattern for the region.
    fill_pattern: Vec<u8>,
}

/// Types of sparse regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SparseRegionType {
    /// Region filled with zeros.
    Zero,
    /// Region with repeated pattern.
    Pattern,
    /// Region with actual data.
    Data,
}

impl SparseImageProfile {
    /// Compute chunk sizes optimized for sparse images.
    fn compute_chunk_sizes(object_size_bytes: u64) -> (u64, u64, u64) {
        match object_size_bytes {
            // Small files: fine-grained chunking for hole detection
            0..=4_194_304 => {
                // Up to 4MB: 256KB chunks for good hole granularity
                (256 * 1024, 64 * 1024, 512 * 1024)
            }
            // Medium files: balanced chunking
            4_194_305..=268_435_456 => {
                // 4MB-256MB: 1MB chunks for reasonable efficiency
                (1024 * 1024, 256 * 1024, 2 * 1024 * 1024)
            }
            // Large files: bigger chunks for sparse regions
            268_435_457..=4_294_967_296 => {
                // 256MB-4GB: 4MB chunks for large VM images
                (4 * 1024 * 1024, 1024 * 1024, 8 * 1024 * 1024)
            }
            // Very large files: maximum efficiency
            _ => {
                // >4GB: 8MB chunks for large disk images
                (8 * 1024 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024)
            }
        }
    }

    /// Detect sparse regions in the data.
    fn detect_sparse_regions(data: &[u8]) -> Result<Vec<SparseRegion>, ChunkingProfileError> {
        let mut regions = Vec::new();
        let min_hole_size = 4096usize; // Minimum 4KB hole to be worth detecting

        let mut i = 0;
        while i < data.len() {
            let remaining = data.len() - i;
            let scan_size = remaining.min(1024 * 1024); // Scan in 1MB chunks
            let scan_data = &data[i..i + scan_size];

            let region = Self::analyze_region_type(
                scan_data,
                utils::usize_to_u64(i, "sparse scan offset")?,
            )?;

            let next_start = utils::u64_to_usize(region.start, "sparse region start")?;
            let next_end = utils::u64_to_usize(region.end, "sparse region end")?;

            // Only create regions for significant sparse areas
            if region.region_type != SparseRegionType::Data
                && (region.end - region.start) >= min_hole_size as u64
            {
                regions.push(region);
            }

            // Move to next region
            i = next_end;
            if i == next_start {
                // Prevent infinite loop - advance by at least 4KB
                i += min_hole_size;
            }
        }

        Ok(regions)
    }

    /// Analyze a region to determine its type and characteristics.
    fn analyze_region_type(
        data: &[u8],
        start_offset: u64,
    ) -> Result<SparseRegion, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(SparseRegion {
                start: start_offset,
                end: start_offset,
                region_type: SparseRegionType::Data,
                fill_pattern: Vec::new(),
            });
        }

        // Check for zero-filled region
        if let Some(zero_length) = Self::find_zero_run(data) {
            return Ok(SparseRegion {
                start: start_offset,
                end: start_offset.checked_add(zero_length).ok_or_else(|| {
                    ChunkingProfileError::SparseHoleDetectionFailed(
                        "zero-filled sparse region end overflow".to_string(),
                    )
                })?,
                region_type: SparseRegionType::Zero,
                fill_pattern: vec![0],
            });
        }

        // Check for pattern-filled region
        if let Some((pattern, pattern_length)) = Self::find_pattern_run(data) {
            return Ok(SparseRegion {
                start: start_offset,
                end: start_offset.checked_add(pattern_length).ok_or_else(|| {
                    ChunkingProfileError::SparseHoleDetectionFailed(
                        "pattern-filled sparse region end overflow".to_string(),
                    )
                })?,
                region_type: SparseRegionType::Pattern,
                fill_pattern: pattern,
            });
        }

        // Default to a bounded data-filled span. Sparse runs can start after a
        // short data prefix inside this scan window, so do not skip the whole
        // window as data or later holes become invisible.
        let data_span = data.len().min(4096);
        Ok(SparseRegion {
            start: start_offset,
            end: start_offset
                .checked_add(utils::usize_to_u64(data_span, "data sparse span")?)
                .ok_or_else(|| {
                    ChunkingProfileError::SparseHoleDetectionFailed(
                        "data sparse region end overflow".to_string(),
                    )
                })?,
            region_type: SparseRegionType::Data,
            fill_pattern: Vec::new(),
        })
    }

    /// Find run of zero bytes starting from the beginning.
    fn find_zero_run(data: &[u8]) -> Option<u64> {
        let min_run_length = 4096; // Minimum 4KB run to be significant

        let zero_count = data.iter().take_while(|&&b| b == 0).count();

        if zero_count >= min_run_length {
            u64::try_from(zero_count).ok()
        } else {
            None
        }
    }

    /// Find run of repeated pattern starting from the beginning.
    fn find_pattern_run(data: &[u8]) -> Option<(Vec<u8>, u64)> {
        let min_run_length = 4096;
        let max_pattern_size = 64;

        // Try different multi-byte pattern sizes. Single repeated bytes are
        // handled by zero-run detection for true holes; non-zero uniform data
        // should not be classified as a sparse pattern.
        for pattern_size in 2..=max_pattern_size.min(data.len() / 4) {
            let pattern = &data[0..pattern_size];
            if !Self::pattern_has_variation(pattern) {
                continue;
            }

            let mut run_length: usize = 0;
            let mut pos: usize = 0;

            while let Some(end) = pos.checked_add(pattern_size) {
                if end > data.len() {
                    break;
                }

                if &data[pos..end] == pattern {
                    run_length = run_length.checked_add(pattern_size)?;
                    pos = end;
                } else {
                    break;
                }
            }

            if run_length >= min_run_length {
                return Some((pattern.to_vec(), u64::try_from(run_length).ok()?));
            }
        }

        None
    }

    fn pattern_has_variation(pattern: &[u8]) -> bool {
        pattern
            .first()
            .is_some_and(|first| pattern.iter().any(|byte| byte != first))
    }

    /// Find chunk boundaries that respect sparse regions.
    fn find_sparse_aware_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
        sparse_regions: &[SparseRegion],
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        let mut boundaries = Vec::new();
        let target_size = utils::u64_to_usize(chunk_plan.target_chunk_size, "target chunk size")?;
        let min_size = utils::u64_to_usize(chunk_plan.min_chunk_size, "minimum chunk size")?;
        let max_size = utils::u64_to_usize(chunk_plan.max_chunk_size, "maximum chunk size")?;
        let merge_threshold =
            utils::checked_usize_add(target_size, min_size, "sparse remainder threshold")?;

        let mut current_pos = 0;

        while current_pos < data.len() {
            let remaining = data.len() - current_pos;

            // Check if we're at the start of a sparse region
            let sparse_region = sparse_regions.iter().find(|region| {
                utils::usize_to_u64(current_pos, "sparse current position")
                    .is_ok_and(|current| region.start == current)
            });

            let chunk_size = if let Some(region) = sparse_region {
                // Handle sparse region specially
                let region_size = region
                    .end
                    .checked_sub(region.start)
                    .ok_or_else(|| {
                        ChunkingProfileError::SparseHoleDetectionFailed(format!(
                            "sparse region end {} is before start {}",
                            region.end, region.start
                        ))
                    })
                    .and_then(|size| utils::u64_to_usize(size, "sparse region size"))?;
                match region.region_type {
                    SparseRegionType::Zero | SparseRegionType::Pattern => {
                        // For sparse regions, use larger chunks to skip over holes efficiently
                        region_size.min(max_size).min(remaining)
                    }
                    SparseRegionType::Data => {
                        // For data regions, use normal chunking
                        target_size.min(region_size).max(min_size).min(remaining)
                    }
                }
            } else if remaining <= merge_threshold {
                // Take all remaining data
                remaining
            } else {
                // Normal chunking
                target_size
            };

            current_pos = current_pos.checked_add(chunk_size).ok_or_else(|| {
                ChunkingProfileError::InvalidChunkParameters(
                    "sparse chunk position overflow".to_string(),
                )
            })?;
            boundaries.push(utils::usize_to_u64(current_pos, "sparse chunk boundary")?);
        }

        Ok(boundaries)
    }

    /// Analyze chunk for sparsity characteristics.
    fn analyze_chunk_sparsity(
        chunk_data: &[u8],
        chunk_offset: u64,
        sparse_regions: &[SparseRegion],
    ) -> (bool, Option<SparseHoleMetadata>) {
        // Check if this chunk overlaps with any sparse regions
        let chunk_end =
            chunk_offset.saturating_add(u64::try_from(chunk_data.len()).unwrap_or(u64::MAX));

        for region in sparse_regions {
            if region.start < chunk_end && region.end > chunk_offset {
                // This chunk overlaps with a sparse region
                match region.region_type {
                    SparseRegionType::Zero | SparseRegionType::Pattern => {
                        let hole_size = (region.end - region.start.max(chunk_offset))
                            .min(chunk_end - chunk_offset);

                        let mut attributes = BTreeMap::new();
                        attributes.insert("pattern".to_string(), region.fill_pattern.clone());
                        attributes.insert(
                            "region_type".to_string(),
                            format!("{:?}", region.region_type).into_bytes(),
                        );

                        let hole_metadata = SparseHoleMetadata {
                            hole_size,
                            hole_type: match region.region_type {
                                SparseRegionType::Zero => "zero-filled".to_string(),
                                SparseRegionType::Pattern => "pattern-filled".to_string(),
                                SparseRegionType::Data => "unknown".to_string(),
                            },
                            attributes,
                        };

                        return (true, Some(hole_metadata));
                    }
                    SparseRegionType::Data => {
                        // Data region, not a hole
                    }
                }
            }
        }

        // Check for inline sparsity within the chunk
        if Self::is_chunk_mostly_sparse(chunk_data) {
            let hole_metadata = SparseHoleMetadata {
                hole_size: u64::try_from(chunk_data.len()).unwrap_or(u64::MAX),
                hole_type: "inline-sparse".to_string(),
                attributes: BTreeMap::new(),
            };
            (true, Some(hole_metadata))
        } else {
            (false, None)
        }
    }

    /// Check if chunk is mostly sparse (>90% zeros or patterns).
    fn is_chunk_mostly_sparse(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        // Count zeros
        let zero_count = data
            .iter()
            .fold(0usize, |count, byte| count + usize::from(*byte == 0));
        let zero_ratio = zero_count as f64 / data.len() as f64;

        if zero_ratio >= 0.9 {
            return true;
        }

        // Check for pattern repetition
        Self::has_high_pattern_repetition(data)
    }

    /// Check if data has high pattern repetition (simple heuristic).
    fn has_high_pattern_repetition(data: &[u8]) -> bool {
        if data.len() < 1024 {
            return false;
        }

        let max_pattern_size = 64.min(data.len() / 4);
        for pattern_size in 2..=max_pattern_size {
            let pattern = &data[..pattern_size];
            if !Self::pattern_has_variation(pattern) {
                continue;
            }

            let total_blocks = data.len() / pattern_size;
            if total_blocks < 4 {
                continue;
            }

            let matching_blocks = (0..total_blocks)
                .filter(|block| {
                    let start = block * pattern_size;
                    let end = start + pattern_size;
                    &data[start..end] == pattern
                })
                .count();
            let match_ratio = matching_blocks as f64 / total_blocks as f64;

            if match_ratio > 0.8 {
                return true;
            }
        }

        false
    }

    /// Estimate compression ratio for sparse images.
    pub fn estimate_sparse_compression_ratio(boundaries: &[ChunkBoundary]) -> f64 {
        if boundaries.is_empty() {
            return 1.0;
        }

        let mut total_size = 0u64;
        let mut sparse_size = 0u64;

        for boundary in boundaries {
            total_size = total_size.saturating_add(boundary.size_bytes);

            if let Some(ChunkMetadata::SparseImage {
                is_sparse_hole,
                hole_metadata,
                ..
            }) = &boundary.metadata
            {
                if *is_sparse_hole {
                    if let Some(metadata) = hole_metadata {
                        sparse_size = sparse_size.saturating_add(metadata.hole_size);
                    } else {
                        sparse_size = sparse_size.saturating_add(boundary.size_bytes);
                    }
                }
            }
        }

        if total_size == 0 {
            1.0
        } else {
            // Compression ratio = original_size / compressed_size
            // Sparse regions compress to nearly nothing
            let mut effective_size = total_size - sparse_size + (sparse_size / 1000); // Sparse metadata overhead
            if effective_size == 0 {
                effective_size = 1;
            }
            total_size as f64 / effective_size as f64
        }
    }

    /// Get transfer order optimized for sparse images (holes last).
    pub fn get_sparse_optimized_order(boundaries: &[ChunkBoundary]) -> Vec<usize> {
        let mut indexed_boundaries: Vec<(usize, &ChunkBoundary)> =
            boundaries.iter().enumerate().collect();

        // Sort data chunks first, then holes
        indexed_boundaries.sort_by(|(a_idx, a), (b_idx, b)| {
            let a_is_sparse = matches!(
                &a.metadata,
                Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: true,
                    ..
                })
            );
            let b_is_sparse = matches!(
                &b.metadata,
                Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: true,
                    ..
                })
            );

            match (a_is_sparse, b_is_sparse) {
                (false, true) => std::cmp::Ordering::Less, // Data before holes
                (true, false) => std::cmp::Ordering::Greater, // Holes after data
                _ => a_idx.cmp(b_idx), // Maintain original order within same type
            }
        });

        indexed_boundaries.into_iter().map(|(idx, _)| idx).collect()
    }

    /// Create hole-only manifest for sparse file reconstruction.
    pub fn create_hole_manifest(boundaries: &[ChunkBoundary]) -> BTreeMap<u64, SparseHoleMetadata> {
        let mut hole_manifest = BTreeMap::new();

        for boundary in boundaries {
            if let Some(ChunkMetadata::SparseImage {
                is_sparse_hole: true,
                hole_metadata: Some(metadata),
                ..
            }) = &boundary.metadata
            {
                hole_manifest.insert(boundary.byte_offset, metadata.clone());
            }
        }

        hole_manifest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_optimize_for_sparse_detection() {
        // Small files should use smaller chunks for hole granularity
        let (target, min, max) = SparseImageProfile::compute_chunk_sizes(1_000_000);
        assert!(min <= target);
        assert!(target >= 64 * 1024);
        assert!(max <= 2 * 1024 * 1024);

        // Large files should use bigger chunks for efficiency
        let (target, min, max) = SparseImageProfile::compute_chunk_sizes(10_000_000_000);
        assert!(min <= target);
        assert!(target >= 4 * 1024 * 1024);
        assert_eq!(max, 8 * 1024 * 1024);
    }

    #[test]
    fn zero_run_detection() {
        let zero_data = vec![0u8; 8192];
        let zero_run = SparseImageProfile::find_zero_run(&zero_data);
        assert_eq!(zero_run, Some(8192));

        let non_zero_data = vec![1u8; 8192];
        let no_run = SparseImageProfile::find_zero_run(&non_zero_data);
        assert_eq!(no_run, None);

        let short_run = vec![0u8; 1000];
        let no_short_run = SparseImageProfile::find_zero_run(&short_run);
        assert_eq!(no_short_run, None); // Below minimum threshold
    }

    #[test]
    fn pattern_run_detection() {
        let pattern_data = b"ABCD".repeat(2000);
        let pattern_run = SparseImageProfile::find_pattern_run(&pattern_data);
        assert!(pattern_run.is_some());
        let (pattern, length) = pattern_run.unwrap();
        assert_eq!(pattern, b"ABCD");
        assert_eq!(length, 8000);

        let no_pattern_data = (0..8192).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let no_pattern = SparseImageProfile::find_pattern_run(&no_pattern_data);
        assert!(no_pattern.is_none());
    }

    #[test]
    fn sparse_region_detection() {
        let mut data = Vec::new();
        data.extend(vec![1u8; 1000]); // Data
        data.extend(vec![0u8; 8192]); // Zero hole
        data.extend(vec![2u8; 1000]); // More data
        data.extend(b"TEST".repeat(2000)); // Pattern hole

        let regions = SparseImageProfile::detect_sparse_regions(&data).unwrap();
        assert!(regions.len() >= 2); // Should find zero and pattern regions

        // Check for zero region
        let zero_region = regions
            .iter()
            .find(|r| r.region_type == SparseRegionType::Zero);
        assert!(zero_region.is_some());

        // Check for pattern region
        let pattern_region = regions
            .iter()
            .find(|r| r.region_type == SparseRegionType::Pattern);
        assert!(pattern_region.is_some());
    }

    #[test]
    fn chunk_sparsity_analysis() {
        let sparse_regions = vec![SparseRegion {
            start: 1000,
            end: 9000,
            region_type: SparseRegionType::Zero,
            fill_pattern: vec![0],
        }];

        // Chunk that overlaps with sparse region
        let sparse_chunk = vec![0u8; 4000];
        let (is_sparse, metadata) = SparseImageProfile::analyze_chunk_sparsity(
            &sparse_chunk,
            2000, // Overlaps with sparse region
            &sparse_regions,
        );
        assert!(is_sparse);
        assert!(metadata.is_some());

        // Chunk that doesn't overlap
        let data_chunk = vec![1u8; 1000];
        let (not_sparse, no_metadata) = SparseImageProfile::analyze_chunk_sparsity(
            &data_chunk,
            0, // Before sparse region
            &sparse_regions,
        );
        assert!(!not_sparse);
        assert!(no_metadata.is_none());
    }

    #[test]
    fn mostly_sparse_detection() {
        let mostly_zeros = {
            let mut data = vec![0u8; 9000];
            data.extend(vec![1u8; 1000]); // 10% non-zero
            data
        };
        assert!(SparseImageProfile::is_chunk_mostly_sparse(&mostly_zeros));

        let mostly_data = vec![1u8; 10000];
        assert!(!SparseImageProfile::is_chunk_mostly_sparse(&mostly_data));
    }

    #[test]
    fn pattern_repetition_detection() {
        let high_repetition = b"PATTERN".repeat(200);
        assert!(SparseImageProfile::has_high_pattern_repetition(
            &high_repetition
        ));

        let no_repetition = (0..1400).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        assert!(!SparseImageProfile::has_high_pattern_repetition(
            &no_repetition
        ));
    }

    #[test]
    fn sparse_aware_chunking() {
        let mut data = Vec::new();
        data.extend(vec![1u8; 50000]); // 50KB data
        data.extend(vec![0u8; 100000]); // 100KB zeros
        data.extend(vec![2u8; 50000]); // 50KB data

        let boundaries = SparseImageProfile::compute_boundaries(&data).unwrap();

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::ObjectSpecific));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::SparseImage { .. })
            ));
        }

        // Check that sparse regions are detected
        let has_sparse = boundaries.iter().any(|b| {
            matches!(
                b.metadata,
                Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: true,
                    ..
                })
            )
        });
        assert!(has_sparse);

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, data.len() as u64);
    }

    #[test]
    fn compression_ratio_estimation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 100000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: false,
                    hole_metadata: None,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 100000,
                size_bytes: 100000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: true,
                    hole_metadata: Some(SparseHoleMetadata {
                        hole_size: 100000,
                        hole_type: "zero-filled".to_string(),
                        attributes: BTreeMap::new(),
                    }),
                }),
            },
        ];

        let ratio = SparseImageProfile::estimate_sparse_compression_ratio(&boundaries);
        assert!(ratio > 1.0); // Should have compression benefit
        assert!(ratio < 1000.0); // But reasonable upper bound
    }

    #[test]
    fn sparse_optimized_transfer_order() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 50000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: true, // Sparse chunk
                    hole_metadata: Some(SparseHoleMetadata {
                        hole_size: 50000,
                        hole_type: "zero-filled".to_string(),
                        attributes: BTreeMap::new(),
                    }),
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 50000,
                size_bytes: 50000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: false, // Data chunk
                    hole_metadata: None,
                }),
            },
        ];

        let order = SparseImageProfile::get_sparse_optimized_order(&boundaries);

        // Data chunks should come before sparse chunks
        assert_eq!(order, vec![1, 0]); // Index 1 (data) before index 0 (sparse)
    }

    #[test]
    fn hole_manifest_creation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 50000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: false,
                    hole_metadata: None,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 50000,
                size_bytes: 100000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::SparseImage {
                    is_sparse_hole: true,
                    hole_metadata: Some(SparseHoleMetadata {
                        hole_size: 100000,
                        hole_type: "zero-filled".to_string(),
                        attributes: BTreeMap::new(),
                    }),
                }),
            },
        ];

        let hole_manifest = SparseImageProfile::create_hole_manifest(&boundaries);

        assert_eq!(hole_manifest.len(), 1);
        assert!(hole_manifest.contains_key(&50000));

        let hole_metadata = &hole_manifest[&50000];
        assert_eq!(hole_metadata.hole_size, 100000);
        assert_eq!(hole_metadata.hole_type, "zero-filled");
    }

    #[test]
    fn boundary_validation_enforces_sparse_requirements() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize, // Wrong strategy
            metadata: Some(ChunkMetadata::SparseImage {
                is_sparse_hole: false,
                hole_metadata: None,
            }),
        };

        let result = SparseImageProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());

        // Sparse hole without metadata
        let invalid_hole_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::ObjectSpecific,
            metadata: Some(ChunkMetadata::SparseImage {
                is_sparse_hole: true, // Marked as hole
                hole_metadata: None,  // But no metadata!
            }),
        };

        let result = SparseImageProfile::validate_boundaries(&[invalid_hole_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn profile_properties() {
        assert!(SparseImageProfile::supports_incremental_chunking());
        assert_eq!(SparseImageProfile::min_chunking_threshold(), 64 * 1024);
        assert_eq!(SparseImageProfile::max_chunk_size(), 8 * 1024 * 1024);
    }
}
