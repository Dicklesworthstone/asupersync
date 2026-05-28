//! Media chunking profile optimized for streaming and progressive delivery.
//!
//! This profile is designed for media files, ML models, and other content that benefits
//! from prefix-friendly delivery where earlier chunks can be consumed before the entire
//! object is available. It balances streaming efficiency with reasonable chunk sizes.
//!
//! Key characteristics:
//! - Prefix-friendly chunking for progressive decoding/processing
//! - Keyframe-aware boundaries for video content
//! - Priority-based chunk ordering for quality-progressive delivery
//! - Optimized for streaming consumption patterns
//! - Adaptive sizing based on content type detection

use super::{
    ChunkBoundary, ChunkMetadata, ChunkingProfileError,
    profiles::{ChunkingProfile as ChunkingProfileTrait, utils},
};
use crate::atp::manifest::{ChunkPlan, ChunkStrategy};

/// Media chunking profile implementation.
pub struct MediaProfile;

impl ChunkingProfileTrait for MediaProfile {
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan {
        let (target_size, min_size, max_size) = Self::compute_chunk_sizes(object_size_bytes);

        ChunkPlan {
            strategy: ChunkStrategy::ObjectSpecific, // Media-aware chunking
            target_chunk_size: target_size,
            min_chunk_size: min_size,
            max_chunk_size: max_size,
            cdc_params: None, // Media chunking uses content-specific boundaries
        }
    }

    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_plan = Self::chunk_plan(utils::data_len_u64(data)?);
        let content_type = Self::detect_content_type(data);

        let positions = match content_type {
            MediaContentType::Video => Self::find_video_boundaries(data, &chunk_plan)?,
            MediaContentType::Audio => Self::find_audio_boundaries(data, &chunk_plan)?,
            MediaContentType::Image => Self::find_image_boundaries(data, &chunk_plan)?,
            MediaContentType::Model => Self::find_model_boundaries(data, &chunk_plan)?,
            MediaContentType::Unknown => Self::find_generic_media_boundaries(data, &chunk_plan)?,
        };

        let boundaries = utils::positions_to_boundaries(
            data,
            &positions,
            ChunkStrategy::ObjectSpecific,
            |index, _offset, _size, chunk_data| {
                let is_keyframe_boundary =
                    Self::is_keyframe_boundary(chunk_data, &content_type, index);
                let decoding_priority = Self::compute_decoding_priority(
                    chunk_data,
                    &content_type,
                    index,
                    positions.len(),
                );

                ChunkMetadata::Media {
                    is_keyframe_boundary,
                    decoding_priority,
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
                    "media profile requires object-specific chunking".to_string(),
                ));
            }

            if !matches!(boundary.metadata, Some(ChunkMetadata::Media { .. })) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "media profile requires Media metadata".to_string(),
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

            // Validate priority range
            if let Some(ChunkMetadata::Media {
                decoding_priority, ..
            }) = &boundary.metadata
            {
                if *decoding_priority > 100 {
                    return Err(ChunkingProfileError::InvalidChunkParameters(format!(
                        "decoding priority {} above maximum 100",
                        decoding_priority
                    )));
                }
            }
        }

        Ok(())
    }

    fn min_chunking_threshold() -> u64 {
        // Minimum 16KB for streaming efficiency
        16 * 1024
    }

    fn max_chunk_size() -> u64 {
        // Maximum 2MB to maintain responsive streaming
        2 * 1024 * 1024
    }

    fn supports_incremental_chunking() -> bool {
        true // Media streaming benefits from incremental processing
    }
}

/// Detected media content types for chunking optimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaContentType {
    /// Video content (MP4, AVI, WebM, etc.)
    Video,
    /// Audio content (MP3, WAV, FLAC, etc.)
    Audio,
    /// Image content (JPEG, PNG, WebP, etc.)
    Image,
    /// ML model data (PyTorch, TensorFlow, ONNX, etc.)
    Model,
    /// Unknown media type
    Unknown,
}

impl MediaProfile {
    fn contains_signature(data: &[u8], signature: &[u8]) -> bool {
        !signature.is_empty()
            && data
                .windows(signature.len())
                .any(|window| window == signature)
    }

    /// Compute chunk sizes optimized for media streaming.
    fn compute_chunk_sizes(object_size_bytes: u64) -> (u64, u64, u64) {
        match object_size_bytes {
            // Small files: preserve for atomic delivery
            0..=262_144 => {
                // Up to 256KB: single chunk or minimal splitting
                (128 * 1024, 16 * 1024, 256 * 1024)
            }
            // Medium files: optimize for streaming startup
            262_145..=16_777_216 => {
                // 256KB-16MB: 256KB chunks for quick startup
                (256 * 1024, 64 * 1024, 512 * 1024)
            }
            // Large files: balance between startup and throughput
            16_777_217..=268_435_456 => {
                // 16MB-256MB: 512KB chunks
                (512 * 1024, 128 * 1024, 1024 * 1024)
            }
            // Very large files: optimize for sustained streaming
            _ => {
                // >256MB: 1MB chunks for sustained throughput
                (1024 * 1024, 256 * 1024, 2 * 1024 * 1024)
            }
        }
    }

    /// Detect content type from data header/magic bytes.
    fn detect_content_type(data: &[u8]) -> MediaContentType {
        if data.is_empty() {
            return MediaContentType::Unknown;
        }

        // Check common video formats
        if data.starts_with(b"\x00\x00\x00\x18ftypmp4") || // MP4
           data.starts_with(b"\x00\x00\x00\x20ftypisom") || // ISO MP4
           data.starts_with(b"RIFF") && data.get(8..12) == Some(b"AVI ") || // AVI
           data.starts_with(b"\x1A\x45\xDF\xA3")
        // WebM/Matroska
        {
            return MediaContentType::Video;
        }

        // Check common audio formats
        if data.starts_with(b"ID3") || // MP3 with ID3
           data.starts_with(b"\xFF\xFB") || data.starts_with(b"\xFF\xFA") || // MP3
           data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WAVE") || // WAV
           data.starts_with(b"fLaC") || // FLAC
           data.starts_with(b"OggS")
        // Ogg
        {
            return MediaContentType::Audio;
        }

        // Check common image formats
        if data.starts_with(b"\xFF\xD8\xFF") || // JPEG
           data.starts_with(b"\x89PNG\r\n\x1A\n") || // PNG
           data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") || // WebP
           data.starts_with(b"GIF8")
        // GIF
        {
            return MediaContentType::Image;
        }

        // Check ML model formats
        if data.starts_with(b"PK\x03\x04") && // ZIP-based formats
           (Self::contains_signature(data, b"pytorch_model.bin") ||
            Self::contains_signature(data, b"saved_model.pb") ||
            Self::contains_signature(data, b"model.onnx"))
        {
            return MediaContentType::Model;
        }

        MediaContentType::Unknown
    }

    /// Find chunk boundaries for video content.
    fn find_video_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        Self::find_marker_aligned_boundaries(
            data,
            chunk_plan,
            1024,
            Self::is_video_frame_boundary,
            "media video",
        )
    }

    /// Find chunk boundaries for audio content.
    fn find_audio_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        Self::find_marker_aligned_boundaries(
            data,
            chunk_plan,
            512,
            Self::is_audio_frame_boundary,
            "media audio",
        )
    }

    /// Find chunk boundaries for image content.
    fn find_image_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        // Images: try to align with scan lines or progressive layers
        let mut boundaries = Vec::new();
        let target_size = utils::u64_to_usize(chunk_plan.target_chunk_size, "target chunk size")?;
        let data_len = utils::data_len_u64(data)?;

        // Simple progressive chunking for images
        let mut pos = 0;
        while pos < data.len() {
            pos = utils::checked_usize_add(pos, target_size, "media image boundary")?;
            if pos < data.len() {
                boundaries.push(utils::usize_to_u64(pos, "media image boundary")?);
            }
        }

        if boundaries.last().copied().unwrap_or(0) < data_len {
            boundaries.push(data_len);
        }

        Ok(boundaries)
    }

    /// Find chunk boundaries for ML model data.
    fn find_model_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        Self::find_marker_aligned_boundaries(
            data,
            chunk_plan,
            4096,
            Self::is_model_layer_boundary,
            "media model",
        )
    }

    /// Find generic media boundaries using fixed sizing.
    fn find_generic_media_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        Self::find_fixed_boundaries(data, chunk_plan)
    }

    /// Find fixed-size boundaries as fallback.
    fn find_fixed_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        let mut boundaries = Vec::new();
        let target_size = utils::u64_to_usize(chunk_plan.target_chunk_size, "target chunk size")?;
        let min_size = utils::u64_to_usize(chunk_plan.min_chunk_size, "minimum chunk size")?;
        let merge_threshold =
            utils::checked_usize_add(target_size, min_size, "media fixed remainder threshold")?;

        let mut pos = 0;
        while pos < data.len() {
            let remaining = data.len() - pos;
            let chunk_size = if remaining <= merge_threshold {
                remaining
            } else {
                target_size
            };

            pos = utils::checked_usize_add(pos, chunk_size, "media fixed boundary")?;
            boundaries.push(utils::usize_to_u64(pos, "media fixed boundary")?);
        }

        Ok(boundaries)
    }

    fn find_marker_aligned_boundaries(
        data: &[u8],
        chunk_plan: &ChunkPlan,
        scan_step: usize,
        is_boundary: fn(&[u8]) -> bool,
        label: &'static str,
    ) -> Result<Vec<u64>, ChunkingProfileError> {
        let mut boundaries = Vec::new();
        let target_size = utils::u64_to_usize(chunk_plan.target_chunk_size, "target chunk size")?;
        let min_size = utils::u64_to_usize(chunk_plan.min_chunk_size, "minimum chunk size")?;
        let max_size = utils::u64_to_usize(chunk_plan.max_chunk_size, "maximum chunk size")?;
        let merge_threshold =
            utils::checked_usize_add(target_size, min_size, "media aligned remainder threshold")?;
        let data_len = utils::data_len_u64(data)?;

        let mut last_boundary = 0usize;
        let mut current_pos = 0usize;
        while last_boundary < data.len() {
            let remaining = data.len() - last_boundary;
            if remaining <= merge_threshold {
                boundaries.push(data_len);
                break;
            }

            let chunk_size = current_pos.saturating_sub(last_boundary);
            let boundary_pos = if chunk_size >= max_size
                || (chunk_size >= min_size && is_boundary(&data[current_pos..]))
            {
                Some(current_pos)
            } else {
                None
            };

            if let Some(pos) = boundary_pos.filter(|pos| *pos > last_boundary) {
                boundaries.push(utils::usize_to_u64(pos, label)?);
                last_boundary = pos;
                current_pos = pos;
                continue;
            }

            if current_pos >= data.len() {
                boundaries.push(data_len);
                break;
            }

            current_pos = utils::checked_usize_add(current_pos, scan_step, label)?.min(data.len());
        }

        if boundaries.last().copied().unwrap_or(0) < data_len {
            boundaries.push(data_len);
        }

        Ok(boundaries)
    }

    /// Check if position is at a video frame boundary.
    fn is_video_frame_boundary(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        // Look for common frame start codes
        data.starts_with(b"\x00\x00\x00\x01") || // H.264/H.265 start code
        data.starts_with(b"\x00\x00\x01") ||     // MPEG start code
        data.starts_with(b"\xFF\xFE") ||         // Some video formats
        (data[0] == 0x1A && data[1] == 0x45) // WebM cluster start
    }

    fn is_audio_frame_boundary(data: &[u8]) -> bool {
        data.starts_with(b"ID3")
            || data.starts_with(b"OggS")
            || data.starts_with(b"fLaC")
            || data.starts_with(b"RIFF")
            || (data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xF0) == 0xF0)
    }

    fn is_model_layer_boundary(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        if data.starts_with(b"ONNX")
            || data.starts_with(b"PK\x03\x04")
            || data.starts_with(b"NUMPY")
            || data.windows(8).take(4).any(|w| w == b"safetens")
        {
            return true;
        }

        let prefix = String::from_utf8_lossy(&data[..data.len().min(256)]).to_ascii_lowercase();
        prefix.contains("\"weight\"")
            || prefix.contains("\"tensor\"")
            || prefix.contains("\"layer\"")
            || prefix.contains("module.")
            || prefix.contains("state_dict")
    }

    /// Determine if this chunk represents a keyframe boundary.
    fn is_keyframe_boundary(
        chunk_data: &[u8],
        content_type: &MediaContentType,
        chunk_index: u32,
    ) -> bool {
        match content_type {
            MediaContentType::Video => {
                // First chunk is usually a keyframe
                if chunk_index == 0 {
                    return true;
                }

                // Look for keyframe indicators
                chunk_data.windows(4).any(|w| w == b"\x00\x00\x00\x01") && chunk_data.len() > 100 // Reasonable keyframe size
            }
            MediaContentType::Image => {
                // First chunk of progressive images
                chunk_index == 0 || (chunk_index < 3 && chunk_data.len() > 1024)
            }
            MediaContentType::Model => {
                // Model header chunks
                chunk_index < 2
            }
            _ => {
                // Audio and unknown: periodic keyframe boundaries
                chunk_index % 10 == 0
            }
        }
    }

    /// Compute decoding priority for this chunk (0-100, higher = more important).
    fn compute_decoding_priority(
        chunk_data: &[u8],
        content_type: &MediaContentType,
        chunk_index: u32,
        total_chunks: usize,
    ) -> u8 {
        let base_priority = match content_type {
            MediaContentType::Video | MediaContentType::Audio => {
                // Earlier chunks more important for streaming
                let position_factor = if total_chunks == 0 {
                    1.0
                } else {
                    1.0 - (chunk_index as f64 / total_chunks as f64)
                };
                (80.0 * position_factor + 20.0) as u8
            }
            MediaContentType::Image => {
                // Progressive image: base layer most important
                if chunk_index == 0 {
                    100
                } else if chunk_index < 3 {
                    80
                } else {
                    50
                }
            }
            MediaContentType::Model => {
                // Model metadata and early layers most important
                if chunk_index < 5 {
                    90u8 - (chunk_index as u8 * 10)
                } else {
                    50
                }
            }
            MediaContentType::Unknown => {
                // Default progressive priority
                if chunk_index == 0 { 90 } else { 70 }
            }
        };

        // Bonus for larger chunks (more content)
        let size_bonus = if chunk_data.len() > 100_000 {
            5
        } else if chunk_data.len() > 10_000 {
            3
        } else {
            0
        };

        (base_priority + size_bonus).min(100)
    }

    /// Get streaming order for chunks based on priority.
    pub fn get_streaming_order(boundaries: &[ChunkBoundary]) -> Vec<usize> {
        let mut indexed_boundaries: Vec<(usize, &ChunkBoundary)> =
            boundaries.iter().enumerate().collect();

        // Sort by priority (descending), then by index (ascending) for ties
        indexed_boundaries.sort_by(|(a_idx, a), (b_idx, b)| {
            let a_priority = if let Some(ChunkMetadata::Media {
                decoding_priority, ..
            }) = &a.metadata
            {
                *decoding_priority
            } else {
                0
            };

            let b_priority = if let Some(ChunkMetadata::Media {
                decoding_priority, ..
            }) = &b.metadata
            {
                *decoding_priority
            } else {
                0
            };

            // Higher priority first, then earlier chunks
            b_priority.cmp(&a_priority).then(a_idx.cmp(b_idx))
        });

        indexed_boundaries.into_iter().map(|(idx, _)| idx).collect()
    }

    /// Estimate streaming startup latency for the given chunk plan.
    pub fn estimate_startup_latency(
        boundaries: &[ChunkBoundary],
        bandwidth_mbps: u64,
        latency_ms: u64,
    ) -> std::time::Duration {
        if boundaries.is_empty() {
            return std::time::Duration::from_millis(0);
        }

        // Find the minimum set of chunks needed for startup
        let startup_chunks = Self::get_startup_chunk_set(boundaries);

        let startup_bytes = startup_chunks.iter().fold(0u64, |acc, &idx| {
            acc.saturating_add(boundaries[idx].size_bytes)
        });

        let transfer_time_ms =
            (startup_bytes as f64 * 8.0) / (bandwidth_mbps.max(1) as f64 * 1000.0);
        let latency_overhead_ms = startup_chunks.len() as f64 * latency_ms as f64;

        let total_ms = transfer_time_ms + latency_overhead_ms;
        std::time::Duration::from_millis(total_ms as u64)
    }

    /// Get the minimum set of chunks needed for streaming startup.
    fn get_startup_chunk_set(boundaries: &[ChunkBoundary]) -> Vec<usize> {
        let mut startup_chunks = Vec::new();
        let mut accumulated_size = 0u64;
        const STARTUP_THRESHOLD: u64 = 256 * 1024; // 256KB for startup

        // Get chunks in streaming order
        let streaming_order = Self::get_streaming_order(boundaries);

        for &chunk_idx in &streaming_order {
            startup_chunks.push(chunk_idx);
            accumulated_size += boundaries[chunk_idx].size_bytes;

            // Check if we have enough for startup
            if accumulated_size >= STARTUP_THRESHOLD || startup_chunks.len() >= 3 {
                break;
            }
        }

        startup_chunks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_optimize_for_streaming() {
        // Small files should avoid over-chunking
        let (target, min, max) = MediaProfile::compute_chunk_sizes(100_000);
        assert!(target >= min);
        assert!(target <= max);
        assert!(max <= 512 * 1024); // Reasonable for small files

        // Large files should use bigger chunks for efficiency
        let (target, min, max) = MediaProfile::compute_chunk_sizes(100_000_000);
        assert!(min <= target);
        assert!(target >= 256 * 1024); // At least 256KB for large files
        assert!(max <= 2 * 1024 * 1024); // But not too large for streaming
    }

    #[test]
    fn content_type_detection() {
        // Test MP4 detection
        let mp4_header = b"\x00\x00\x00\x18ftypmp4\x00\x00\x00\x00";
        assert_eq!(
            MediaProfile::detect_content_type(mp4_header),
            MediaContentType::Video
        );

        // Test PNG detection
        let png_header = b"\x89PNG\r\n\x1A\n\x00\x00\x00\rIHDR";
        assert_eq!(
            MediaProfile::detect_content_type(png_header),
            MediaContentType::Image
        );

        // Test MP3 detection
        let mp3_header = b"ID3\x03\x00\x00\x00\x00\x00\x00";
        assert_eq!(
            MediaProfile::detect_content_type(mp3_header),
            MediaContentType::Audio
        );

        let pytorch_zip = b"PK\x03\x04metadata/pytorch_model.bin";
        assert_eq!(
            MediaProfile::detect_content_type(pytorch_zip),
            MediaContentType::Model
        );

        let saved_model_zip = b"PK\x03\x04assets/saved_model.pb";
        assert_eq!(
            MediaProfile::detect_content_type(saved_model_zip),
            MediaContentType::Model
        );

        // Test unknown
        let unknown_header = b"unknown format here";
        assert_eq!(
            MediaProfile::detect_content_type(unknown_header),
            MediaContentType::Unknown
        );
    }

    #[test]
    fn video_frame_boundary_detection() {
        let h264_start = b"\x00\x00\x00\x01\x67\x42\x00\x1E";
        assert!(MediaProfile::is_video_frame_boundary(h264_start));

        let not_boundary = b"random video data here";
        assert!(!MediaProfile::is_video_frame_boundary(not_boundary));
    }

    #[test]
    fn keyframe_boundary_detection() {
        // First chunk of video should be keyframe
        let video_data = b"some video chunk data";
        assert!(MediaProfile::is_keyframe_boundary(
            video_data,
            &MediaContentType::Video,
            0
        ));

        // Later chunks with start codes
        let keyframe_data = b"\x00\x00\x00\x01".repeat(50);
        assert!(MediaProfile::is_keyframe_boundary(
            &keyframe_data,
            &MediaContentType::Video,
            5
        ));

        // First chunk of image is keyframe
        assert!(MediaProfile::is_keyframe_boundary(
            b"image data",
            &MediaContentType::Image,
            0
        ));
    }

    #[test]
    fn decoding_priority_computation() {
        // First chunk should have high priority
        let priority = MediaProfile::compute_decoding_priority(
            &vec![0u8; 1000],
            &MediaContentType::Video,
            0,
            10,
        );
        assert!(priority >= 90);

        // Last chunk should have lower priority
        let priority = MediaProfile::compute_decoding_priority(
            &vec![0u8; 1000],
            &MediaContentType::Video,
            9,
            10,
        );
        assert!(priority < 50);

        // Large chunks get size bonus
        let priority_large = MediaProfile::compute_decoding_priority(
            &vec![0u8; 200_000],
            &MediaContentType::Video,
            5,
            10,
        );
        let priority_small = MediaProfile::compute_decoding_priority(
            &vec![0u8; 1000],
            &MediaContentType::Video,
            5,
            10,
        );
        assert!(priority_large > priority_small);
    }

    #[test]
    fn chunking_creates_media_boundaries() {
        let video_data = b"\x00\x00\x00\x18ftypmp4\x00".repeat(1000);
        let boundaries =
            MediaProfile::compute_boundaries(&video_data).expect("media chunking should succeed");

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::ObjectSpecific));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::Media { .. })
            ));
        }

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, video_data.len() as u64);
    }

    #[test]
    fn streaming_order_respects_priority() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 1000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: true,
                    decoding_priority: 100,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 1000,
                size_bytes: 1000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 50,
                }),
            },
            ChunkBoundary {
                index: 2,
                byte_offset: 2000,
                size_bytes: 1000,
                content_hash: [3; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 75,
                }),
            },
        ];

        let order = MediaProfile::get_streaming_order(&boundaries);

        // Should be ordered by priority: 100, 75, 50
        assert_eq!(order, vec![0, 2, 1]);
    }

    #[test]
    fn startup_latency_estimation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 100_000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: true,
                    decoding_priority: 100,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 100_000,
                size_bytes: 200_000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 80,
                }),
            },
        ];

        let latency = MediaProfile::estimate_startup_latency(&boundaries, 100, 50);
        assert!(latency > std::time::Duration::from_millis(50)); // At least one RTT
        assert!(latency < std::time::Duration::from_secs(5)); // Reasonable for startup
    }

    #[test]
    fn boundary_validation_enforces_media_requirements() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 1000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize, // Wrong strategy
            metadata: Some(ChunkMetadata::Media {
                is_keyframe_boundary: false,
                decoding_priority: 50,
            }),
        };

        let result = MediaProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());

        // Priority out of range
        let invalid_priority_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100_000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::ObjectSpecific,
            metadata: Some(ChunkMetadata::Media {
                is_keyframe_boundary: false,
                decoding_priority: 150, // Invalid priority > 100
            }),
        };

        let result = MediaProfile::validate_boundaries(&[invalid_priority_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn profile_properties() {
        assert!(MediaProfile::supports_incremental_chunking());
        assert_eq!(MediaProfile::min_chunking_threshold(), 16 * 1024);
        assert_eq!(MediaProfile::max_chunk_size(), 2 * 1024 * 1024);
    }

    #[test]
    fn startup_chunk_set_selection() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 50_000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: true,
                    decoding_priority: 100,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 50_000,
                size_bytes: 100_000,
                content_hash: [2; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 90,
                }),
            },
            ChunkBoundary {
                index: 2,
                byte_offset: 150_000,
                size_bytes: 200_000,
                content_hash: [3; 32],
                strategy: ChunkStrategy::ObjectSpecific,
                metadata: Some(ChunkMetadata::Media {
                    is_keyframe_boundary: false,
                    decoding_priority: 80,
                }),
            },
        ];

        let startup_set = MediaProfile::get_startup_chunk_set(&boundaries);

        // Should include enough chunks for 256KB threshold
        let startup_bytes: u64 = startup_set
            .iter()
            .map(|&idx| boundaries[idx].size_bytes)
            .sum();
        assert!(startup_bytes >= 256 * 1024);
    }
}
