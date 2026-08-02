//! Artifact chunking profile optimized for build reproducibility and proof strength.
//!
//! This profile is designed for build artifacts, software packages, and other content
//! where reproducibility and cryptographic proof strength are critical. It provides
//! deterministic chunking that enables strong verification guarantees.
//!
//! Key characteristics:
//! - Deterministic chunking for reproducible builds
//! - Strong cryptographic proof generation
//! - Build context preservation for verification
//! - Content-defined chunking for deduplication benefits
//! - Optimized for software artifacts and packages

use super::{
    ChunkingProfileError,
    profiles::{ChunkingProfile as ChunkingProfileTrait, utils},
};
use crate::atp::manifest::{
    ArtifactBuildContext, CdcParams, ChunkBoundary, ChunkMetadata, ChunkPlan, ChunkStrategy,
    ProofStrength,
};
use sha2::{Digest, Sha256};

/// Maximum artifact prefix inspected for a version token.
///
/// This matches the pre-existing artifact metadata sample, preserving the Rust
/// marker's search reach while keeping work independent of artifact size.
const MAX_VERSION_SCAN_BYTES: usize = 2000;

/// The legacy non-Rust marker path searched a single 50-byte area.
const NON_RUST_VERSION_SCAN_BYTES: usize = 50;

/// Maximum accepted version token length.
///
/// Conventional compiler releases fit comfortably within this limit. The
/// bound intentionally rejects the legacy Rust fast path's remainder-of-sample
/// whitespace token (including oversized or non-grammar text) instead of
/// persisting an arbitrary metadata field.
const MAX_VERSION_TOKEN_BYTES: usize = 64;

const TOOLCHAIN_MARKERS: &[(&str, &str, usize, Option<usize>)] = &[
    ("rustc", "rustc", MAX_VERSION_SCAN_BYTES, None),
    ("gcc", "gcc", NON_RUST_VERSION_SCAN_BYTES, Some(3)),
    ("clang", "clang", NON_RUST_VERSION_SCAN_BYTES, Some(3)),
    ("go", "go", NON_RUST_VERSION_SCAN_BYTES, Some(3)),
    ("javac", "java", NON_RUST_VERSION_SCAN_BYTES, Some(3)),
    ("java", "java", NON_RUST_VERSION_SCAN_BYTES, Some(3)),
];

/// Artifact chunking profile implementation.
pub struct ArtifactProfile;

impl ChunkingProfileTrait for ArtifactProfile {
    fn chunk_plan(object_size_bytes: u64) -> ChunkPlan {
        let (target_size, min_size, max_size) = Self::compute_chunk_sizes(object_size_bytes);

        ChunkPlan {
            strategy: ChunkStrategy::ContentDefined, // Deterministic CDC for reproducibility
            target_chunk_size: target_size,
            min_chunk_size: min_size,
            max_chunk_size: max_size,
            cdc_params: Some(Self::deterministic_cdc_parameters(target_size)),
        }
    }

    fn compute_boundaries(data: &[u8]) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let chunk_plan = Self::chunk_plan(utils::data_len_u64(data)?);
        let cdc_params = chunk_plan.cdc_params.as_ref().ok_or_else(|| {
            ChunkingProfileError::InvalidChunkParameters(
                "artifact profile requires deterministic CDC parameters".to_string(),
            )
        })?;

        // Use deterministic boundary detection
        let positions = Self::find_deterministic_boundaries(
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

        let build_context = Self::derive_build_context(data);

        let boundaries = utils::positions_to_boundaries(
            data,
            &positions,
            ChunkStrategy::ContentDefined,
            |index, _offset, _size, chunk_data| {
                let proof_strength = Self::compute_proof_strength(chunk_data, index);

                ChunkMetadata::Artifact {
                    build_context: build_context.clone(),
                    proof_strength,
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
                    "artifact profile requires content-defined chunking".to_string(),
                ));
            }

            if !matches!(boundary.metadata, Some(ChunkMetadata::Artifact { .. })) {
                return Err(ChunkingProfileError::InvalidChunkParameters(
                    "artifact profile requires Artifact metadata".to_string(),
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

            // Validate build context
            if let Some(ChunkMetadata::Artifact { build_context, .. }) = &boundary.metadata {
                Self::validate_build_context(build_context)?;
            }
        }

        Ok(())
    }

    fn min_chunking_threshold() -> u64 {
        // Minimum 8KB for meaningful deduplication of artifacts
        8 * 1024
    }

    fn max_chunk_size() -> u64 {
        // Maximum 512KB to maintain good deduplication granularity
        512 * 1024
    }

    fn supports_incremental_chunking() -> bool {
        true // Deterministic CDC supports incremental processing
    }
}

impl ArtifactProfile {
    /// Compute chunk sizes optimized for artifact deduplication and verification.
    fn compute_chunk_sizes(object_size_bytes: u64) -> (u64, u64, u64) {
        match object_size_bytes {
            // Small files: fine-grained chunking for maximum deduplication
            0..=65_536 => {
                // Up to 64KB: 4KB average chunks
                (4 * 1024, 1024, 16 * 1024)
            }
            // Medium files: balanced for typical source files/libraries
            65_537..=1_048_576 => {
                // 64KB-1MB: 16KB average chunks
                (16 * 1024, 4 * 1024, 64 * 1024)
            }
            // Large files: larger chunks but still dedupe-friendly
            1_048_577..=16_777_216 => {
                // 1MB-16MB: 64KB average chunks
                (64 * 1024, 16 * 1024, 256 * 1024)
            }
            // Very large files: maximum deduplication efficiency
            _ => {
                // >16MB: 128KB average chunks
                (128 * 1024, 32 * 1024, 512 * 1024)
            }
        }
    }

    /// Get deterministic CDC parameters for reproducible chunking.
    fn deterministic_cdc_parameters(target_chunk_size: u64) -> CdcParams {
        CdcParams {
            window_size: 32, // Fixed window size for determinism
            average_chunk_size: target_chunk_size,
            normalization: Self::deterministic_normalization_constant(target_chunk_size),
        }
    }

    /// Compute deterministic normalization constant.
    fn deterministic_normalization_constant(avg_chunk_size: u64) -> u64 {
        // Use a well-known constant based on chunk size for determinism
        let bits = (avg_chunk_size as f64).log2() as u32;
        let base_constant = 0x1021; // CRC-16-CCITT polynomial

        // Create deterministic constant that scales with chunk size
        (base_constant as u64) << bits.clamp(8, 16)
    }

    /// Find boundaries using deterministic algorithm for reproducibility.
    fn find_deterministic_boundaries(
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
        let mut rolling_hash = DeterministicRollingHash::new(window_size);
        let mut last_boundary = 0u64;

        // Compute deterministic mask for consistent boundary detection
        let mask = Self::compute_deterministic_mask(avg_chunk_size);

        for (i, &byte) in data.iter().enumerate() {
            let hash = rolling_hash.update(byte);
            let current_pos = i
                .checked_add(1)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(|| {
                    ChunkingProfileError::InvalidChunkParameters(format!(
                        "position overflow in boundary detection at index {i}"
                    ))
                })?;
            let chunk_size_since_last = current_pos - last_boundary;

            let is_boundary = if chunk_size_since_last < min_chunk_size {
                false
            } else if chunk_size_since_last >= max_chunk_size {
                true // Force boundary at max size
            } else {
                // Deterministic boundary detection
                Self::is_deterministic_boundary(hash, mask, chunk_size_since_last, data, i)
            };

            if is_boundary {
                boundaries.push(current_pos);
                last_boundary = current_pos;
            }
        }

        // Add final boundary
        if last_boundary < data_len {
            boundaries.push(data_len);
        }

        Ok(boundaries)
    }

    /// Deterministic boundary detection that considers content structure.
    fn is_deterministic_boundary(
        hash: u64,
        base_mask: u64,
        chunk_size: u64,
        data: &[u8],
        position: usize,
    ) -> bool {
        // Base hash boundary
        let _hash_boundary = (hash & base_mask) == 0;

        // Structural boundaries for build artifacts
        let structural_boundary = if position > 0 && position < data.len() - 1 {
            Self::is_artifact_structural_boundary(data, position)
        } else {
            false
        };

        // Adjust probability based on chunk size (prefer smaller chunks for artifacts)
        let size_factor = if chunk_size > 32 * 1024 {
            2 // More aggressive boundary detection for large chunks
        } else {
            1
        };

        let adjusted_mask = if structural_boundary {
            base_mask << 2 // Much more likely at structural boundaries
        } else {
            base_mask >> size_factor
        };

        (hash & adjusted_mask) == 0
    }

    /// Detect structural boundaries in artifacts (file headers, section boundaries, etc.).
    fn is_artifact_structural_boundary(data: &[u8], position: usize) -> bool {
        if position < 4 || position + 4 >= data.len() {
            return false;
        }

        let context =
            &data[position.saturating_sub(10)..position.saturating_add(10).min(data.len())];

        // Look for common artifact boundaries
        Self::has_elf_section_boundary(context)
            || Self::has_zip_entry_boundary(context)
            || Self::has_tar_header_boundary(context)
            || Self::has_pe_section_boundary(context)
    }

    /// Check for ELF section boundaries.
    fn has_elf_section_boundary(context: &[u8]) -> bool {
        // ELF magic number or section headers
        context.windows(4).any(|w| w == b"\x7fELF")
            || context.windows(8).any(|w| {
                w.starts_with(b".text\0\0\0")
                    || w.starts_with(b".data\0\0\0")
                    || w.starts_with(b".rodata\0")
            })
    }

    /// Check for ZIP entry boundaries.
    fn has_zip_entry_boundary(context: &[u8]) -> bool {
        // ZIP local file header or central directory
        context
            .windows(4)
            .any(|w| w == b"PK\x03\x04" || w == b"PK\x01\x02")
    }

    /// Check for TAR header boundaries.
    fn has_tar_header_boundary(context: &[u8]) -> bool {
        // TAR files have 512-byte headers with specific patterns
        if context.len() >= 8 {
            // Look for null-terminated filename patterns or ustar magic
            context.windows(5).any(|w| w == b"ustar")
                || (context
                    .iter()
                    .take(8)
                    .all(|&b| b.is_ascii_graphic() || b == 0)
                    && context[7] == 0)
        } else {
            false
        }
    }

    /// Check for PE (Windows executable) section boundaries.
    fn has_pe_section_boundary(context: &[u8]) -> bool {
        // PE/COFF magic numbers or section names
        context.windows(2).any(|w| w == b"MZ")
            || context.windows(4).any(|w| w == b"PE\0\0")
            || context
                .windows(8)
                .any(|w| w.starts_with(b".text\0\0\0") || w.starts_with(b".rdata\0\0"))
    }

    /// Compute deterministic mask for boundary detection.
    fn compute_deterministic_mask(avg_chunk_size: u64) -> u64 {
        // Create mask that gives approximately the right average chunk size
        let bits = (avg_chunk_size as f64).log2() as u32;
        let mask_bits = bits.clamp(8, 20);

        // Use checked_shl to prevent overflow/undefined behavior
        assert!(
            mask_bits < 64,
            "mask_bits must be less than 64 to avoid shift overflow"
        );
        match 1u64.checked_shl(mask_bits) {
            Some(shifted) => shifted - 1,
            None => u64::MAX, // Fallback for impossible overflow case
        }
    }

    /// Derive build context from artifact data.
    fn derive_build_context(data: &[u8]) -> ArtifactBuildContext {
        let build_system = Self::detect_build_system(data);
        let environment_hash = Self::compute_environment_hash(data);
        let toolchain_version = Self::detect_toolchain_version(data);

        ArtifactBuildContext {
            build_system,
            build_timestamp: None, // Deterministic builds should not include timestamp
            environment_hash,
            toolchain_version,
        }
    }

    /// Detect build system from artifact signatures.
    fn detect_build_system(data: &[u8]) -> String {
        // Check for various build system signatures
        let data_str = String::from_utf8_lossy(&data[..1000.min(data.len())]);

        if data_str.contains("rustc") || data_str.contains("cargo") {
            "cargo".to_string()
        } else if data_str.contains("go build") || data_str.contains("golang") {
            "go".to_string()
        } else if data_str.contains("gcc") || data_str.contains("clang") {
            "gcc/clang".to_string()
        } else if data_str.contains("javac") || data_str.contains("java") {
            "javac".to_string()
        } else if data_str.contains("node") || data_str.contains("npm") {
            "npm".to_string()
        } else if data.starts_with(b"\x7fELF") {
            "native".to_string()
        } else if data.starts_with(b"MZ") {
            "msvc".to_string()
        } else if data.starts_with(b"PK\x03\x04") {
            "jar".to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// Compute deterministic environment hash from artifact.
    fn compute_environment_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash build-relevant portions of the artifact
        let sample_size = 1024.min(data.len());
        hasher.update(&data[..sample_size]);

        if data.len() > sample_size * 2 {
            // Also hash from the end for better distribution
            hasher.update(&data[data.len() - sample_size..]);
        }

        // Return 32-byte SHA-256 hash
        hasher.finalize().into()
    }

    /// Detect toolchain version from artifact metadata.
    fn detect_toolchain_version(data: &[u8]) -> String {
        let sample_len = MAX_VERSION_SCAN_BYTES.min(data.len());
        let mut data_str = String::from_utf8_lossy(&data[..sample_len]);
        if sample_len < data.len() {
            // Prevent a candidate touching the outer sample boundary from
            // looking complete solely because the input was truncated there.
            data_str.to_mut().push('\u{fffd}');
        }

        for &(marker, prefix, scan_limit, max_lines) in TOOLCHAIN_MARKERS {
            let mut marker_search_start = 0;
            while let Some(marker_start) =
                Self::find_next_toolchain_marker(&data_str, marker, marker_search_start)
            {
                let (search_end, resume_at) = Self::version_search_bounds(
                    &data_str,
                    marker_start,
                    marker.len(),
                    scan_limit,
                    max_lines,
                );
                if let Some(version) = Self::extract_version_number_with_limit(
                    &data_str[marker_start..search_end],
                    scan_limit,
                ) {
                    return format!("{prefix}-{version}");
                }

                marker_search_start = resume_at.max(marker_start + marker.len());
            }
        }

        "unknown".to_string()
    }

    /// Extract the first bounded ASCII version token from a string.
    ///
    /// The accepted grammar is two or more dot-separated digit components,
    /// followed by an optional `-` suffix containing ASCII letters, digits, or
    /// underscores. Alphabetic tool prefixes such as `v` and `go` are not part
    /// of the returned token.
    #[cfg(test)]
    fn extract_version_number(text: &str) -> Option<&str> {
        Self::extract_version_number_with_limit(text, MAX_VERSION_SCAN_BYTES)
    }

    fn extract_version_number_with_limit(text: &str, scan_limit: usize) -> Option<&str> {
        let (start, end) = Self::version_span_with_limit(text, scan_limit)?;
        text.get(start..end)
    }

    fn version_span_with_limit(text: &str, scan_limit: usize) -> Option<(usize, usize)> {
        let bytes = text.as_bytes();
        let scan_end = bytes.len().min(scan_limit);
        let mut cursor = 0;

        while cursor < scan_end {
            if !bytes[cursor].is_ascii_digit() {
                cursor += 1;
                continue;
            }
            if !Self::is_version_start_boundary(bytes, cursor) {
                cursor = Self::skip_version_like(bytes, cursor, scan_end);
                continue;
            }

            let start = cursor;
            cursor = Self::consume_ascii_digits(bytes, cursor, scan_end);
            let mut has_additional_component = false;

            while cursor < scan_end
                && bytes[cursor] == b'.'
                && cursor + 1 < scan_end
                && bytes[cursor + 1].is_ascii_digit()
            {
                cursor += 1;
                cursor = Self::consume_ascii_digits(bytes, cursor, scan_end);
                has_additional_component = true;
            }

            if !has_additional_component {
                cursor = Self::skip_version_like(bytes, cursor, scan_end);
                continue;
            }

            if cursor < scan_end && bytes[cursor] == b'-' {
                let suffix_start = cursor + 1;
                cursor = suffix_start;
                while cursor < scan_end
                    && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
                {
                    cursor += 1;
                }

                if cursor == suffix_start {
                    cursor = Self::skip_version_like(bytes, cursor, scan_end);
                    continue;
                }
            }

            let token_len = cursor - start;
            if token_len > MAX_VERSION_TOKEN_BYTES || !Self::is_version_end_boundary(bytes, cursor)
            {
                cursor = Self::skip_version_like(bytes, cursor, scan_end);
                continue;
            }

            return Some((start, cursor));
        }

        None
    }

    fn find_next_toolchain_marker(text: &str, marker: &str, from: usize) -> Option<usize> {
        text[from..]
            .match_indices(marker)
            .find_map(|(relative_start, _)| {
                let start = from + relative_start;
                Self::is_toolchain_marker_boundary(text, start, marker.len()).then_some(start)
            })
    }

    fn version_search_bounds(
        text: &str,
        marker_start: usize,
        marker_len: usize,
        scan_limit: usize,
        max_lines: Option<usize>,
    ) -> (usize, usize) {
        let bytes = text.as_bytes();
        let inspect_end = marker_start
            .saturating_add(scan_limit)
            .saturating_add(1)
            .min(bytes.len());
        let accepted_version_span =
            Self::version_span_with_limit(&text[marker_start..], scan_limit);
        let mut cursor = marker_start + marker_len;
        let mut newline_count = 0;

        while cursor < inspect_end {
            if bytes[cursor] == b'\n' {
                newline_count += 1;
                if max_lines.is_some_and(|max_lines| newline_count == max_lines) {
                    return (cursor, cursor);
                }
            }

            for &(candidate, _, _, _) in TOOLCHAIN_MARKERS {
                let candidate_end = cursor.saturating_add(candidate.len());
                if candidate_end <= bytes.len()
                    && &bytes[cursor..candidate_end] == candidate.as_bytes()
                    && Self::is_toolchain_marker_boundary(text, cursor, candidate.len())
                    && !Self::marker_is_accepted_version_suffix(
                        bytes,
                        marker_start,
                        cursor,
                        candidate.len(),
                        accepted_version_span,
                    )
                {
                    return (cursor, cursor);
                }
            }

            cursor += 1;
        }

        let scan_boundary = marker_start.saturating_add(scan_limit).min(bytes.len());
        let mut resume_at = scan_boundary;
        while resume_at > marker_start && !text.is_char_boundary(resume_at) {
            resume_at -= 1;
        }

        (text.len(), resume_at)
    }

    fn skip_version_like(bytes: &[u8], mut cursor: usize, scan_end: usize) -> usize {
        while cursor < scan_end && !Self::is_version_separator(bytes[cursor]) {
            cursor += 1;
        }
        cursor
    }

    fn is_toolchain_marker_boundary(text: &str, start: usize, marker_len: usize) -> bool {
        let bytes = text.as_bytes();
        let end = start + marker_len;
        let valid_start = start == 0 || Self::is_marker_separator(bytes[start - 1]);
        let valid_end = end == bytes.len()
            || Self::is_marker_separator(bytes[end])
            || bytes[end].is_ascii_digit();

        valid_start && valid_end
    }

    fn marker_is_accepted_version_suffix(
        bytes: &[u8],
        segment_start: usize,
        marker_start: usize,
        marker_len: usize,
        accepted_version_span: Option<(usize, usize)>,
    ) -> bool {
        let Some((version_start, version_end)) = accepted_version_span else {
            return false;
        };
        let Some(relative_marker_start) = marker_start.checked_sub(segment_start) else {
            return false;
        };

        relative_marker_start > 0
            && bytes[marker_start - 1] == b'-'
            && relative_marker_start > version_start
            && relative_marker_start
                .checked_add(marker_len)
                .is_some_and(|marker_end| marker_end <= version_end)
    }

    fn consume_ascii_digits(bytes: &[u8], mut cursor: usize, scan_end: usize) -> usize {
        while cursor < scan_end && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        cursor
    }

    fn is_version_start_boundary(bytes: &[u8], start: usize) -> bool {
        start == 0
            || Self::is_version_separator(bytes[start - 1])
            || bytes[start - 1].is_ascii_alphabetic()
            || (bytes[start - 1] == b'-' && start >= 2 && bytes[start - 2].is_ascii_alphabetic())
    }

    fn is_version_end_boundary(bytes: &[u8], end: usize) -> bool {
        end == bytes.len() || Self::is_version_separator(bytes[end])
    }

    fn is_version_separator(byte: u8) -> bool {
        byte.is_ascii()
            && !byte.is_ascii_alphanumeric()
            && !matches!(byte, b'_' | b'.' | b'-' | b'+' | b'~')
    }

    fn is_marker_separator(byte: u8) -> bool {
        byte.is_ascii() && !byte.is_ascii_alphanumeric() && byte != b'_'
    }

    /// Compute proof strength for a chunk.
    fn compute_proof_strength(chunk_data: &[u8], chunk_index: u32) -> ProofStrength {
        // Larger chunks and chunks with more structure get higher proof strength
        let size_factor = if chunk_data.len() > 64 * 1024 {
            2
        } else {
            i32::from(chunk_data.len() > 16 * 1024)
        };

        let structure_factor = if Self::has_high_structure(chunk_data) {
            2
        } else {
            0
        };

        let position_factor = i32::from(chunk_index < 5); // Early chunks often more important

        match size_factor + structure_factor + position_factor {
            0..=2 => ProofStrength::Basic,
            3..=4 => ProofStrength::Enhanced,
            _ => ProofStrength::Cryptographic,
        }
    }

    /// Check if chunk has high structural content.
    fn has_high_structure(data: &[u8]) -> bool {
        if data.len() < 1024 {
            return false;
        }
        if data.len() > 64 * 1024 && Self::has_binary_headers(data) {
            return true;
        }

        // Count different types of structural indicators
        let mut structure_score = 0;

        // Binary headers and magic numbers
        if Self::has_binary_headers(data) {
            structure_score += 2;
        }

        // String tables and symbol information
        if Self::has_string_tables(data) {
            structure_score += 1;
        }

        // Code patterns
        if Self::has_code_patterns(data) {
            structure_score += 1;
        }

        // Entropy variation (structured data has variable entropy)
        if Self::has_entropy_variation(data) {
            structure_score += 1;
        }

        structure_score >= 3
    }

    /// Check for binary headers (ELF, PE, Mach-O, etc.).
    fn has_binary_headers(data: &[u8]) -> bool {
        data.starts_with(b"\x7fELF") || // ELF
        data.starts_with(b"MZ") ||      // PE
        data.starts_with(b"\xfe\xed\xfa") || // Mach-O
        data.starts_with(b"PK\x03\x04") // ZIP/JAR
    }

    /// Check for string tables (common in executables).
    fn has_string_tables(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        // Simple heuristic: look for null-terminated strings
        let null_count = data
            .iter()
            .fold(0usize, |count, byte| count + usize::from(*byte == 0));
        let null_ratio = null_count as f64 / data.len() as f64;

        // String tables typically have 5-20% null bytes
        null_ratio > 0.05 && null_ratio < 0.3
    }

    /// Check for code patterns in the data.
    fn has_code_patterns(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(&data[..1000.min(data.len())]) {
            // Look for code-like patterns
            text.contains("main")
                || text.contains("function")
                || text.contains("class")
                || text.contains("import")
                || text.contains("include")
        } else {
            false
        }
    }

    /// Check for entropy variation (structured data characteristic).
    fn has_entropy_variation(data: &[u8]) -> bool {
        if data.len() < 1024 {
            return false;
        }

        // Sample entropy at different positions
        let sample_size = 256;
        let num_samples = 4.min(data.len() / sample_size);
        let mut entropies = Vec::new();

        for i in 0..num_samples {
            let start = i * sample_size;
            let end = (start + sample_size).min(data.len());
            let entropy = Self::calculate_entropy(&data[start..end]);
            entropies.push(entropy);
        }

        if entropies.len() < 2 {
            return false;
        }

        // Check for significant variation in entropy
        let max_entropy = entropies.iter().fold(0.0f64, |a: f64, &b| a.max(b));
        let min_entropy = entropies.iter().fold(8.0f64, |a: f64, &b| a.min(b));

        (max_entropy - min_entropy) > 2.0 // Significant variation
    }

    /// Calculate Shannon entropy of data.
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Validate build context for consistency.
    fn validate_build_context(context: &ArtifactBuildContext) -> Result<(), ChunkingProfileError> {
        if context.build_system.is_empty() {
            return Err(ChunkingProfileError::BuildContextValidationFailed(
                "build system cannot be empty".to_string(),
            ));
        }

        if context.toolchain_version.is_empty() {
            return Err(ChunkingProfileError::BuildContextValidationFailed(
                "toolchain version cannot be empty".to_string(),
            ));
        }

        // Environment hash should not be all zeros
        if context.environment_hash == [0u8; 32] {
            return Err(ChunkingProfileError::BuildContextValidationFailed(
                "environment hash cannot be all zeros".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify reproducible chunking by re-chunking the same data.
    pub fn verify_reproducibility(data: &[u8]) -> Result<bool, ChunkingProfileError> {
        let boundaries1 = Self::compute_boundaries(data)?;
        let boundaries2 = Self::compute_boundaries(data)?;

        // Boundaries should be identical for reproducible chunking
        Ok(boundaries1 == boundaries2)
    }

    /// Get deduplication metrics for artifact chunks.
    pub fn compute_deduplication_metrics(boundaries: &[ChunkBoundary]) -> DeduplicationMetrics {
        let mut total_size = 0u64;
        let mut unique_hashes = std::collections::HashSet::new();
        let mut proof_strength_distribution = std::collections::HashMap::new();

        for boundary in boundaries {
            total_size = total_size.saturating_add(boundary.size_bytes);
            unique_hashes.insert(boundary.content_hash);

            if let Some(ChunkMetadata::Artifact { proof_strength, .. }) = &boundary.metadata {
                *proof_strength_distribution
                    .entry(*proof_strength)
                    .or_insert(0) += 1;
            }
        }

        let unique_ratio = if boundaries.is_empty() {
            0.0
        } else {
            unique_hashes.len() as f64 / boundaries.len() as f64
        };
        let deduplication_potential = 1.0 - unique_ratio;

        DeduplicationMetrics {
            total_chunks: boundaries.len(),
            unique_chunks: unique_hashes.len(),
            total_size,
            deduplication_potential,
            proof_strength_distribution,
        }
    }
}

/// Deterministic rolling hash for reproducible chunking.
struct DeterministicRollingHash {
    window_size: usize,
    hash: u64,
    window: Vec<u8>,
    position: usize,
    filled: usize,
    polynomial: u64,
    powers: Vec<u64>,
}

impl DeterministicRollingHash {
    /// Create new deterministic rolling hash.
    fn new(window_size: usize) -> Self {
        let window_size = window_size.max(1);
        let polynomial: u64 = 0x9e3779b9; // Well-known constant for determinism
        let powers = Self::precompute_powers(polynomial, window_size);
        Self {
            window_size,
            hash: 0,
            window: vec![0; window_size],
            position: 0,
            filled: 0,
            polynomial,
            powers,
        }
    }

    /// Update hash with new byte.
    fn update(&mut self, byte: u8) -> u64 {
        let insert_at = self.position;

        if self.filled == self.window_size {
            let old_byte = self.window[insert_at];
            let old_contribution =
                (old_byte as u64).wrapping_mul(self.powers[self.window_size - 1]);
            self.hash = self.hash.wrapping_sub(old_contribution);
        } else {
            self.filled += 1;
        }

        self.hash = self
            .hash
            .wrapping_mul(self.polynomial)
            .wrapping_add(byte as u64);
        self.window[insert_at] = byte;
        self.position = (self.position + 1) % self.window_size;
        self.hash
    }

    /// Get current hash value.
    #[allow(dead_code)]
    fn current_hash(&self) -> u64 {
        self.hash
    }

    fn precompute_powers(polynomial: u64, window_size: usize) -> Vec<u64> {
        let mut powers = vec![1; window_size];
        for index in 1..window_size {
            powers[index] = (powers[index - 1] as u64).wrapping_mul(polynomial);
        }
        powers
    }
}

/// Deduplication metrics for artifacts.
#[derive(Debug, Clone)]
pub struct DeduplicationMetrics {
    /// Total number of chunks.
    pub total_chunks: usize,
    /// Number of unique chunks.
    pub unique_chunks: usize,
    /// Total size in bytes.
    pub total_size: u64,
    /// Deduplication potential (0.0 to 1.0).
    pub deduplication_potential: f64,
    /// Distribution of proof strength levels.
    pub proof_strength_distribution: std::collections::HashMap<ProofStrength, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_optimize_for_deduplication() {
        // Small artifacts should use fine-grained chunking
        let (target, min, max) = ArtifactProfile::compute_chunk_sizes(32_768);
        assert!(min <= target);
        assert_eq!(target, 4 * 1024);
        assert!(max <= 32 * 1024);

        // Large artifacts should balance dedup and efficiency
        let (target, min, max) = ArtifactProfile::compute_chunk_sizes(50_000_000);
        assert!(min <= target);
        assert_eq!(target, 128 * 1024);
        assert_eq!(max, 512 * 1024);
    }

    #[test]
    fn deterministic_cdc_parameters() {
        let params1 = ArtifactProfile::deterministic_cdc_parameters(16384);
        let params2 = ArtifactProfile::deterministic_cdc_parameters(16384);

        // Should be identical for same input
        assert_eq!(params1.window_size, params2.window_size);
        assert_eq!(params1.average_chunk_size, params2.average_chunk_size);
        assert_eq!(params1.normalization, params2.normalization);

        // Fixed window size for determinism
        assert_eq!(params1.window_size, 32);
    }

    #[test]
    fn deterministic_rolling_hash() {
        let mut hash1 = DeterministicRollingHash::new(16);
        let mut hash2 = DeterministicRollingHash::new(16);

        let data = b"deterministic test data";
        for &byte in data {
            let h1 = hash1.update(byte);
            let h2 = hash2.update(byte);
            assert_eq!(h1, h2);
        }
    }

    #[test]
    fn deterministic_rolling_hash_default_window_does_not_overflow() {
        let data: Vec<u8> = (0..128).map(|value| value as u8).collect();
        let mut hash1 = DeterministicRollingHash::new(32);
        let mut hash2 = DeterministicRollingHash::new(32);

        let mut last_hash = 0;
        for &byte in &data {
            last_hash = hash1.update(byte);
            assert_eq!(last_hash, hash2.update(byte));
        }

        assert_eq!(last_hash, hash1.current_hash());
        assert_ne!(last_hash, 0);
    }

    #[test]
    fn deterministic_rolling_hash_matches_window_recompute_after_wrap() {
        let data: Vec<u8> = (0..96)
            .map(|value| ((value * 37 + 11) % 251) as u8)
            .collect();
        let window_size = 8;
        let polynomial = 0x9e3779b9_u64;
        let mut rolling = DeterministicRollingHash::new(window_size);

        for (index, &byte) in data.iter().enumerate() {
            let actual = rolling.update(byte);
            let end = index + 1;
            let start = end.saturating_sub(window_size);
            let expected = data[start..end].iter().fold(0_u64, |hash, &window_byte| {
                hash.wrapping_mul(polynomial)
                    .wrapping_add(window_byte as u64)
            });
            assert_eq!(actual, expected, "rolling hash drift at byte {index}");
        }
    }

    #[test]
    fn deterministic_boundaries_keep_rolling_hash_state_after_boundary() {
        let data = [1, 2, 3, 1, 71, 5, 6, 7, 8];
        let boundaries =
            ArtifactProfile::find_deterministic_boundaries(&data, 2, 256, 1, 4).unwrap();

        // Resetting the hash at each boundary produces [4, 8, 9] here. A CDC
        // rolling hash must continue across boundaries so position 5 is found.
        assert_eq!(boundaries, vec![4, 5, 9]);
    }

    #[test]
    fn build_system_detection() {
        let rust_data = b"rustc 1.70.0 (90c541806 2023-05-31)";
        assert_eq!(ArtifactProfile::detect_build_system(rust_data), "cargo");

        let elf_data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(ArtifactProfile::detect_build_system(elf_data), "native");

        let java_data = b"PK\x03\x04\x14\x00\x08\x08\x08\x00";
        assert_eq!(ArtifactProfile::detect_build_system(java_data), "jar");
    }

    #[test]
    fn toolchain_version_detection_covers_recognized_markers() {
        let cases: &[(&[u8], &str)] = &[
            (b"rustc 1.70.0 (90c541806 2023-05-31)", "rustc-1.70.0"),
            (
                b"rustc 1.93.0-nightly (abc123 2026-08-01)",
                "rustc-1.93.0-nightly",
            ),
            (b"rustc-1.70.0", "rustc-1.70.0"),
            (b"gcc (Ubuntu) 13.2.1 release", "gcc-13.2.1"),
            (b"gcc-13.2.1", "gcc-13.2.1"),
            (b"clang version 18.1.8 (release)", "clang-18.1.8"),
            (b"clang-18.1.8", "clang-18.1.8"),
            (b"go version go1.22.5 linux/amd64", "go-1.22.5"),
            (b"go1.23.0 linux/amd64", "go-1.23.0"),
            (b"go-1.23.0 linux/amd64", "go-1.23.0"),
            (b"cargo metadata; go1.23.1 linux/amd64", "go-1.23.1"),
            (b"javac 21.0.2", "java-21.0.2"),
            (b"javac-21.0.2", "java-21.0.2"),
            (b"java version \"21.0.2\"", "java-21.0.2"),
            (b"java-21.0.2", "java-21.0.2"),
            (b"rustc 1.2-java", "rustc-1.2-java"),
            (b"rustc 1.2-javac", "rustc-1.2-javac"),
            (b"rustc 1.2-go1", "rustc-1.2-go1"),
            (b"cargo 1.88.0 metadata", "unknown"),
            (b"golang 1.22.5 metadata", "unknown"),
            (b"artifact without a toolchain marker", "unknown"),
        ];

        for &(input, expected) in cases {
            assert_eq!(
                ArtifactProfile::detect_toolchain_version(input),
                expected,
                "input={}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn toolchain_version_detection_is_stable_in_public_artifact_metadata() {
        let input = b"go build metadata; go version go1.22.5 linux/amd64";
        let first = crate::net::atp::chunk::ChunkingProfile::Artifact
            .compute_boundaries(input)
            .unwrap();
        let second = crate::net::atp::chunk::ChunkingProfile::Artifact
            .compute_boundaries(input)
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first
                .iter()
                .map(|boundary| boundary.size_bytes)
                .sum::<u64>(),
            u64::try_from(input.len()).unwrap()
        );

        let Some(ChunkMetadata::Artifact { build_context, .. }) = first
            .first()
            .and_then(|boundary| boundary.metadata.as_ref())
        else {
            panic!("artifact chunk must contain artifact metadata");
        };
        assert_eq!(build_context.toolchain_version, "go-1.22.5");
    }

    #[test]
    fn toolchain_version_detection_respects_sample_and_utf8_boundaries() {
        let mut beyond_sample = vec![b'x'; 2000];
        beyond_sample.extend_from_slice(b" clang version 18.1.8");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&beyond_sample),
            "unknown"
        );

        let mut crossing_sample = vec![b'x'; 1988];
        crossing_sample.extend_from_slice(b" rustc 1.234567890");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&crossing_sample),
            "unknown"
        );

        let mut late_rustc_version = b"rustc ".to_vec();
        late_rustc_version.extend(std::iter::repeat_n(b'x', 123));
        late_rustc_version.extend_from_slice(b" 1.70.0");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&late_rustc_version),
            "rustc-1.70.0"
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(
                b"rustc marker\nfirst line\nsecond line\nthird line\n1.70.0"
            ),
            "rustc-1.70.0"
        );

        let mut late_gcc_version = b"gcc ".to_vec();
        late_gcc_version.extend(std::iter::repeat_n(b'x', NON_RUST_VERSION_SCAN_BYTES));
        late_gcc_version.extend_from_slice(b" 13.2.1");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(&late_gcc_version),
            "unknown"
        );

        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"clang version \xff 18.1.8"),
            "clang-18.1.8"
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"clang version \xff18.1.8"),
            "unknown"
        );

        let decoy_then_real = b"go marker without a version\nno token here\nstill no token\ncargo metadata; go1.23.1 linux/amd64";
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(decoy_then_real),
            "go-1.23.1"
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"rustc metadata; java version 21.0.2"),
            "java-21.0.2"
        );

        let mut repeated_markers = "rustc ".repeat(100);
        repeated_markers.push_str("rustc 1.70.0");
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(repeated_markers.as_bytes()),
            "rustc-1.70.0"
        );

        let separated_gcc_markers = format!("gcc {} gcc 13.2.1", "x".repeat(60));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(separated_gcc_markers.as_bytes()),
            "gcc-13.2.1"
        );

        let straddling_gcc_marker = format!("gcc {}-gcc-13.2.1", "x".repeat(43));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(straddling_gcc_marker.as_bytes()),
            "gcc-13.2.1"
        );

        let straddling_clang_join = format!("clang {}-clang-18.1.8", "x".repeat(37));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(straddling_clang_join.as_bytes()),
            "clang-18.1.8"
        );

        let straddling_clang_prefix = format!("clang {}-clang-v18.1.8", "x".repeat(36));
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(straddling_clang_prefix.as_bytes()),
            "clang-18.1.8"
        );

        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"rustc metadata-java-21.0"),
            "java-21.0"
        );

        let oversized_before_java = format!(
            "rustc {}.0-java 21.0",
            "7".repeat(MAX_VERSION_TOKEN_BYTES - 1)
        );
        assert_eq!(
            ArtifactProfile::detect_toolchain_version(oversized_before_java.as_bytes()),
            "java-21.0"
        );

        assert_eq!(
            ArtifactProfile::detect_toolchain_version(b"rustc foo9bar1.2-java 21.0"),
            "java-21.0"
        );
    }

    #[test]
    fn structural_boundary_detection() {
        let elf_data = b"some data before\x7fELF\x02\x01\x01\x00and after";
        assert!(ArtifactProfile::is_artifact_structural_boundary(
            elf_data, 16
        ));

        let zip_data = b"prefix dataPK\x03\x04local file header";
        assert!(ArtifactProfile::is_artifact_structural_boundary(
            zip_data, 11
        ));

        let normal_data = b"just normal data without structure";
        assert!(!ArtifactProfile::is_artifact_structural_boundary(
            normal_data,
            10
        ));
    }

    #[test]
    fn proof_strength_computation() {
        // Large chunk with structure should get high proof strength
        let structured_data = b"\x7fELF".repeat(20000);
        let strength = ArtifactProfile::compute_proof_strength(&structured_data, 0);
        assert_eq!(strength, ProofStrength::Cryptographic);

        // Small chunk should get basic strength
        let small_data = b"small data";
        let strength = ArtifactProfile::compute_proof_strength(small_data, 10);
        assert_eq!(strength, ProofStrength::Basic);
    }

    #[test]
    fn entropy_calculation() {
        // Uniform data should have high entropy
        let uniform_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = ArtifactProfile::calculate_entropy(&uniform_data);
        assert!(entropy > 7.0);

        // All same byte should have zero entropy
        let uniform_bytes = vec![0u8; 256];
        let entropy = ArtifactProfile::calculate_entropy(&uniform_bytes);
        assert!(entropy < 0.1);
    }

    #[test]
    fn binary_header_detection() {
        assert!(ArtifactProfile::has_binary_headers(b"\x7fELF binary"));
        assert!(ArtifactProfile::has_binary_headers(b"MZ PE executable"));
        assert!(!ArtifactProfile::has_binary_headers(b"plain text file"));
    }

    #[test]
    fn reproducible_chunking() {
        let artifact_data = b"reproducible artifact data for testing".repeat(1000);

        // Should produce identical results
        let result = ArtifactProfile::verify_reproducibility(&artifact_data);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn artifact_chunking_creates_boundaries() {
        let artifact_data = b"\x7fELF\x02\x01\x01\x00".repeat(5000);
        let boundaries = ArtifactProfile::compute_boundaries(&artifact_data).unwrap();

        assert!(!boundaries.is_empty());
        for boundary in &boundaries {
            assert!(matches!(boundary.strategy, ChunkStrategy::ContentDefined));
            assert!(matches!(
                boundary.metadata,
                Some(ChunkMetadata::Artifact { .. })
            ));

            // Check build context
            if let Some(ChunkMetadata::Artifact { build_context, .. }) = &boundary.metadata {
                assert!(!build_context.build_system.is_empty());
                assert!(!build_context.toolchain_version.is_empty());
            }
        }

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, artifact_data.len() as u64);
    }

    #[test]
    fn deduplication_metrics_computation() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 10000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::Artifact {
                    build_context: ArtifactBuildContext {
                        build_system: "cargo".to_string(),
                        build_timestamp: None,
                        environment_hash: [1; 32],
                        toolchain_version: "rustc-1.70.0".to_string(),
                    },
                    proof_strength: ProofStrength::Enhanced,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 10000,
                size_bytes: 10000,
                content_hash: [1; 32], // Same hash = potential duplication
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::Artifact {
                    build_context: ArtifactBuildContext {
                        build_system: "cargo".to_string(),
                        build_timestamp: None,
                        environment_hash: [1; 32],
                        toolchain_version: "rustc-1.70.0".to_string(),
                    },
                    proof_strength: ProofStrength::Basic,
                }),
            },
        ];

        let metrics = ArtifactProfile::compute_deduplication_metrics(&boundaries);
        assert_eq!(metrics.total_chunks, 2);
        assert_eq!(metrics.unique_chunks, 1); // Same hash
        assert_eq!(metrics.total_size, 20000);
        assert!(metrics.deduplication_potential > 0.0);
        assert_eq!(metrics.proof_strength_distribution.len(), 2); // Two different strengths
    }

    #[test]
    fn build_context_validation() {
        let valid_context = ArtifactBuildContext {
            build_system: "cargo".to_string(),
            build_timestamp: None,
            environment_hash: [1; 32],
            toolchain_version: "rustc-1.70.0".to_string(),
        };
        assert!(ArtifactProfile::validate_build_context(&valid_context).is_ok());

        let invalid_context = ArtifactBuildContext {
            build_system: String::new(), // Empty!
            build_timestamp: None,
            environment_hash: [1; 32],
            toolchain_version: "rustc-1.70.0".to_string(),
        };
        assert!(ArtifactProfile::validate_build_context(&invalid_context).is_err());

        let zero_hash_context = ArtifactBuildContext {
            build_system: "cargo".to_string(),
            build_timestamp: None,
            environment_hash: [0; 32], // All zeros!
            toolchain_version: "rustc-1.70.0".to_string(),
        };
        assert!(ArtifactProfile::validate_build_context(&zero_hash_context).is_err());
    }

    #[test]
    fn boundary_validation_enforces_artifact_requirements() {
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 10000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize, // Wrong strategy!
            metadata: Some(ChunkMetadata::Artifact {
                build_context: ArtifactBuildContext {
                    build_system: "cargo".to_string(),
                    build_timestamp: None,
                    environment_hash: [1; 32],
                    toolchain_version: "rustc-1.70.0".to_string(),
                },
                proof_strength: ProofStrength::Basic,
            }),
        };

        let result = ArtifactProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn profile_properties() {
        assert!(ArtifactProfile::supports_incremental_chunking());
        assert_eq!(ArtifactProfile::min_chunking_threshold(), 8 * 1024);
        assert_eq!(ArtifactProfile::max_chunk_size(), 512 * 1024);
    }

    #[test]
    fn toolchain_version_detection_freezes_token_boundaries() {
        let cases = [
            ("rustc 1.70.0 something", Some("1.70.0")),
            ("version 2.1.3-beta info", Some("2.1.3-beta")),
            ("go version go1.22.5", Some("1.22.5")),
            ("release v01.002.3-rc_1!", Some("01.002.3-rc_1")),
            ("build7.4 finished", Some("7.4")),
            ("tool-7.4 finished", Some("7.4")),
            ("nul\0delimited\01.2\0token", Some("1.2")),
            ("no version here", None),
            ("1", None),
            (".1.2", None),
            ("1.2.", None),
            ("1..2", None),
            ("1.2-", None),
            ("-1.2", None),
            ("1.2-3.4", None),
            ("1.2-beta-2", None),
            ("1.2+metadata", None),
            ("1.2+metadata3.4", None),
            ("1.2~vendor", None),
            ("1.2suffix", None),
            ("1.2suffix3.4", None),
            ("1.2-beta.more", None),
            ("١.٢.٣", None),
            ("1.2β", None),
        ];

        for (input, expected) in cases {
            assert_eq!(
                ArtifactProfile::extract_version_number(input),
                expected,
                "input={input:?}"
            );
        }
    }

    #[test]
    fn toolchain_version_detection_skips_invalid_candidates_without_truncation() {
        assert_eq!(
            ArtifactProfile::extract_version_number("bad 1.2. then good 3.4.5"),
            Some("3.4.5")
        );

        let maximum = format!("{}.0", "7".repeat(MAX_VERSION_TOKEN_BYTES - 2));
        assert_eq!(maximum.len(), MAX_VERSION_TOKEN_BYTES);
        assert_eq!(
            ArtifactProfile::extract_version_number(&maximum),
            Some(maximum.as_str())
        );

        let oversized = format!("{}.0", "7".repeat(MAX_VERSION_TOKEN_BYTES - 1));
        assert_eq!(oversized.len(), MAX_VERSION_TOKEN_BYTES + 1);
        assert_eq!(ArtifactProfile::extract_version_number(&oversized), None);

        let mut beyond_scan_window = "x".repeat(MAX_VERSION_SCAN_BYTES);
        beyond_scan_window.push_str(" 1.2.3");
        assert_eq!(
            ArtifactProfile::extract_version_number(&beyond_scan_window),
            None
        );

        let mut crossing_scan_window = "x".repeat(MAX_VERSION_SCAN_BYTES - 4);
        crossing_scan_window.push_str(" 1.23456789");
        assert_eq!(
            ArtifactProfile::extract_version_number(&crossing_scan_window),
            None
        );
    }

    #[test]
    fn toolchain_version_detection_generated_tokens_match_independent_grammar() {
        for major in ["0", "1", "01", "999"] {
            for minor in ["0", "2", "002", "88"] {
                for patch in ["0", "3", "0004"] {
                    for suffix in ["", "-alpha", "-RC1", "-rc_1", "-9"] {
                        let token = format!("{major}.{minor}.{patch}{suffix}");
                        assert!(reference_version_token(&token));

                        let input = format!("toolchain=({token}); done");
                        assert_eq!(
                            ArtifactProfile::extract_version_number(&input),
                            Some(token.as_str()),
                            "input={input:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn toolchain_version_detection_short_exact_candidates_match_independent_grammar() {
        const ALPHABET: &[u8] = b"01.-a_+";

        for length in 1..=6 {
            let mut combinations = 1;
            for _ in 1..length {
                combinations *= ALPHABET.len();
            }

            for leading in [b'0', b'1'] {
                for mut encoded in 0..combinations {
                    let mut bytes = vec![leading; length];
                    for byte in &mut bytes[1..] {
                        *byte = ALPHABET[encoded % ALPHABET.len()];
                        encoded /= ALPHABET.len();
                    }

                    let candidate = String::from_utf8(bytes).unwrap();
                    let expected =
                        reference_version_token(&candidate).then_some(candidate.as_str());
                    assert_eq!(
                        ArtifactProfile::extract_version_number(&candidate),
                        expected,
                        "candidate={candidate:?}"
                    );
                }
            }
        }
    }

    fn reference_version_token(token: &str) -> bool {
        if token.is_empty() || token.len() > MAX_VERSION_TOKEN_BYTES || !token.is_ascii() {
            return false;
        }

        let (components, suffix) = match token.split_once('-') {
            Some((components, suffix)) => (components, Some(suffix)),
            None => (token, None),
        };

        let component_count = components.split('.').count();
        let components_are_numeric = components.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        });

        components_are_numeric
            && component_count >= 2
            && suffix.is_none_or(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
    }
}
