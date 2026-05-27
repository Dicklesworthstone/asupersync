//! ATP chunking strategies and profiles for different use cases.
//!
//! This module implements multiple chunking profiles optimized for different transfer scenarios:
//! - **bulk-file**: Large fixed chunks for maximum throughput on large files
//! - **sync-tree**: Content-defined chunking optimized for deduplication across source trees
//! - **media**: Prefix-friendly chunking for streaming and progressive delivery
//! - **sparse-image**: Hole-aware chunking for sparse files and VM images
//! - **artifact**: Reproducible chunking focused on build artifacts and proof strength
//! - **stream**: Rolling manifest chunking for real-time streaming scenarios
//!
//! Each profile balances different trade-offs between throughput, deduplication efficiency,
//! proof strength, and use-case-specific requirements.

use crate::atp::manifest::{ChunkBoundary, ChunkPlan};
pub(crate) use crate::atp::manifest::{ChunkMetadata, SparseHoleMetadata};
use profiles::ChunkingProfile as ChunkingProfileTrait;

pub mod artifact;
pub mod bulk_file;
pub mod dedupe;
pub mod media;
pub mod profiles;
pub mod sparse_image;
pub mod stream;
pub mod sync_tree;

/// Chunking profile identifier for deterministic chunk layout selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChunkingProfile {
    /// Large fixed chunks for maximum throughput on bulk transfers.
    BulkFile,
    /// Content-defined chunking optimized for dedupe across source trees.
    SyncTree,
    /// Prefix-friendly chunking for streaming media and progressive delivery.
    Media,
    /// Hole-aware chunking for sparse files and virtual machine images.
    SparseImage,
    /// Reproducible chunking focused on build artifacts and proof strength.
    Artifact,
    /// Rolling manifest chunking for real-time streaming scenarios.
    Stream,
}

impl ChunkingProfile {
    /// All chunking profiles in canonical order.
    pub const ALL: [Self; 6] = [
        Self::BulkFile,
        Self::SyncTree,
        Self::Media,
        Self::SparseImage,
        Self::Artifact,
        Self::Stream,
    ];

    /// Get human-readable name for this profile.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BulkFile => "bulk-file",
            Self::SyncTree => "sync-tree",
            Self::Media => "media",
            Self::SparseImage => "sparse-image",
            Self::Artifact => "artifact",
            Self::Stream => "stream",
        }
    }

    /// Get recommended chunk plan for this profile with the given object size.
    #[must_use]
    pub fn recommended_chunk_plan(self, object_size_bytes: u64) -> ChunkPlan {
        match self {
            Self::BulkFile => bulk_file::BulkFileProfile::chunk_plan(object_size_bytes),
            Self::SyncTree => sync_tree::SyncTreeProfile::chunk_plan(object_size_bytes),
            Self::Media => media::MediaProfile::chunk_plan(object_size_bytes),
            Self::SparseImage => sparse_image::SparseImageProfile::chunk_plan(object_size_bytes),
            Self::Artifact => artifact::ArtifactProfile::chunk_plan(object_size_bytes),
            Self::Stream => stream::StreamProfile::chunk_plan(object_size_bytes),
        }
    }

    /// Compute chunk boundaries using this profile.
    #[must_use = "this returns computed boundaries; consume or inspect the result"]
    pub fn compute_boundaries(
        self,
        data: &[u8],
    ) -> Result<Vec<ChunkBoundary>, ChunkingProfileError> {
        use profiles::ChunkingProfile as ChunkingProfileTrait;

        match self {
            Self::BulkFile => bulk_file::BulkFileProfile::compute_boundaries(data),
            Self::SyncTree => sync_tree::SyncTreeProfile::compute_boundaries(data),
            Self::Media => media::MediaProfile::compute_boundaries(data),
            Self::SparseImage => sparse_image::SparseImageProfile::compute_boundaries(data),
            Self::Artifact => artifact::ArtifactProfile::compute_boundaries(data),
            Self::Stream => stream::StreamProfile::compute_boundaries(data),
        }
    }

    /// Check if chunk can be deduplicated using CDC engine.
    #[must_use]
    pub const fn supports_deduplication(self) -> bool {
        matches!(self, Self::SyncTree | Self::Artifact | Self::Stream)
    }

    /// Check if profile supports incremental/streaming chunking.
    #[must_use]
    pub const fn supports_incremental_chunking(self) -> bool {
        matches!(
            self,
            Self::SyncTree | Self::Media | Self::Artifact | Self::Stream
        )
    }

    /// Whether this profile supports streaming/progressive consumption.
    #[must_use]
    pub const fn supports_streaming(self) -> bool {
        matches!(self, Self::Media | Self::Stream)
    }

    /// Whether this profile prioritizes deduplication efficiency.
    #[must_use]
    pub const fn optimizes_for_deduplication(self) -> bool {
        matches!(self, Self::SyncTree | Self::Artifact)
    }

    /// Whether this profile handles sparse data efficiently.
    #[must_use]
    pub const fn supports_sparse_data(self) -> bool {
        matches!(self, Self::SparseImage)
    }

    /// Whether this profile provides reproducible chunking for proof strength.
    #[must_use]
    pub const fn provides_reproducible_chunking(self) -> bool {
        matches!(self, Self::BulkFile | Self::Artifact)
    }
}

impl std::fmt::Display for ChunkingProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for ChunkingProfile {
    type Err = ChunkingProfileError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bulk-file" => Ok(Self::BulkFile),
            "sync-tree" => Ok(Self::SyncTree),
            "media" => Ok(Self::Media),
            "sparse-image" => Ok(Self::SparseImage),
            "artifact" => Ok(Self::Artifact),
            "stream" => Ok(Self::Stream),
            _ => Err(ChunkingProfileError::InvalidProfile(s.to_string())),
        }
    }
}

/// Errors in chunking operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkingProfileError {
    /// Invalid profile name.
    InvalidProfile(String),
    /// Unsupported operation for this profile.
    UnsupportedOperation(ChunkingProfile, String),
    /// Invalid chunk parameters.
    InvalidChunkParameters(String),
    /// Sparse hole detection failed.
    SparseHoleDetectionFailed(String),
    /// Build context validation failed.
    BuildContextValidationFailed(String),
    /// Stream sequencing error.
    StreamSequencingError(String),
}

impl std::fmt::Display for ChunkingProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProfile(name) => write!(f, "invalid chunking profile: {name}"),
            Self::UnsupportedOperation(profile, op) => {
                write!(f, "unsupported operation '{op}' for profile {profile}")
            }
            Self::InvalidChunkParameters(msg) => write!(f, "invalid chunk parameters: {msg}"),
            Self::SparseHoleDetectionFailed(msg) => {
                write!(f, "sparse hole detection failed: {msg}")
            }
            Self::BuildContextValidationFailed(msg) => {
                write!(f, "build context validation failed: {msg}")
            }
            Self::StreamSequencingError(msg) => {
                write!(f, "stream sequencing error: {msg}")
            }
        }
    }
}

impl std::error::Error for ChunkingProfileError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::{ChunkStrategy, ProofStrength, ThroughputTier};

    #[test]
    fn chunking_profile_all_variants_listed() {
        assert_eq!(ChunkingProfile::ALL.len(), 6);
        for profile in ChunkingProfile::ALL {
            // Each profile should have a valid name
            assert!(!profile.name().is_empty());
        }
    }

    #[test]
    fn chunking_profile_string_conversion() {
        for profile in ChunkingProfile::ALL {
            let name = profile.name();
            let parsed: ChunkingProfile = name.parse().unwrap();
            assert_eq!(parsed, profile);
        }

        // Invalid profile should fail
        let result: Result<ChunkingProfile, _> = "invalid-profile".parse();
        assert!(result.is_err());
    }

    #[test]
    fn chunking_profile_properties() {
        // Streaming profiles
        assert!(ChunkingProfile::Media.supports_streaming());
        assert!(ChunkingProfile::Stream.supports_streaming());
        assert!(!ChunkingProfile::BulkFile.supports_streaming());

        // Deduplication optimization
        assert!(ChunkingProfile::SyncTree.optimizes_for_deduplication());
        assert!(ChunkingProfile::Artifact.optimizes_for_deduplication());
        assert!(!ChunkingProfile::BulkFile.optimizes_for_deduplication());

        // Sparse data support
        assert!(ChunkingProfile::SparseImage.supports_sparse_data());
        assert!(!ChunkingProfile::BulkFile.supports_sparse_data());

        // Reproducible chunking
        assert!(ChunkingProfile::Artifact.provides_reproducible_chunking());
        assert!(ChunkingProfile::BulkFile.provides_reproducible_chunking());
        assert!(!ChunkingProfile::Media.provides_reproducible_chunking());
    }

    #[test]
    fn chunk_boundary_ordering() {
        let chunk1 = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 1024,
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::BulkFile {
                throughput_tier: ThroughputTier::Standard,
            }),
        };

        let chunk2 = ChunkBoundary {
            index: 1,
            byte_offset: 1024,
            size_bytes: 1024,
            content_hash: [2; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::BulkFile {
                throughput_tier: ThroughputTier::Standard,
            }),
        };

        assert!(chunk1 < chunk2);

        let mut chunks = vec![chunk2.clone(), chunk1.clone()];
        chunks.sort();
        assert_eq!(chunks[0], chunk1);
        assert_eq!(chunks[1], chunk2);
    }

    #[test]
    fn throughput_tier_ordering() {
        assert!(ThroughputTier::Tail < ThroughputTier::Standard);
        assert!(ThroughputTier::Standard < ThroughputTier::Bulk);
    }

    #[test]
    fn proof_strength_ordering() {
        assert!(ProofStrength::Basic < ProofStrength::Enhanced);
        assert!(ProofStrength::Enhanced < ProofStrength::Cryptographic);
    }
}
