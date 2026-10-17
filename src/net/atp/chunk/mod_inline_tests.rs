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
