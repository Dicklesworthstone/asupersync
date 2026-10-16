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
    fn deduplication_ratio_handles_large_similarity_scores() {
        let boundaries = vec![
            ChunkBoundary {
                index: 0,
                byte_offset: 0,
                size_bytes: 1000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::SyncTree {
                    boundary_hash: 123,
                    similarity_score: u32::MAX,
                }),
            },
            ChunkBoundary {
                index: 1,
                byte_offset: 1000,
                size_bytes: 1000,
                content_hash: [1; 32],
                strategy: ChunkStrategy::ContentDefined,
                metadata: Some(ChunkMetadata::SyncTree {
                    boundary_hash: 456,
                    similarity_score: u32::MAX,
                }),
            },
        ];

        let ratio = SyncTreeProfile::estimate_deduplication_ratio(&boundaries);
        assert!(ratio.is_finite());
        assert_eq!(ratio, 0.5);
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
