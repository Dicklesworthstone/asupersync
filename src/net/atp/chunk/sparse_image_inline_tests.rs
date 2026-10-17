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
        assert_eq!(metadata.unwrap().hole_size, 4000);

        // Chunk that begins before the sparse region should only account for
        // the actual intersection, not the whole chunk.
        let partially_sparse_chunk = vec![0u8; 4000];
        let (is_sparse, metadata) =
            SparseImageProfile::analyze_chunk_sparsity(&partially_sparse_chunk, 0, &sparse_regions);
        assert!(is_sparse);
        assert_eq!(metadata.unwrap().hole_size, 3000);

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
    fn compression_ratio_caps_malformed_sparse_metadata() {
        let boundaries = vec![ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 100_000,
            content_hash: [1; 32],
            strategy: ChunkStrategy::ObjectSpecific,
            metadata: Some(ChunkMetadata::SparseImage {
                is_sparse_hole: true,
                hole_metadata: Some(SparseHoleMetadata {
                    hole_size: 200_000,
                    hole_type: "zero-filled".to_string(),
                    attributes: BTreeMap::new(),
                }),
            }),
        }];

        let ratio = SparseImageProfile::estimate_sparse_compression_ratio(&boundaries);
        assert!(ratio.is_finite());
        assert_eq!(ratio, 1000.0);
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
