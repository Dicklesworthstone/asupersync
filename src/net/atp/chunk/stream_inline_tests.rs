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
    fn rolling_manifest_completion_ratio_is_capped() {
        let boundary = ChunkBoundary {
            index: 9,
            byte_offset: 90_000,
            size_bytes: 20_000,
            content_hash: [9; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::Stream {
                sequence: 9,
                early_consumption_safe: true,
            }),
        };

        let update = StreamProfile::create_rolling_manifest_update(&boundary, Some(100_000));

        assert_eq!(update.completion_ratio, 1.0);
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
