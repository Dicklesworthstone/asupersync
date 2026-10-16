    use super::*;

    #[test]
    fn chunk_sizes_scale_with_object_size() {
        // Small file
        let (target, min, max) = BulkFileProfile::compute_chunk_sizes(500_000);
        assert_eq!(target, 64 * 1024);
        assert_eq!(min, 16 * 1024);
        assert_eq!(max, 128 * 1024);

        // Large file
        let (target, min, max) = BulkFileProfile::compute_chunk_sizes(2_000_000_000);
        assert_eq!(target, 16 * 1024 * 1024);
        assert_eq!(min, 4 * 1024 * 1024);
        assert_eq!(max, 16 * 1024 * 1024);
    }

    #[test]
    fn chunk_plan_for_small_file() {
        let plan = BulkFileProfile::chunk_plan(100_000);
        assert_eq!(plan.strategy, ChunkStrategy::FixedSize);
        assert!(plan.target_chunk_size >= plan.min_chunk_size);
        assert!(plan.target_chunk_size <= plan.max_chunk_size);
        assert!(plan.cdc_params.is_none());
    }

    #[test]
    fn chunking_respects_size_constraints() {
        let data = vec![0u8; 1_000_000]; // 1MB of data
        let boundaries = BulkFileProfile::compute_boundaries(&data).unwrap();

        for boundary in &boundaries {
            assert!(boundary.size_bytes >= BulkFileProfile::absolute_min_chunk_size());
            assert!(boundary.size_bytes <= BulkFileProfile::max_chunk_size());
            assert!(matches!(boundary.strategy, ChunkStrategy::FixedSize));
        }

        // Validate total coverage
        let total_size: u64 = boundaries.iter().map(|b| b.size_bytes).sum();
        assert_eq!(total_size, data.len() as u64);
    }

    #[test]
    fn chunks_avoid_tiny_remainders() {
        let chunk_size = 64 * 1024;
        let data_size = chunk_size + 1000; // Just over one chunk + tiny remainder
        let data = vec![0u8; data_size];

        let boundaries = BulkFileProfile::compute_boundaries(&data).unwrap();

        // Should have merged the tiny remainder into the last chunk
        assert!(boundaries.len() <= 2, "Too many chunks for small remainder");

        // All chunks should be reasonably sized
        for boundary in &boundaries {
            assert!(
                boundary.size_bytes >= 1000,
                "Chunk too small: {}",
                boundary.size_bytes
            );
        }
    }

    #[test]
    fn throughput_tier_classification() {
        // Small chunk should be Tail
        let tier = BulkFileProfile::determine_throughput_tier(64 * 1024, 10 * 1024 * 1024);
        assert_eq!(tier, ThroughputTier::Tail);

        // Large chunk should be Bulk
        let tier = BulkFileProfile::determine_throughput_tier(8 * 1024 * 1024, 10 * 1024 * 1024);
        assert_eq!(tier, ThroughputTier::Bulk);

        // Medium chunk should be Standard
        let tier = BulkFileProfile::determine_throughput_tier(1024 * 1024, 10 * 1024 * 1024);
        assert_eq!(tier, ThroughputTier::Standard);
    }

    #[test]
    fn network_adaptation_works() {
        let base_plan = BulkFileProfile::chunk_plan(10 * 1024 * 1024);

        // High latency should increase chunk size
        let high_latency_plan = BulkFileProfile::chunk_plan_for_network(
            10 * 1024 * 1024,
            100, // 100 Mbps
            200, // 200ms latency
        );
        assert!(high_latency_plan.target_chunk_size > base_plan.target_chunk_size);

        // Low bandwidth should increase chunk size
        let low_bandwidth_plan = BulkFileProfile::chunk_plan_for_network(
            10 * 1024 * 1024,
            10, // 10 Mbps
            50, // 50ms latency
        );
        assert!(low_bandwidth_plan.target_chunk_size > base_plan.target_chunk_size);
    }

    #[test]
    fn boundary_validation_catches_errors() {
        // Invalid strategy
        let invalid_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 1024,
            content_hash: [1; 32],
            strategy: ChunkStrategy::ContentDefined, // Wrong strategy!
            metadata: Some(ChunkMetadata::BulkFile {
                throughput_tier: ThroughputTier::Standard,
            }),
        };

        let result = BulkFileProfile::validate_boundaries(&[invalid_boundary]);
        assert!(result.is_err());

        // Chunk too small
        let too_small_boundary = ChunkBoundary {
            index: 0,
            byte_offset: 0,
            size_bytes: 1024, // Too small
            content_hash: [1; 32],
            strategy: ChunkStrategy::FixedSize,
            metadata: Some(ChunkMetadata::BulkFile {
                throughput_tier: ThroughputTier::Standard,
            }),
        };

        let result = BulkFileProfile::validate_boundaries(&[too_small_boundary]);
        assert!(result.is_err());
    }

    #[test]
    fn transfer_time_estimation() {
        let plan = BulkFileProfile::chunk_plan(10 * 1024 * 1024);
        let duration = BulkFileProfile::estimate_transfer_time(
            10 * 1024 * 1024, // 10MB
            &plan,
            100, // 100 Mbps
            50,  // 50ms latency
        );

        // Should be reasonable (less than 10 seconds for 10MB at 100Mbps)
        assert!(duration < std::time::Duration::from_secs(10));
        assert!(duration > std::time::Duration::from_millis(100));
    }

    #[test]
    fn profile_properties() {
        assert!(BulkFileProfile::supports_incremental_chunking());
        assert_eq!(BulkFileProfile::min_chunking_threshold(), 256 * 1024);
        assert_eq!(BulkFileProfile::max_chunk_size(), 16 * 1024 * 1024);
    }

    #[test]
    fn empty_data_handling() {
        let boundaries = BulkFileProfile::compute_boundaries(&[]).unwrap();
        assert!(boundaries.is_empty());
    }

    #[test]
    fn single_chunk_data() {
        let data = vec![0u8; 32 * 1024]; // Small data that fits in one chunk
        let boundaries = BulkFileProfile::compute_boundaries(&data).unwrap();

        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].size_bytes, data.len() as u64);
        assert_eq!(boundaries[0].byte_offset, 0);
        assert_eq!(boundaries[0].index, 0);
    }
