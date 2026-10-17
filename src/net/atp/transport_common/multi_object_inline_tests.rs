    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn default_geometry_matches_two_gib_object_cap() {
        let config = MultiObjectSplitConfig::default();
        assert_eq!(
            config.object_byte_limit().unwrap(),
            u64::from(ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT) * ATP_RQ_DEFAULT_MULTI_OBJECT_BLOCK_SIZE
        );
        assert_eq!(config.object_byte_limit().unwrap(), 2 * GIB);
    }

    #[test]
    fn small_entry_stays_single_object() {
        let plan = plan_multi_object_split(10 * MIB, MultiObjectSplitConfig::default()).unwrap();
        assert_eq!(plan.logical_size, 10 * MIB);
        assert_eq!(plan.shard_count(), 1);
        assert!(!plan.is_split());
        assert_eq!(plan.planned_bytes(), 10 * MIB);

        let shard = &plan.shards[0];
        assert_eq!(shard.shard_index, 0);
        assert_eq!(shard.logical_offset, 0);
        assert_eq!(shard.logical_end(), 10 * MIB);
        assert_eq!(shard.source_block_count, 2);
    }

    #[test]
    fn one_byte_over_limit_splits_without_overlapping_ranges() {
        let config = MultiObjectSplitConfig::default();
        let limit = config.object_byte_limit().unwrap();
        let plan = plan_multi_object_split(limit + 1, config).unwrap();

        assert!(plan.is_split());
        assert_eq!(plan.shard_count(), 2);
        assert_eq!(plan.planned_bytes(), limit + 1);
        assert_eq!(plan.shards[0].logical_offset, 0);
        assert_eq!(plan.shards[0].len, limit);
        assert_eq!(plan.shards[0].source_block_count, 256);
        assert_eq!(plan.shards[1].logical_offset, limit);
        assert_eq!(plan.shards[1].len, 1);
        assert_eq!(plan.shards[1].source_block_count, 1);
    }

    #[test]
    fn five_gib_entry_uses_three_bounded_objects() {
        let plan = plan_multi_object_split(5 * GIB, MultiObjectSplitConfig::default()).unwrap();

        assert_eq!(plan.shard_count(), 3);
        assert_eq!(plan.planned_bytes(), 5 * GIB);
        assert_eq!(plan.shards[0].len, 2 * GIB);
        assert_eq!(plan.shards[1].len, 2 * GIB);
        assert_eq!(plan.shards[2].len, GIB);
        for shard in &plan.shards {
            assert!(shard.len <= plan.max_object_bytes);
            assert!(shard.source_block_count <= ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT);
        }
        assert_eq!(plan.shards[0].logical_end(), plan.shards[1].logical_offset);
        assert_eq!(plan.shards[1].logical_end(), plan.shards[2].logical_offset);
        assert_eq!(plan.shards[2].logical_end(), 5 * GIB);
    }

    #[test]
    fn ten_gib_entry_keeps_default_k_bounded() {
        let plan = plan_multi_object_split(10 * GIB, MultiObjectSplitConfig::default()).unwrap();

        assert_eq!(plan.shard_count(), 5);
        assert_eq!(plan.planned_bytes(), 10 * GIB);
        assert!(plan.shards.iter().all(|shard| {
            shard.max_block_size == ATP_RQ_DEFAULT_MULTI_OBJECT_BLOCK_SIZE
                && shard.source_block_count <= ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT
        }));
    }

    #[test]
    fn empty_entry_gets_manifest_placeholder() {
        let plan = plan_multi_object_split(0, MultiObjectSplitConfig::default()).unwrap();

        assert_eq!(plan.shard_count(), 1);
        assert_eq!(plan.planned_bytes(), 0);
        assert!(plan.shards[0].is_empty());
        assert_eq!(plan.shards[0].source_block_count, 0);
    }

    #[test]
    fn invalid_geometry_fails_closed() {
        assert!(matches!(
            plan_multi_object_split(1, MultiObjectSplitConfig::new(0)),
            Err(MultiObjectSplitError::ZeroMaxBlockSize)
        ));
        assert!(matches!(
            plan_multi_object_split(
                1,
                MultiObjectSplitConfig {
                    max_source_blocks_per_object: 257,
                    max_block_size: 1,
                },
            ),
            Err(MultiObjectSplitError::InvalidSourceBlockLimit { .. })
        ));
        assert!(matches!(
            plan_multi_object_split(
                u64::MAX,
                MultiObjectSplitConfig {
                    max_source_blocks_per_object: 1,
                    max_block_size: 1,
                },
            ),
            Err(MultiObjectSplitError::TooManyShards { .. })
        ));
    }
