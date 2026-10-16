    use super::*;

    const TEST_NOW_NANOS: u64 = 1_000_000_000_000;

    #[test]
    fn artifact_memory_pressure_snapshot_default() {
        let snapshot = ArtifactMemoryPressureSnapshot::default();
        assert_eq!(snapshot.resident_bytes, 0);
        assert_eq!(snapshot.artifact_count, 0);
        assert_eq!(snapshot.pressure_bps, 0);
        assert!(!snapshot.is_under_pressure());
        assert_eq!(snapshot.pressure_ratio(), 0.0);
        assert_eq!(snapshot.utilization_ratio(), 0.0);
    }

    #[test]
    fn artifact_memory_pressure_snapshot_calculations() {
        let mut snapshot = ArtifactMemoryPressureSnapshot::default();
        snapshot.pressure_bps = 7500; // 75%
        snapshot.resident_bytes = 512 * 1024 * 1024; // 512MiB
        snapshot.max_resident_bytes = 1024 * 1024 * 1024; // 1GiB
        snapshot.high_pressure = true;

        assert_eq!(snapshot.pressure_ratio(), 0.75);
        assert_eq!(snapshot.utilization_ratio(), 0.5);
        assert!(snapshot.is_under_pressure()); // At threshold
    }

    #[test]
    fn artifact_cache_creation() {
        let config = ArtifactCacheConfig::default();
        let cache = ArtifactCache::new(config);

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size_bytes(), 0);
    }

    #[test]
    fn artifact_cache_put_and_get() {
        let mut cache = ArtifactCache::default_config();
        let test_data = b"test artifact data".to_vec();
        let test_id = "test-artifact-1".to_string();

        // Put artifact
        assert!(cache.put(test_id.clone(), test_data.clone(), TEST_NOW_NANOS));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.current_size_bytes(), test_data.len() as u64);
        assert!(cache.contains(&test_id));

        // Get artifact
        let retrieved = cache.get(&test_id, TEST_NOW_NANOS);
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.expect("cache should contain stored artifact"),
            test_data.as_slice()
        );

        // Verify access count increased
        let stats = cache.statistics();
        assert_eq!(stats.total_hits, 1);
        assert_eq!(stats.total_misses, 0);
        assert_eq!(stats.total_stored, 1);
    }

    #[test]
    fn artifact_cache_remove() {
        let mut cache = ArtifactCache::default_config();
        let test_data = b"test data".to_vec();
        let test_id = "test-id".to_string();

        // Put and then remove
        cache.put(test_id.clone(), test_data, TEST_NOW_NANOS);
        assert!(cache.contains(&test_id));
        assert!(cache.remove(&test_id));
        assert!(!cache.contains(&test_id));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size_bytes(), 0);

        // Removing non-existent artifact should return false
        assert!(!cache.remove("non-existent"));
    }

    #[test]
    fn artifact_cache_eviction() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 100,      // Small cache for testing
            eviction_threshold_ratio: 5000, // 50%
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        // Fill cache beyond capacity
        cache.put("item1".to_string(), vec![0u8; 40], TEST_NOW_NANOS);
        cache.put("item2".to_string(), vec![1u8; 40], TEST_NOW_NANOS);
        cache.put("item3".to_string(), vec![2u8; 40], TEST_NOW_NANOS); // This should trigger eviction

        // Should have evicted some items to stay under capacity
        assert!(cache.current_size_bytes() <= 100);
        assert!(cache.len() <= 2); // At least one item should be evicted
    }

    #[test]
    fn artifact_cache_replacement_at_capacity_preserves_peer() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 100,
            eviction_threshold_ratio: 7500,
            eviction_policy: EvictionPolicy::LargestFirst,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put("replace".to_string(), vec![1; 50], TEST_NOW_NANOS));
        assert!(cache.put("peer".to_string(), vec![2; 50], TEST_NOW_NANOS));
        assert_eq!(cache.current_size_bytes(), 100);
        assert!(cache.put("replace".to_string(), vec![3; 50], TEST_NOW_NANOS));

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_size_bytes(), 100);
        assert_eq!(
            cache.data.get("replace").map(Vec::as_slice),
            Some(&[3; 50][..])
        );
        assert_eq!(
            cache.data.get("peer").map(Vec::as_slice),
            Some(&[2; 50][..])
        );
        assert_eq!(cache.statistics().total_evictions, 0);
    }

    #[test]
    fn artifact_cache_oversized_put_preserves_existing_entries() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 100,
            eviction_policy: EvictionPolicy::LargestFirst,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put("replace".to_string(), vec![1; 40], TEST_NOW_NANOS));
        assert!(cache.put("peer".to_string(), vec![2; 50], TEST_NOW_NANOS));

        assert!(!cache.put("oversized".to_string(), vec![3; 101], TEST_NOW_NANOS));
        assert!(!cache.put("replace".to_string(), vec![4; 101], TEST_NOW_NANOS));

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_size_bytes(), 90);
        assert_eq!(
            cache.data.get("replace").map(Vec::as_slice),
            Some(&[1; 40][..])
        );
        assert_eq!(
            cache.data.get("peer").map(Vec::as_slice),
            Some(&[2; 50][..])
        );
        assert!(!cache.contains("oversized"));
        assert_eq!(cache.statistics().total_evictions, 0);
        assert_eq!(cache.statistics().total_stored, 2);
    }

    #[test]
    fn artifact_cache_clear() {
        let mut cache = ArtifactCache::default_config();

        // Add some artifacts
        cache.put("item1".to_string(), vec![0u8; 10], TEST_NOW_NANOS);
        cache.put("item2".to_string(), vec![1u8; 20], TEST_NOW_NANOS);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_size_bytes(), 30);

        // Clear cache
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.current_size_bytes(), 0);
    }

    #[test]
    fn artifact_cache_miss() {
        let mut cache = ArtifactCache::default_config();

        // Get non-existent artifact
        let result = cache.get("non-existent", TEST_NOW_NANOS);
        assert!(result.is_none());

        let stats = cache.statistics();
        assert_eq!(stats.total_misses, 1);
        assert_eq!(stats.total_hits, 0);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size_bytes(), 0);
        assert!(!cache.contains("test"));
    }

    #[test]
    fn artifact_cache_memory_pressure_snapshot() {
        let cache = ArtifactCache::default_config();
        let snapshot = cache.memory_pressure_snapshot(TEST_NOW_NANOS);

        assert_eq!(snapshot.resident_bytes, 0);
        assert_eq!(snapshot.artifact_count, 0);
        assert_eq!(snapshot.pressure_bps, 0);
        assert_eq!(snapshot.hot_resident_bytes, 0);
        assert_eq!(snapshot.cold_resident_bytes, 0);
    }

    #[test]
    fn artifact_cache_snapshot_classifies_hot_cold_and_spill_in_one_clock_domain() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 200,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);
        let cold_time = TEST_NOW_NANOS - ARTIFACT_HOT_WINDOW_NANOS - 1;

        assert!(cache.put("cold".to_string(), vec![0; 40], cold_time));
        assert!(cache.put("hot".to_string(), vec![1; 60], TEST_NOW_NANOS));

        let snapshot = cache.memory_pressure_snapshot(TEST_NOW_NANOS);
        assert_eq!(snapshot.resident_bytes, 100);
        assert_eq!(snapshot.hot_resident_bytes, 60);
        assert_eq!(snapshot.cold_resident_bytes, 40);
        assert_eq!(snapshot.spill_eligible_bytes, 40);
        assert_eq!(snapshot.pressure_bps, 5_000);
        assert_eq!(snapshot.artifact_count, 2);
    }

    #[test]
    fn artifact_cache_snapshot_boundary_and_access_refresh_are_deterministic() {
        let mut cache = ArtifactCache::default_config();
        let boundary_time = TEST_NOW_NANOS - ARTIFACT_HOT_WINDOW_NANOS;

        assert!(cache.put("boundary".to_string(), vec![0; 10], boundary_time));
        assert!(cache.put("older".to_string(), vec![1; 20], boundary_time - 1));

        let before = cache.memory_pressure_snapshot(TEST_NOW_NANOS);
        assert_eq!(before.hot_resident_bytes, 10);
        assert_eq!(before.cold_resident_bytes, 20);
        assert_eq!(
            cache.memory_pressure_snapshot(TEST_NOW_NANOS),
            before,
            "an unchanged explicit clock must produce an identical snapshot"
        );

        assert_eq!(cache.get("older", TEST_NOW_NANOS), Some(&[1; 20][..]));
        let after = cache.memory_pressure_snapshot(TEST_NOW_NANOS);
        assert_eq!(after.hot_resident_bytes, 30);
        assert_eq!(after.cold_resident_bytes, 0);
        assert_eq!(after.spill_eligible_bytes, 0);

        let mut zero_clock_cache = ArtifactCache::default_config();
        assert!(zero_clock_cache.put("zero".to_string(), vec![2; 7], 0));
        let zero_snapshot = zero_clock_cache.memory_pressure_snapshot(0);
        assert_eq!(zero_snapshot.hot_resident_bytes, 7);
        assert_eq!(zero_snapshot.cold_resident_bytes, 0);
    }

    #[test]
    fn artifact_cache_expiry_uses_the_explicit_clock_domain() {
        let config = ArtifactCacheConfig {
            default_ttl_secs: 1,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);
        let inserted_at = 5;
        let expires_at = inserted_at + 1_000_000_000;

        assert!(cache.put("ttl".to_string(), vec![3; 4], inserted_at));
        assert_eq!(cache.get("ttl", expires_at - 1), Some(&[3; 4][..]));
        assert_eq!(cache.get("ttl", expires_at), None);
        assert!(!cache.contains("ttl"));
    }

    #[test]
    fn eviction_policy_serialization() {
        let policies = [
            EvictionPolicy::LruWithTtl,
            EvictionPolicy::Mru,
            EvictionPolicy::LargestFirst,
            EvictionPolicy::Random,
        ];

        for policy in &policies {
            let serialized =
                serde_json::to_string(policy).expect("eviction policy should serialize to JSON");
            let deserialized: EvictionPolicy = serde_json::from_str(&serialized)
                .expect("serialized policy should deserialize from JSON");
            assert_eq!(*policy, deserialized);
        }
    }

    #[test]
    fn cache_config_default_values() {
        let config = ArtifactCacheConfig::default();
        assert_eq!(config.max_cache_size_bytes, 1024 * 1024 * 1024);
        assert_eq!(config.eviction_threshold_ratio, 7500);
        assert_eq!(config.default_ttl_secs, 3600);
        assert_eq!(config.max_artifact_count, 10_000);
        assert!(config.numa_aware);
        assert_eq!(config.eviction_policy, EvictionPolicy::LruWithTtl);
    }
