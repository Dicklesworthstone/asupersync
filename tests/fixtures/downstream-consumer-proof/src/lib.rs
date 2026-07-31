use asupersync::{Budget, Outcome, Time};

pub fn public_surface_smoke_value() -> u64 {
    let deadline = Time::from_secs(2);
    let budget = Budget::new()
        .with_deadline(deadline)
        .with_poll_quota(8)
        .with_cost_quota(13)
        .with_priority(200);
    let outcome: Outcome<u64, &str> = Outcome::ok(
        budget
            .deadline
            .expect("downstream proof sets a deadline")
            .as_secs(),
    );

    assert!(outcome.is_ok());
    assert_eq!(budget.deadline, Some(deadline));
    assert_eq!(budget.poll_quota, 8);
    assert_eq!(budget.cost_quota, Some(13));
    assert_eq!(budget.priority, 200);

    outcome.unwrap()
}

#[cfg(test)]
mod tests {
    use asupersync::runtime::{ArtifactCache, ArtifactCacheConfig, CacheStatistics};

    const NOW_NANOS: u64 = 1_000_000_000_000;

    #[test]
    fn artifact_cache_zero_count_rejects_zero_byte_artifact_without_mutation() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 0,
            max_artifact_count: 0,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(!cache.put("zero".to_string(), Vec::new(), NOW_NANOS));

        assert!(cache.is_empty());
        assert_eq!(cache.current_size_bytes(), 0);
        assert_eq!(cache.statistics(), &CacheStatistics::default());
    }

    #[test]
    fn artifact_cache_count_bound_evicts_zero_byte_artifacts() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 0,
            max_artifact_count: 1,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put("older".to_string(), Vec::new(), NOW_NANOS));
        assert!(cache.put("newer".to_string(), Vec::new(), NOW_NANOS + 1));

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains("older"));
        assert!(cache.contains("newer"));
        assert_eq!(cache.current_size_bytes(), 0);
        assert_eq!(cache.statistics().total_evictions, 1);
    }

    #[test]
    fn artifact_cache_replacement_at_count_bound_preserves_peer() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 2,
            max_artifact_count: 2,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put("replace".to_string(), vec![1], NOW_NANOS));
        assert!(cache.put("peer".to_string(), vec![2], NOW_NANOS));
        assert!(cache.put("replace".to_string(), vec![3], NOW_NANOS));

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_size_bytes(), 2);
        assert_eq!(cache.get("replace", NOW_NANOS), Some(&[3][..]));
        assert_eq!(cache.get("peer", NOW_NANOS), Some(&[2][..]));
        assert_eq!(cache.statistics().total_evictions, 0);
    }

    #[test]
    fn artifact_cache_expiry_reclaims_count_before_eviction() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 0,
            max_artifact_count: 1,
            default_ttl_secs: 1,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);
        let expires_at = NOW_NANOS + 1_000_000_000;

        assert!(cache.put("expired".to_string(), Vec::new(), NOW_NANOS));
        assert!(cache.put("fresh".to_string(), Vec::new(), expires_at));

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains("expired"));
        assert!(cache.contains("fresh"));
        assert_eq!(cache.statistics().total_evictions, 0);
    }

    #[test]
    fn artifact_cache_evicts_until_count_and_byte_bounds_both_hold() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 5,
            max_artifact_count: 2,
            eviction_threshold_ratio: 10_000,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put("older".to_string(), vec![1; 2], NOW_NANOS));
        assert!(cache.put("newer".to_string(), vec![2; 2], NOW_NANOS + 1));
        assert!(cache.put("incoming".to_string(), vec![3; 4], NOW_NANOS + 2));

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.current_size_bytes(), 4);
        assert!(!cache.contains("older"));
        assert!(!cache.contains("newer"));
        assert_eq!(cache.get("incoming", NOW_NANOS + 2), Some(&[3; 4][..]));
        assert_eq!(cache.statistics().total_evictions, 2);
    }

    #[test]
    fn artifact_cache_count_only_eviction_skips_byte_threshold_overflow() {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: u64::MAX,
            max_artifact_count: 1,
            eviction_threshold_ratio: u32::MAX,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put("older".to_string(), Vec::new(), NOW_NANOS));
        assert!(cache.put("newer".to_string(), Vec::new(), NOW_NANOS + 1));

        assert_eq!(cache.len(), 1);
        assert!(!cache.contains("older"));
        assert!(cache.contains("newer"));
        assert_eq!(cache.statistics().total_evictions, 1);
    }
}
