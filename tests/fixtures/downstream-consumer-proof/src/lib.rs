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
    use asupersync::runtime::{
        ArtifactCache, ArtifactCacheConfig, CacheStatistics, EvictionPolicy,
    };
    #[cfg(debug_assertions)]
    use asupersync::sync::lock_ordering::{self, LockModule, LockRank};

    const NOW_NANOS: u64 = 1_000_000_000_000;
    #[cfg(debug_assertions)]
    const LOCK_ORDER_HOOK_CHILD: &str = "ASUPERSYNC_LOCK_ORDER_HOOK_CHILD";

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

    fn exact_eviction_victim(policy: EvictionPolicy, first_id: &str, second_id: &str) -> String {
        let config = ArtifactCacheConfig {
            max_cache_size_bytes: 2,
            max_artifact_count: 2,
            eviction_policy: policy,
            ..ArtifactCacheConfig::default()
        };
        let mut cache = ArtifactCache::new(config);

        assert!(cache.put(first_id.to_string(), vec![1], NOW_NANOS));
        assert!(cache.put(second_id.to_string(), vec![2], NOW_NANOS));
        assert_eq!(cache.evict(1), 1);

        match (cache.contains(first_id), cache.contains(second_id)) {
            (false, true) => first_id.to_string(),
            (true, false) => second_id.to_string(),
            state => panic!("exactly one artifact must be evicted, got {state:?}"),
        }
    }

    #[test]
    fn artifact_cache_eviction_ties_have_exact_insertion_independent_victims() {
        // These IDs have equal length. Lexical ordering selects `alpha`, while
        // the stable full-ID hash selects `cider`, proving Random does not fall
        // back to the old length-only ordering.
        let cases = [
            (EvictionPolicy::LruWithTtl, "alpha"),
            (EvictionPolicy::Mru, "alpha"),
            (EvictionPolicy::LargestFirst, "alpha"),
            (EvictionPolicy::Random, "cider"),
        ];

        for (policy, expected_victim) in cases {
            assert_eq!(
                exact_eviction_victim(policy, "alpha", "cider"),
                expected_victim
            );
            assert_eq!(
                exact_eviction_victim(policy, "cider", "alpha"),
                expected_victim
            );
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn lock_order_violation_hook_can_reenter_bookkeeping() {
        if std::env::var_os(LOCK_ORDER_HOOK_CHILD).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("test executable path must be available"),
            )
            .env(LOCK_ORDER_HOOK_CHILD, "1")
            .arg("--exact")
            .arg("tests::lock_order_violation_hook_can_reenter_bookkeeping")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .output()
            .expect("lock-order hook child must start");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "lock-order hook child failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            );
            assert!(
                stdout.contains("1 passed"),
                "exact child test did not execute\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
            return;
        }

        lock_ordering::clear_held_locks();
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {
            // The hook runs synchronously at panic emission. This public helper
            // needs mutable access to both held-lock bookkeeping cells.
            lock_ordering::clear_held_locks();
        }));

        let rank_order = std::panic::catch_unwind(|| {
            lock_ordering::record_acquire("tasks_test", LockRank::Tasks);
            lock_ordering::check_acquire("config_test", LockRank::Config);
        });
        let cross_module = std::panic::catch_unwind(|| {
            lock_ordering::record_acquire_with_module(
                "cancel_token",
                LockRank::Tasks,
                LockModule::Cancel,
            );
            lock_ordering::check_acquire_with_module(
                "obligation_tracker",
                LockRank::Obligations,
                LockModule::Obligation,
            );
        });

        std::panic::set_hook(previous_hook);

        for (case, result) in [("rank-order", rank_order), ("cross-module", cross_module)] {
            let payload = result.expect_err("lock-order violation must still panic");
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&'static str>().copied())
                .expect("lock-order violation must use a text panic payload");
            assert!(
                message.starts_with("[ASUP-E205]"),
                "{case} child caught the wrong panic: {message}"
            );
        }

        assert!(lock_ordering::current_held_ranks().is_empty());
        assert!(lock_ordering::current_held_locks().is_empty());
    }
}
